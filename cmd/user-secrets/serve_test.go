package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"github.com/nebari-dev/nebari-user-secrets/internal/audit"
	"github.com/nebari-dev/nebari-user-secrets/internal/config"
	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
	"github.com/nebari-dev/nebari-user-secrets/internal/guard"
	"github.com/nebari-dev/nebari-user-secrets/internal/registry"
)

func discard() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

func writePair(t *testing.T, dir, cn string, mod time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certPath, keyPath = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{certPath, keyPath} {
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	return certPath, keyPath
}

func subjectCN(t *testing.T, r *certReloader) string {
	t.Helper()
	c, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func TestCertReloader(t *testing.T) {
	base := time.Now().Add(-time.Minute)
	tests := []struct {
		name   string
		mutate func(t *testing.T, dir string)
		wantCN string
	}{
		{name: "unchanged files keep the cert", mutate: func(*testing.T, string) {}, wantCN: "one"},
		{name: "changed files are reloaded", mutate: func(t *testing.T, dir string) {
			writePair(t, dir, "two", base.Add(time.Minute))
		}, wantCN: "two"},
		{name: "broken replacement keeps the last good cert", mutate: func(t *testing.T, dir string) {
			for _, f := range []string{"tls.crt", "tls.key"} {
				p := filepath.Join(dir, f)
				if err := os.WriteFile(p, []byte("garbage"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(p, base.Add(time.Minute), base.Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
			}
		}, wantCN: "one"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cert, key := writePair(t, dir, "one", base)
			r, err := newCertReloader(cert, key, discard())
			if err != nil {
				t.Fatal(err)
			}
			if subjectCN(t, r) != "one" {
				t.Fatal("initial cert wrong")
			}
			tc.mutate(t, dir)
			if got := subjectCN(t, r); got != tc.wantCN {
				t.Fatalf("CN = %q, want %q", got, tc.wantCN)
			}
		})
	}
	t.Run("initial load failure is an error", func(t *testing.T) {
		if _, err := newCertReloader("/nope.crt", "/nope.key", discard()); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestKEKGate(t *testing.T) {
	g := &kekGate{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)

	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"kek_unavailable"`) ||
		rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("before ready: %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}

	g.set(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	rec = httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("after ready: %d", rec.Code)
	}
}

func TestRetryBootstrap(t *testing.T) {
	tests := []struct {
		name       string
		failures   int
		wantSleeps []time.Duration
	}{
		{name: "succeeds after two failures", failures: 2,
			wantSleeps: []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}},
		{name: "backoff caps at 30s", failures: 8, wantSleeps: []time.Duration{
			time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second,
			30 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			var sleeps []time.Duration
			var ready atomic.Bool
			boot := func(context.Context) error {
				calls++
				if calls <= tc.failures {
					return crypto.ErrKEKUnavailable
				}
				return nil
			}
			sleep := func(_ context.Context, d time.Duration) bool { sleeps = append(sleeps, d); return true }
			retryBootstrap(context.Background(), boot, sleep, func() { ready.Store(true) }, discard())
			if !ready.Load() || calls != tc.failures+1 {
				t.Fatalf("ready=%v calls=%d", ready.Load(), calls)
			}
			if len(sleeps) != len(tc.wantSleeps) {
				t.Fatalf("sleeps = %v, want %v", sleeps, tc.wantSleeps)
			}
			for i := range sleeps {
				if sleeps[i] != tc.wantSleeps[i] {
					t.Fatalf("sleeps = %v, want %v", sleeps, tc.wantSleeps)
				}
			}
		})
	}
	t.Run("stops when context ends", func(t *testing.T) {
		var ready atomic.Bool
		retryBootstrap(context.Background(),
			func(context.Context) error { return errors.New("x") },
			func(context.Context, time.Duration) bool { return false },
			func() { ready.Store(true) }, discard())
		if ready.Load() {
			t.Fatal("onReady called")
		}
	})
}

func TestHealthHandler(t *testing.T) {
	tests := []struct {
		name string
		path string
		kek  bool
		want int
	}{
		{"healthz ok before kek", "/healthz", false, 200},
		{"readyz not ready", "/readyz", false, 503},
		{"readyz ready", "/readyz", true, 200},
		{"unknown path", "/other", true, 404},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var kek atomic.Bool
			kek.Store(tc.kek)
			rec := httptest.NewRecorder()
			healthHandler(&kek).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != tc.want {
				t.Fatalf("code = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestNewHTTPServerBounds(t *testing.T) {
	s := newHTTPServer(":0", http.NotFoundHandler())
	if s.ReadHeaderTimeout <= 0 || s.ReadTimeout <= 0 || s.WriteTimeout <= 0 || s.IdleTimeout <= 0 {
		t.Fatalf("timeouts not all set: %+v", s)
	}
	if s.MaxHeaderBytes != 16<<10 {
		t.Fatalf("MaxHeaderBytes = %d, want 16384", s.MaxHeaderBytes)
	}
}

// TestTLSServerProtocols: a client that tries HTTP/2 gets it from the
// management server but only HTTP/1.1 from the resolve server.
func TestTLSServerProtocols(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, "user-secrets", time.Now())
	certs, err := newCertReloader(certPath, keyPath, discard())
	if err != nil {
		t.Fatal(err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mgmt := func() *http.Server { return newTLSServer(managementAddr, ok, certs.GetCertificate) }
	resolve := func() *http.Server { return newResolveServer(resolveAddr, ok, certs.GetCertificate) }
	tests := []struct {
		name      string
		build     func() *http.Server
		wantProto string
	}{
		{name: "management keeps HTTP/2", build: mgmt, wantProto: "HTTP/2.0"},
		{name: "resolve is HTTP/1.1 only", build: resolve, wantProto: "HTTP/1.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			srv := tt.build()
			go func() { _ = srv.ServeTLS(ln, "", "") }()
			defer func() { _ = srv.Close() }()
			client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
				ForceAttemptHTTP2: true,
				// Test-only self-signed certificate without SANs.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // test server
			}}
			resp, err := client.Get("https://" + ln.Addr().String() + "/")
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.Proto != tt.wantProto {
				t.Fatalf("proto %s, want %s", resp.Proto, tt.wantProto)
			}
		})
	}
}

func TestNewGuard(t *testing.T) {
	reg, err := registry.Load(strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name         string
		mode         string
		namespace    string
		wantErr      bool
		wantState    guard.GuardState
		wantStarters int
	}{
		{name: "enforced builds watcher and store", mode: config.GuardEnforced, namespace: "us-system",
			wantState:    guard.GuardState{State: guard.StateUnknown, Mode: guard.ModeEnforced, Reason: "not evaluated yet"},
			wantStarters: 2},
		{name: "unverified is overridden with nothing to start", mode: config.GuardUnverified, namespace: "us-system",
			wantState: guard.GuardState{State: guard.StateOverridden, Mode: guard.ModeOverridden,
				Reason: "guard.mode is unverified"}},
		{name: "enforced rejects a bad namespace", mode: config.GuardEnforced, namespace: "Not_A_Label", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{Namespace: tt.namespace, Guard: config.Guard{Mode: tt.mode}}
			g, starters, err := newGuard(cfg, fake.NewClientset(), reg, audit.NewSlogAuditSink(discard()))
			if tt.wantErr {
				if err == nil {
					t.Fatal("want an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := g.State(); got != tt.wantState {
				t.Errorf("State() = %+v, want %+v", got, tt.wantState)
			}
			if len(starters) != tt.wantStarters {
				t.Errorf("%d starters, want %d", len(starters), tt.wantStarters)
			}
		})
	}
}

func TestNewClientsets(t *testing.T) {
	tests := []struct {
		name string
		k    config.Kubernetes
	}{
		{name: "chart defaults", k: config.Kubernetes{QPS: 50, Burst: 100}},
		{name: "fractional qps", k: config.Kubernetes{QPS: 7.5, Burst: 8}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := &rest.Config{Host: "https://kube.example"}
			cs, guardCS, err := newClientsets(rc, tt.k)
			if err != nil {
				t.Fatal(err)
			}
			if rc.QPS != 0 || rc.Burst != 0 || rc.RateLimiter != nil {
				t.Errorf("rc modified: qps %v burst %d limiter %v", rc.QPS, rc.Burst, rc.RateLimiter)
			}
			// One limiter for every API group the store, master key and pod
			// verifier use, at the configured rate.
			core := cs.CoreV1().RESTClient().GetRateLimiter()
			if got := core.QPS(); got != tt.k.QPS {
				t.Errorf("service qps %v, want %v", got, tt.k.QPS)
			}
			if authn := cs.AuthenticationV1().RESTClient().GetRateLimiter(); authn != core {
				t.Error("authentication/v1 does not share the core/v1 limiter")
			}
			// The guard's client has client-go's defaults and shares nothing.
			gcore := guardCS.CoreV1().RESTClient().GetRateLimiter()
			if gcore == core {
				t.Error("guard shares the service limiter")
			}
			if got := gcore.QPS(); got != rest.DefaultQPS {
				t.Errorf("guard qps %v, want %v", got, rest.DefaultQPS)
			}
		})
	}
}

// countingEvaluator counts Evaluate calls and signals each one.
type countingEvaluator struct {
	calls atomic.Int32
	done  chan struct{}
}

func (c *countingEvaluator) Evaluate(context.Context) guard.GuardState {
	c.calls.Add(1)
	c.done <- struct{}{}
	return guard.GuardState{State: guard.StateOverridden, Mode: guard.ModeOverridden}
}

func TestRunOverridden(t *testing.T) {
	tests := []struct {
		name  string
		ticks int
	}{
		{name: "checks and warns at start", ticks: 0},
		{name: "checks and warns on every tick", ticks: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs syncBuffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			ev := &countingEvaluator{done: make(chan struct{})}
			tick := make(chan time.Time)
			ctx, cancel := context.WithCancel(context.Background())
			finished := make(chan struct{})
			go func() {
				runOverridden(ctx, ev, tick, logger)
				close(finished)
			}()
			<-ev.done
			for range tt.ticks {
				tick <- time.Now()
				<-ev.done
			}
			cancel()
			<-finished
			want := tt.ticks + 1
			if got := int(ev.calls.Load()); got != want {
				t.Errorf("%d evaluations, want %d", got, want)
			}
			if got := strings.Count(logs.String(), `"level":"WARN","msg":"guard overridden`); got != want {
				t.Errorf("%d warnings, want %d; logs:\n%s", got, want, logs.String())
			}
		})
	}
}

// syncBuffer is a bytes.Buffer safe for the logger goroutine and the test.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
