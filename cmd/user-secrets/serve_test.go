package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
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
