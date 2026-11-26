package initfiles

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

const testToken = "tok-SENTINEL-do-not-leak"

// fakeClock advances only when Sleep is called, so backoff runs instantly.
type fakeClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	return nil
}

// scriptClient returns one scripted result per call; the last result repeats.
type scriptClient struct {
	results []result
	calls   int
	tokens  []string
}

type result struct {
	secrets []model.ResolvedSecret
	err     error
}

func (c *scriptClient) Resolve(_ context.Context, token string) ([]model.ResolvedSecret, error) {
	c.tokens = append(c.tokens, token)
	r := c.results[min(c.calls, len(c.results)-1)]
	c.calls++
	return r.secrets, r.err
}

var errRefused = errors.New("dial tcp 10.0.0.1:8443: connect: connection refused")

func TestFetch(t *testing.T) {
	two := []model.ResolvedSecret{
		{Env: "NEBARI_SECRET_A", Value: []byte("a\x00b")},
		{Env: "NEBARI_SECRET_B", Value: []byte("value-SENTINEL")},
	}
	tests := []struct {
		name       string
		results    []result
		noToken    bool
		token      string   // token file content; default testToken
		existing   []string // secret files present before the fetch
		wantStatus string   // exact, or prefix when wantPrefix
		wantPrefix bool
		wantOK     bool
		wantCalls  int
		wantSleeps []time.Duration
		wantFiles  []string
	}{
		{
			name:       "200 writes files and ok count",
			results:    []result{{secrets: two}},
			wantStatus: "ok 2", wantOK: true, wantCalls: 1,
			wantFiles: []string{"NEBARI_SECRET_A", "NEBARI_SECRET_B"},
		},
		{
			name:       "200 with no secrets",
			results:    []result{{secrets: []model.ResolvedSecret{}}},
			wantStatus: "ok 0", wantOK: true, wantCalls: 1,
		},
		{
			name: "503 then 200 retried with backoff",
			results: []result{
				{err: &APIError{Status: 503, Code: "kubernetes_unavailable"}},
				{err: &APIError{Status: 503, Code: "kek_unavailable"}},
				{secrets: two},
			},
			wantStatus: "ok 2", wantOK: true, wantCalls: 3,
			wantSleeps: []time.Duration{500 * time.Millisecond, time.Second},
			wantFiles:  []string{"NEBARI_SECRET_A", "NEBARI_SECRET_B"},
		},
		{
			name:       "connection refused until budget",
			results:    []result{{err: errRefused}},
			wantStatus: "error unreachable ", wantPrefix: true, wantCalls: 9,
			wantSleeps: []time.Duration{
				500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second,
				5 * time.Second, 5 * time.Second, 5 * time.Second, 5 * time.Second,
			},
		},
		{
			name:       "503 until budget keeps the server code",
			results:    []result{{err: &APIError{Status: 503, Code: "guard_not_verified"}}},
			wantStatus: "error guard_not_verified http 503 after 9 attempts", wantCalls: 9,
			wantSleeps: []time.Duration{
				500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second,
				5 * time.Second, 5 * time.Second, 5 * time.Second, 5 * time.Second,
			},
		},
		{
			name:       "403 pod_predates_guard is final",
			results:    []result{{err: &APIError{Status: 403, Code: "pod_predates_guard"}}},
			wantStatus: "error pod_predates_guard http 403", wantCalls: 1,
		},
		{
			name:       "401 not_pod_bound is final",
			results:    []result{{err: &APIError{Status: 401, Code: "not_pod_bound"}}},
			wantStatus: "error not_pod_bound http 401", wantCalls: 1,
		},
		{
			name:       "500 decrypt_failed is final",
			results:    []result{{err: &APIError{Status: 500, Code: "decrypt_failed"}}},
			wantStatus: "error decrypt_failed http 500", wantCalls: 1,
		},
		{
			name:       "404 is final",
			results:    []result{{err: &APIError{Status: 404, Code: "not_found"}}},
			wantStatus: "error not_found http 404", wantCalls: 1,
		},
		{
			name:       "malformed response is final",
			results:    []result{{err: errBadResponse}},
			wantStatus: "error bad_response ", wantPrefix: true, wantCalls: 1,
		},
		{
			name:       "missing token is final",
			results:    []result{{secrets: two}},
			noToken:    true,
			wantStatus: "error token_missing ", wantPrefix: true, wantCalls: 0,
		},
		{
			name: "200 with one invalid name delivers nothing",
			results: []result{{secrets: []model.ResolvedSecret{
				{Env: "NEBARI_SECRET_A", Value: []byte("a")}, {Env: "BAD", Value: []byte("x")},
			}}},
			existing:   []string{"NEBARI_SECRET_OLD"},
			wantStatus: "error invalid_response secret 1: invalid delivered name", wantCalls: 1,
		},
		{
			name:       "200 with bad base64 delivers nothing",
			results:    []result{{err: fmt.Errorf("%w: secret 0 value is not base64", errInvalidResponse)}},
			existing:   []string{"NEBARI_SECRET_OLD"},
			wantStatus: "error invalid_response ", wantPrefix: true, wantCalls: 1,
		},
		{
			name:       "earlier success then final failure clears files",
			results:    []result{{err: &APIError{Status: 403, Code: "pod_predates_guard"}}},
			existing:   []string{"NEBARI_SECRET_A", "NEBARI_SECRET_OLD"},
			wantStatus: "error pod_predates_guard http 403", wantCalls: 1,
		},
		{
			name:       "earlier success then budget exhausted clears files",
			results:    []result{{err: errRefused}},
			existing:   []string{"NEBARI_SECRET_A"},
			wantStatus: "error unreachable ", wantPrefix: true, wantCalls: 9,
			wantSleeps: []time.Duration{
				500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second,
				5 * time.Second, 5 * time.Second, 5 * time.Second, 5 * time.Second,
			},
		},
		{
			name:       "earlier success then new set replaces it",
			results:    []result{{secrets: two}},
			existing:   []string{"NEBARI_SECRET_OLD"},
			wantStatus: "ok 2", wantOK: true, wantCalls: 1,
			wantFiles: []string{"NEBARI_SECRET_A", "NEBARI_SECRET_B"},
		},
		{
			name:       "token with a control byte is final",
			results:    []result{{secrets: two}},
			token:      "abc\ndef-SENTINEL",
			wantStatus: "error token_invalid ", wantPrefix: true, wantCalls: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tokenPath := filepath.Join(t.TempDir(), "token")
			for _, name := range tt.existing {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("old-SENTINEL"), 0o440); err != nil {
					t.Fatal(err)
				}
			}
			token := tt.token
			if token == "" {
				token = testToken + "\n"
			}
			if !tt.noToken {
				if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			c := &scriptClient{results: tt.results}
			clk := &fakeClock{now: time.Unix(1000, 0)}
			status, ok := fetch(context.Background(), c, tokenPath, NewFileWriter(dir), 30*time.Second, clk, defaultRetry)

			if tt.wantPrefix {
				if !strings.HasPrefix(status, tt.wantStatus) {
					t.Fatalf("status = %q, want prefix %q", status, tt.wantStatus)
				}
			} else if status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", status, tt.wantStatus)
			}
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if c.calls != tt.wantCalls {
				t.Fatalf("calls = %d, want %d", c.calls, tt.wantCalls)
			}
			if fmt.Sprint(clk.sleeps) != fmt.Sprint(tt.wantSleeps) {
				t.Fatalf("sleeps = %v, want %v", clk.sleeps, tt.wantSleeps)
			}
			for _, tok := range c.tokens {
				if tok != testToken {
					t.Fatalf("token sent = %q, want trimmed token", tok)
				}
			}
			if strings.Contains(status, "SENTINEL") {
				t.Fatalf("status leaks a token or value: %q", status)
			}
			gotStatus, err := os.ReadFile(filepath.Join(dir, ".status"))
			if err != nil {
				t.Fatal(err)
			}
			if string(gotStatus) != status {
				t.Fatalf(".status = %q, returned %q", gotStatus, status)
			}
			assertSecretFiles(t, dir, tt.wantFiles)
		})
	}
}

func assertSecretFiles(t *testing.T, dir string, want []string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), namePrefix) {
			got = append(got, e.Name())
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("secret files = %v, want %v", got, want)
	}
}

func TestFetchReadsTokenEachAttempt(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &rotatingClient{tokenPath: tokenPath}
	status, ok := fetch(context.Background(), c, tokenPath, NewFileWriter(t.TempDir()), 30*time.Second,
		&fakeClock{now: time.Unix(0, 0)}, defaultRetry)
	if !ok || status != "ok 0" {
		t.Fatalf("status = %q ok = %v", status, ok)
	}
	if fmt.Sprint(c.tokens) != "[first second]" {
		t.Fatalf("tokens = %v, want [first second]", c.tokens)
	}
}

// rotatingClient fails once with a 503, rotating the token file in between.
type rotatingClient struct {
	tokenPath string
	tokens    []string
}

func (c *rotatingClient) Resolve(_ context.Context, token string) ([]model.ResolvedSecret, error) {
	c.tokens = append(c.tokens, token)
	if len(c.tokens) == 1 {
		if err := os.WriteFile(c.tokenPath, []byte("second"), 0o600); err != nil {
			return nil, err
		}
		return nil, &APIError{Status: 503, Code: "kek_unavailable"}
	}
	return []model.ResolvedSecret{}, nil
}

func TestFetchCancelledContextStopsRetrying(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &scriptClient{results: []result{{err: errRefused}}}
	status, ok := Fetch(ctx, c, tokenPath, NewFileWriter(t.TempDir()), 30*time.Second)
	if ok || !strings.HasPrefix(status, "error unreachable ") {
		t.Fatalf("status = %q ok = %v", status, ok)
	}
	if c.calls != 1 {
		t.Fatalf("calls = %d, want 1", c.calls)
	}
}

func TestFetchStatusWriteFailure(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		setup func(t *testing.T) string // returns the delivery dir
	}{
		{name: "dir missing", setup: func(t *testing.T) string { return filepath.Join(t.TempDir(), "gone") }},
		{name: "status rename fails after the files are written", setup: func(t *testing.T) string {
			d := t.TempDir()
			// A non-empty directory at .status makes the rename onto it fail.
			if err := os.MkdirAll(filepath.Join(d, ".status", "x"), 0o700); err != nil {
				t.Fatal(err)
			}
			return d
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.setup(t)
			c := &scriptClient{results: []result{{secrets: []model.ResolvedSecret{
				{Env: "NEBARI_SECRET_A", Value: []byte("a")}}}}}
			status, ok := Fetch(context.Background(), c, tokenPath, NewFileWriter(dir), time.Second)
			if ok || !strings.HasPrefix(status, "error write_failed ") {
				t.Fatalf("status = %q ok = %v", status, ok)
			}
			if _, err := os.Stat(filepath.Join(dir, "NEBARI_SECRET_A")); err == nil {
				t.Fatal("secret file left behind after a failed status write")
			}
		})
	}
}

func TestRealClockSleep(t *testing.T) {
	tests := []struct {
		name    string
		cancel  bool
		wantErr bool
	}{
		{name: "sleeps", cancel: false},
		{name: "cancelled", cancel: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancel {
				cancel()
			}
			err := realClock{}.Sleep(ctx, time.Millisecond)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// tlsServer starts an HTTP/1.1 TLS server and writes its certificate as a CA
// bundle. The returned URL uses the IP address the certificate names.
func tlsServer(t *testing.T, h http.HandlerFunc) (url, caFile string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	caFile = filepath.Join(t.TempDir(), "ca-certificates.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv.URL + "/api/v1/resolve", caFile
}

type seenRequest struct {
	method, path, proto string
	auth                []string
	bodyLen             int64
}

func TestHTTPResolveClient(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantSecrets []model.ResolvedSecret
		wantErr     error
		wantAPI     *APIError
	}{
		{
			name: "200 decodes values", status: 200,
			body: `{"secrets":[{"env":"NEBARI_SECRET_A","value_b64":"YQBi"},{"env":"NEBARI_SECRET_E","value_b64":""}]}`,
			wantSecrets: []model.ResolvedSecret{
				{Env: "NEBARI_SECRET_A", Value: []byte("a\x00b")},
				{Env: "NEBARI_SECRET_E", Value: []byte{}},
			},
		},
		{name: "200 empty array", status: 200, body: `{"secrets":[]}`, wantSecrets: []model.ResolvedSecret{}},
		{name: "200 missing array", status: 200, body: `{}`, wantErr: errBadResponse},
		{name: "200 not json", status: 200, body: `nope`, wantErr: errBadResponse},
		{name: "200 bad base64", status: 200, body: `{"secrets":[{"env":"NEBARI_SECRET_A","value_b64":"!!"}]}`,
			wantErr: errInvalidResponse},
		{name: "403 code", status: 403, body: `{"error":"pod_predates_guard"}`,
			wantAPI: &APIError{Status: 403, Code: "pod_predates_guard"}},
		{name: "503 with reason", status: 503, body: `{"error":"guard_not_verified","reason":"x"}`,
			wantAPI: &APIError{Status: 503, Code: "guard_not_verified"}},
		{name: "503 unparseable body", status: 503, body: `<html>`,
			wantAPI: &APIError{Status: 503, Code: "unavailable"}},
		{name: "502 proxy page", status: 502, body: `<html>`,
			wantAPI: &APIError{Status: 502, Code: "bad_response"}},
		{name: "code that is not a code", status: 403, body: `{"error":"Bad Thing\n"}`,
			wantAPI: &APIError{Status: 403, Code: "bad_response"}},
		{name: "redirect not followed", status: 307, body: ``,
			wantAPI: &APIError{Status: 307, Code: "bad_response"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var seen seenRequest
			url, ca := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				seen = seenRequest{r.Method, r.URL.Path, r.Proto, r.Header.Values("Authorization"), r.ContentLength}
				mu.Unlock()
				if tt.status == 307 {
					w.Header().Set("Location", "/elsewhere")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			c, err := NewHTTPResolveClient(url, ca)
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.Resolve(context.Background(), testToken)

			mu.Lock()
			defer mu.Unlock()
			if seen.method != http.MethodPost || seen.path != "/api/v1/resolve" || seen.proto != "HTTP/1.1" {
				t.Fatalf("request = %+v", seen)
			}
			if fmt.Sprint(seen.auth) != "[Bearer "+testToken+"]" || seen.bodyLen != 0 {
				t.Fatalf("auth = %v body = %d", seen.auth, seen.bodyLen)
			}
			switch {
			case tt.wantAPI != nil:
				var apiErr *APIError
				if !errors.As(err, &apiErr) || *apiErr != *tt.wantAPI {
					t.Fatalf("err = %v, want %v", err, tt.wantAPI)
				}
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				if fmt.Sprintf("%q", got) != fmt.Sprintf("%q", tt.wantSecrets) {
					t.Fatalf("secrets = %q, want %q", got, tt.wantSecrets)
				}
			}
			if err != nil && (strings.Contains(err.Error(), "SENTINEL") || strings.Contains(err.Error(), "YQBi")) {
				t.Fatalf("error leaks a token or value: %v", err)
			}
		})
	}
}

func TestHTTPResolveClientTLS(t *testing.T) {
	okHandler := func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"secrets":[]}`)) }
	tests := []struct {
		name  string
		setup func(t *testing.T) (url, ca string)
	}{
		{
			name: "server not signed by the bundle",
			setup: func(t *testing.T) (string, string) {
				// httptest servers share one certificate, so trust an unrelated one.
				url, _ := tlsServer(t, okHandler)
				return url, writeCA(t, selfSignedPEM(t))
			},
		},
		{
			name: "host not named by the certificate",
			setup: func(t *testing.T) (string, string) {
				url, ca := tlsServer(t, okHandler)
				_, port, _ := net.SplitHostPort(strings.TrimPrefix(strings.TrimSuffix(url, "/api/v1/resolve"), "https://"))
				// The httptest certificate names 127.0.0.1 and example.com, not localhost.
				return "https://localhost:" + port + "/api/v1/resolve", ca
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, ca := tt.setup(t)
			c, err := NewHTTPResolveClient(url, ca)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Resolve(context.Background(), testToken)
			if err == nil || !strings.Contains(err.Error(), "certificate") {
				t.Fatalf("err = %v, want a certificate verification error", err)
			}
		})
	}
}

func TestNewHTTPResolveClient(t *testing.T) {
	_, goodCA := tlsServer(t, func(http.ResponseWriter, *http.Request) {})
	empty := writeCA(t, []byte("not a certificate\n"))
	tests := []struct {
		name    string
		url     string
		ca      string
		wantErr error
	}{
		{name: "ok", url: "https://user-secrets.ns.svc:8443/api/v1/resolve", ca: goodCA},
		{name: "CA file missing", url: "https://h/api/v1/resolve", ca: filepath.Join(t.TempDir(), "nope"),
			wantErr: ErrCAMissing},
		{name: "CA file has no certificates", url: "https://h/api/v1/resolve", ca: empty, wantErr: ErrCAMissing},
		{name: "plain http refused", url: "http://h/api/v1/resolve", ca: goodCA, wantErr: ErrBadURL},
		{name: "no host", url: "https:///api/v1/resolve", ca: goodCA, wantErr: ErrBadURL},
		{name: "unparseable", url: "https://h:bad/\x7f", ca: goodCA, wantErr: ErrBadURL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewHTTPResolveClient(tt.url, tt.ca)
			if tt.wantErr == nil {
				if err != nil || c == nil {
					t.Fatalf("c = %v err = %v", c, err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeCA(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// ctxClient answers 503 guard_not_verified after a short delay, and fails the
// way http.Client does once its ctx is done.
type ctxClient struct{ delay time.Duration }

func (c ctxClient) Resolve(ctx context.Context, _ string) ([]model.ResolvedSecret, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("Post \"https://x/api/v1/resolve\": %w", ctx.Err())
	case <-time.After(c.delay):
		return nil, &APIError{Status: 503, Code: "guard_not_verified"}
	}
}

func TestFetchBudgetKeepsServerCodeRealClock(t *testing.T) {
	tests := []struct {
		name   string
		budget time.Duration
		retry  retryPolicy
		delay  time.Duration
	}{
		{name: "backoff ends near the budget", budget: 300 * time.Millisecond,
			retry: retryPolicy{first: 10 * time.Millisecond, max: 40 * time.Millisecond}, delay: time.Millisecond},
		{name: "attempt cut off by the budget", budget: 50 * time.Millisecond,
			retry: retryPolicy{first: 5 * time.Millisecond, max: 5 * time.Millisecond}, delay: 30 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenPath := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(tokenPath, []byte("t"), 0o600); err != nil {
				t.Fatal(err)
			}
			status, ok := fetch(context.Background(), ctxClient{delay: tt.delay}, tokenPath,
				NewFileWriter(t.TempDir()), tt.budget, realClock{}, tt.retry)
			if ok || !strings.HasPrefix(status, "error guard_not_verified http 503 after ") {
				t.Fatalf("status = %q ok = %v", status, ok)
			}
		})
	}
}

func TestFetchSpanRecordsOutcome(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	tests := []struct {
		name     string
		results  []result
		wantCode string
		wantErr  bool
	}{
		{name: "success", results: []result{{secrets: []model.ResolvedSecret{
			{Env: "NEBARI_SECRET_A", Value: []byte("value-SENTINEL")}}}}, wantCode: "ok"},
		{name: "failure", results: []result{{err: &APIError{Status: 403, Code: "not_annotated"}}},
			wantCode: "not_annotated", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenPath := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(tokenPath, []byte(testToken), 0o600); err != nil {
				t.Fatal(err)
			}
			before := len(rec.Ended())
			Fetch(context.Background(), &scriptClient{results: tt.results}, tokenPath, NewFileWriter(t.TempDir()),
				time.Second)
			spans := rec.Ended()[before:]
			if len(spans) != 1 || spans[0].Name() != "initfiles.Fetch" {
				t.Fatalf("spans = %v", spans)
			}
			sp := spans[0]
			var got string
			for _, a := range sp.Attributes() {
				if strings.Contains(a.Value.String(), "SENTINEL") {
					t.Fatalf("span attribute leaks a token or value: %v", a)
				}
				if a.Key == "initfiles.status_code" {
					got = a.Value.AsString()
				}
			}
			if got != tt.wantCode {
				t.Fatalf("status_code = %q, want %q", got, tt.wantCode)
			}
			if (sp.Status().Code == codes.Error) != tt.wantErr {
				t.Fatalf("span status = %v, wantErr %v", sp.Status(), tt.wantErr)
			}
		})
	}
}

func TestFileWriterFail(t *testing.T) {
	tests := []struct {
		name       string
		existing   []string // files present before Fail
		setup      func(t *testing.T, dir string) string
		wantErr    string // substring; "" means no error
		wantStatus bool   // .status holds the given status afterwards
		wantLeft   []string
	}{
		{name: "removes secret files and writes status",
			existing:   []string{"NEBARI_SECRET_A", "NEBARI_SECRET_B", "other.txt"},
			wantStatus: true, wantLeft: []string{"other.txt"}},
		{name: "empty dir", wantStatus: true},
		{name: "removes leftover temp files from a killed write",
			existing:   []string{".tmp-123", ".tmp-456", "NEBARI_SECRET_A", "other.txt"},
			wantStatus: true, wantLeft: []string{"other.txt"}},
		{name: "dir missing", setup: func(t *testing.T, _ string) string { return filepath.Join(t.TempDir(), "gone") },
			wantErr: "secret files not removed"},
		{name: "status write fails after removal", existing: []string{"NEBARI_SECRET_A"},
			setup: func(t *testing.T, dir string) string {
				if err := os.MkdirAll(filepath.Join(dir, ".status", "x"), 0o700); err != nil {
					t.Fatal(err)
				}
				return dir
			},
			wantErr: ".status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, n := range tt.existing {
				if err := os.WriteFile(filepath.Join(dir, n), []byte("old-SENTINEL"), 0o440); err != nil {
					t.Fatal(err)
				}
			}
			if tt.setup != nil {
				dir = tt.setup(t, dir)
			}
			err := NewFileWriter(dir).Fail("error pod_missing http 403")
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
			if tt.wantStatus {
				got, err := os.ReadFile(filepath.Join(dir, ".status"))
				if err != nil || string(got) != "error pod_missing http 403" {
					t.Fatalf(".status = %q err = %v", got, err)
				}
			}
			entries, _ := os.ReadDir(dir)
			var left []string
			for _, e := range entries {
				if e.Name() != ".status" {
					left = append(left, e.Name())
				}
			}
			if fmt.Sprint(left) != fmt.Sprint(tt.wantLeft) {
				t.Fatalf("left = %v, want %v", left, tt.wantLeft)
			}
		})
	}
}

func TestFailureStatusFitsLimit(t *testing.T) {
	long := strings.Repeat("d", 300)
	code64 := "c" + strings.Repeat("x", 63)
	tests := []struct {
		name       string
		status     string
		wantPrefix string
		wantSuffix string
	}{
		{name: "short detail unchanged", status: failure("unreachable", "dial tcp: refused"),
			wantPrefix: "error unreachable dial tcp: refused"},
		{name: "long detail cut", status: failure("unreachable", long), wantPrefix: "error unreachable ddd"},
		{name: "attempts suffix kept on a long detail", status: failureAfter("unreachable", oneLine(long), 7),
			wantPrefix: "error unreachable ddd", wantSuffix: "d after 7 attempts"},
		{name: "longest code kept whole", status: failureAfter(code64, long, 12),
			wantPrefix: "error " + code64 + " ddd", wantSuffix: "d after 12 attempts"},
		{name: "cut never splits a rune", status: failure("unreachable", strings.Repeat("é", 150)),
			wantPrefix: "error unreachable é"},
		{name: "empty detail is a dash", status: failure("token_missing", ""), wantPrefix: "error token_missing -"},
		{name: "FailureStatus collapses lines and cuts", status: FailureStatus("ca_missing", "/a\n/b "+long),
			wantPrefix: "error ca_missing /a /b ddd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.status) > 200 {
				t.Errorf("status is %d bytes, want at most 200", len(tt.status))
			}
			if !utf8.ValidString(tt.status) {
				t.Errorf("status is not valid UTF-8: %q", tt.status)
			}
			if strings.Contains(tt.status, "\n") {
				t.Errorf("status has a newline: %q", tt.status)
			}
			if !strings.HasPrefix(tt.status, tt.wantPrefix) || !strings.HasSuffix(tt.status, tt.wantSuffix) {
				t.Errorf("status = %q, want prefix %q and suffix %q", tt.status, tt.wantPrefix, tt.wantSuffix)
			}
		})
	}
}
