package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/internal/audit"
	"github.com/nebari-dev/nebari-user-secrets/internal/auth"
	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
	"github.com/nebari-dev/nebari-user-secrets/internal/guard"
	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"github.com/nebari-dev/nebari-user-secrets/internal/service"
	"github.com/nebari-dev/nebari-user-secrets/internal/store"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// fakeVerifier maps token strings to principals.
type fakeVerifier map[string]model.Principal

func (f fakeVerifier) Verify(_ context.Context, raw string) (model.Principal, error) {
	if p, ok := f[raw]; ok {
		return p, nil
	}
	return model.Principal{}, auth.ErrInvalidToken
}

type fakeGuard struct{ st guard.GuardState }

func (f fakeGuard) State() guard.GuardState { return f.st }

type fakeApps []model.AppID

func (f fakeApps) Apps() []model.AppID { return f }

// fakeSecrets records the principal and name each call received.
type fakeSecrets struct {
	mu      sync.Mutex
	err     error
	created bool
	calls   []string // "<op> <sub> <name>"
	in      service.UpsertInput
}

func (f *fakeSecrets) rec(op string, u model.Principal, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, op+" "+u.Sub+" "+name)
}

func (f *fakeSecrets) ListForOwner(_ context.Context, u model.Principal) (model.OwnerView, error) {
	f.rec("list", u, "")
	if f.err != nil {
		return model.OwnerView{}, f.err
	}
	return model.OwnerView{Secrets: []model.SecretSummary{{Name: "a", Bindings: []model.BindingView{}}}}, nil
}

func (f *fakeSecrets) Upsert(_ context.Context, u model.Principal, in service.UpsertInput) (model.SecretSummary, bool, error) {
	f.rec("upsert", u, in.Name)
	f.in = in
	if f.err != nil {
		return model.SecretSummary{}, false, f.err
	}
	return model.SecretSummary{Name: in.Name, Bindings: []model.BindingView{}}, f.created, nil
}

func (f *fakeSecrets) Delete(_ context.Context, u model.Principal, name string) error {
	f.rec("delete", u, name)
	return f.err
}

var (
	alice = model.Principal{Kind: "user", Sub: "sub-alice", Username: "alice"}
	bob   = model.Principal{Kind: "user", Sub: "sub-bob", Username: "bob"}
)

func newHandler(s Secrets) http.Handler {
	return NewManagementHandler(
		fakeVerifier{"tok-alice": alice, "tok-bob": bob},
		s,
		fakeApps{"notebook", "other"},
		fakeGuard{guard.GuardState{State: "verified", Mode: "overridden", Reason: "x"}},
		slog.New(slog.NewJSONHandler(io.Discard, nil)),
	)
}

func do(h http.Handler, method, path, authz, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func errCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var e model.APIError
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil {
		t.Fatalf("body is not APIError JSON: %q: %v", rr.Body.String(), err)
	}
	return e.Error
}

func TestRoutes(t *testing.T) {
	good := "Bearer tok-alice"
	put := `{"description":"d","value_b64":"` + base64.StdEncoding.EncodeToString([]byte("v")) + `","bindings":[{"app":"notebook","env":"X"}]}`
	tests := []struct {
		name         string
		method, path string
		authz, body  string
		svcErr       error
		created      bool
		wantStatus   int
		wantErr      string
		wantBody     string // substring on success
	}{
		{name: "list ok", method: "GET", path: "/api/v1/secrets", authz: good, wantStatus: 200, wantBody: `"secrets"`},
		{name: "put created", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: put, created: true, wantStatus: 201, wantBody: `"name":"a"`},
		{name: "put updated", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: put, wantStatus: 200, wantBody: `"name":"a"`},
		{name: "put absent value keeps", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: `{"description":"d"}`, wantStatus: 200},
		{name: "put bad base64", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: `{"value_b64":"!!!"}`, wantStatus: 400, wantErr: "invalid_value"},
		{name: "put url-safe base64 rejected", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: `{"value_b64":"-_-_"}`, wantStatus: 400, wantErr: "invalid_value"},
		{name: "put unknown field", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: `{"nope":1}`, wantStatus: 400, wantErr: "invalid_request"},
		{name: "put not json", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: `x`, wantStatus: 400, wantErr: "invalid_request"},
		{name: "put empty body", method: "PUT", path: "/api/v1/secrets/a", authz: good, wantStatus: 400, wantErr: "invalid_request"},
		{name: "put trailing object", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: `{}{}`, wantStatus: 400, wantErr: "invalid_request"},
		{name: "put trailing object spaced", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: `{} {}`, wantStatus: 400, wantErr: "invalid_request"},
		{name: "put trailing brace", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: `{} }`, wantStatus: 400, wantErr: "invalid_request"},
		{name: "put trailing bracket", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: `{}]`, wantStatus: 400, wantErr: "invalid_request"},
		{name: "put empty value rejected", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: `{"value_b64":""}`, wantStatus: 400, wantErr: "invalid_value"},
		{name: "put null value keeps", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: `{"value_b64":null}`, wantStatus: 200},
		{name: "delete ok", method: "DELETE", path: "/api/v1/secrets/a", authz: good, wantStatus: 204},
		{name: "apps", method: "GET", path: "/api/v1/apps", authz: good, wantStatus: 200, wantBody: `{"apps":["notebook","other"]}`},
		{name: "status", method: "GET", path: "/api/v1/status", authz: good, wantStatus: 200, wantBody: `{"guard":{"state":"verified","mode":"overridden","reason":"x"}}`},

		{name: "no auth", method: "GET", path: "/api/v1/secrets", wantStatus: 401, wantErr: "invalid_token"},
		{name: "bad token", method: "GET", path: "/api/v1/secrets", authz: "Bearer nope", wantStatus: 401, wantErr: "invalid_token"},
		{name: "basic scheme", method: "GET", path: "/api/v1/secrets", authz: "Basic tok-alice", wantStatus: 401, wantErr: "invalid_token"},
		{name: "two tokens", method: "GET", path: "/api/v1/secrets", authz: "Bearer tok-alice x", wantStatus: 401, wantErr: "invalid_token"},
		{name: "double space", method: "GET", path: "/api/v1/secrets", authz: "Bearer  tok-alice", wantStatus: 401, wantErr: "invalid_token"},
		{name: "scheme only", method: "GET", path: "/api/v1/secrets", authz: "Bearer", wantStatus: 401, wantErr: "invalid_token"},
		{name: "scheme case-insensitive", method: "GET", path: "/api/v1/secrets", authz: "bEaReR tok-alice", wantStatus: 200},
		{name: "put no auth", method: "PUT", path: "/api/v1/secrets/a", body: put, wantStatus: 401, wantErr: "invalid_token"},
		{name: "apps no auth", method: "GET", path: "/api/v1/apps", wantStatus: 401, wantErr: "invalid_token"},
		{name: "status no auth", method: "GET", path: "/api/v1/status", wantStatus: 401, wantErr: "invalid_token"},

		{name: "invalid_name", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: put, svcErr: service.ErrInvalidName, wantStatus: 400, wantErr: "invalid_name"},
		{name: "invalid_suffix", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: put, svcErr: service.ErrInvalidSuffix, wantStatus: 400, wantErr: "invalid_suffix"},
		{name: "unknown_app", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: put, svcErr: service.ErrUnknownApp, wantStatus: 400, wantErr: "unknown_app"},
		{name: "grants_not_supported", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: put, svcErr: service.ErrGrantsNotSupported, wantStatus: 400, wantErr: "grants_not_supported"},
		{name: "limit_exceeded", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: put, svcErr: service.ErrLimitExceeded, wantStatus: 400, wantErr: "limit_exceeded"},
		{name: "value_required", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: put, svcErr: service.ErrValueRequired, wantStatus: 400, wantErr: "value_required"},
		{name: "wrapped invalid_name", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: put, svcErr: fmt.Errorf("ctx: %w", service.ErrInvalidName), wantStatus: 400, wantErr: "invalid_name"},
		{name: "not_found delete", method: "DELETE", path: "/api/v1/secrets/a", authz: good, svcErr: service.ErrNotFound, wantStatus: 404, wantErr: "not_found"},
		{name: "env_conflict", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: put, svcErr: service.ErrEnvConflict, wantStatus: 409, wantErr: "env_conflict"},
		{name: "kek_unavailable", method: "GET", path: "/api/v1/secrets", authz: good, svcErr: fmt.Errorf("x: %w", crypto.ErrKEKUnavailable), wantStatus: 503, wantErr: "kek_unavailable"},
		{name: "kubernetes_unavailable", method: "GET", path: "/api/v1/secrets", authz: good, svcErr: errors.New("boom"), wantStatus: 503, wantErr: "kubernetes_unavailable"},
		{name: "kubernetes_unavailable put", method: "PUT", path: "/api/v1/secrets/a", authz: good, body: put, svcErr: errors.New("boom"), wantStatus: 503, wantErr: "kubernetes_unavailable"},
		{name: "kubernetes_unavailable delete", method: "DELETE", path: "/api/v1/secrets/a", authz: good, svcErr: errors.New("boom"), wantStatus: 503, wantErr: "kubernetes_unavailable"},

		{name: "405 secrets POST", method: "POST", path: "/api/v1/secrets", authz: good, wantStatus: 405, wantErr: "method_not_allowed"},
		{name: "405 secrets/{name} GET", method: "GET", path: "/api/v1/secrets/a", authz: good, wantStatus: 405, wantErr: "method_not_allowed"},
		{name: "405 apps PUT", method: "PUT", path: "/api/v1/apps", authz: good, wantStatus: 405, wantErr: "method_not_allowed"},
		{name: "405 status DELETE", method: "DELETE", path: "/api/v1/status", authz: good, wantStatus: 405, wantErr: "method_not_allowed"},
		{name: "404 unknown", method: "GET", path: "/api/v1/nope", authz: good, wantStatus: 404, wantErr: "not_found"},
		{name: "404 root", method: "GET", path: "/", authz: good, wantStatus: 404, wantErr: "not_found"},
		{name: "404 nested name", method: "PUT", path: "/api/v1/secrets/a/b", authz: good, body: put, wantStatus: 404, wantErr: "not_found"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := &fakeSecrets{err: tc.svcErr, created: tc.created}
			rr := do(newHandler(fs), tc.method, tc.path, tc.authz, tc.body)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %q", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if ct := rr.Header().Get("Content-Type"); tc.wantStatus != 204 && ct != "application/json" {
				t.Errorf("Content-Type = %q", ct)
			}
			if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
				t.Errorf("Cache-Control = %q", cc)
			}
			if tc.wantStatus == 405 {
				want := map[string]string{"/api/v1/secrets": "GET, HEAD", "/api/v1/apps": "GET, HEAD", "/api/v1/status": "GET, HEAD", "/api/v1/secrets/a": "PUT, DELETE"}[tc.path]
				if got := rr.Header().Get("Allow"); got != want {
					t.Errorf("Allow = %q, want %q", got, want)
				}
			}
			if tc.wantErr != "" {
				if got := errCode(t, rr); got != tc.wantErr {
					t.Errorf("error = %q, want %q", got, tc.wantErr)
				}
				if strings.Contains(rr.Body.String(), "detail") {
					t.Errorf("error body has detail: %q", rr.Body.String())
				}
			}
			if tc.wantBody != "" && !strings.Contains(rr.Body.String(), tc.wantBody) {
				t.Errorf("body %q lacks %q", rr.Body.String(), tc.wantBody)
			}
			if tc.wantStatus == 401 && len(fs.calls) != 0 {
				t.Errorf("service called without auth: %v", fs.calls)
			}
		})
	}
}

type panicSecrets struct {
	fakeSecrets
	val any
}

func (p *panicSecrets) ListForOwner(context.Context, model.Principal) (model.OwnerView, error) {
	panic(p.val)
}

func TestPanicRecovered(t *testing.T) {
	tests := []struct {
		name      string
		val       any
		propagate bool
		wantType  string
	}{
		{"string with marker", "boom leak-me-123", false, "string"},
		{"error with marker", errors.New("leak-me-123"), false, "*errors.errorString"},
		{"abort handler propagates", http.ErrAbortHandler, true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			h := NewManagementHandler(fakeVerifier{"tok-alice": alice}, &panicSecrets{val: tc.val}, fakeApps{}, fakeGuard{},
				slog.New(slog.NewJSONHandler(&logs, nil)))
			if tc.propagate {
				defer func() {
					if r := recover(); r != http.ErrAbortHandler {
						t.Fatalf("recovered %v, want http.ErrAbortHandler", r)
					}
				}()
				do(h, "GET", "/api/v1/secrets", "Bearer tok-alice", "")
				t.Fatal("did not panic")
			}
			rr := do(h, "GET", "/api/v1/secrets", "Bearer tok-alice", "")
			if rr.Code != 500 || errCode(t, rr) != "internal" {
				t.Fatalf("status %d body %q", rr.Code, rr.Body.String())
			}
			if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Content-Type") != "application/json" {
				t.Errorf("headers %v", rr.Header())
			}
			l := logs.String()
			if !strings.Contains(l, `"panic_type":"`+tc.wantType+`"`) || strings.Contains(l, "leak-me-123") || strings.Contains(l, "tok-alice") {
				t.Errorf("log %q", l)
			}
		})
	}
}

func TestErrorCodeLogged(t *testing.T) {
	var logs bytes.Buffer
	h := NewManagementHandler(fakeVerifier{"tok-alice": alice}, &fakeSecrets{err: errors.New("secret detail text")}, fakeApps{}, fakeGuard{},
		slog.New(slog.NewJSONHandler(&logs, nil)))
	rr := do(h, "GET", "/api/v1/secrets", "Bearer tok-alice", "")
	if rr.Code != 503 || strings.Contains(rr.Body.String(), "secret detail") {
		t.Fatalf("status %d body %q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(logs.String(), `"code":"kubernetes_unavailable"`) || strings.Contains(logs.String(), "secret detail") {
		t.Errorf("log %q", logs.String())
	}
}

func TestPutPassesInput(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantNil   bool
		wantValue string
	}{
		{"absent keeps", `{"description":"d"}`, true, ""},
		{"null keeps", `{"value_b64":null}`, true, ""},
		{"present", `{"value_b64":"` + base64.StdEncoding.EncodeToString([]byte("hello")) + `"}`, false, "hello"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := &fakeSecrets{}
			rr := do(newHandler(fs), "PUT", "/api/v1/secrets/n1", "Bearer tok-alice", tc.body)
			if rr.Code != 200 {
				t.Fatalf("status %d", rr.Code)
			}
			if (fs.in.Value == nil) != tc.wantNil || string(fs.in.Value) != tc.wantValue {
				t.Errorf("Value = %#v", fs.in.Value)
			}
			if fs.in.Name != "n1" {
				t.Errorf("Name = %q", fs.in.Name)
			}
		})
	}
}

func TestOnlyCallersRecord(t *testing.T) {
	tests := []struct {
		name, method, path, body, token, wantSub string
	}{
		{"list alice", "GET", "/api/v1/secrets", "", "tok-alice", "sub-alice"},
		{"list bob", "GET", "/api/v1/secrets", "", "tok-bob", "sub-bob"},
		{"list with sub query", "GET", "/api/v1/secrets?sub=sub-bob&owner=sub-bob", "", "tok-alice", "sub-alice"},
		{"put with sub query", "PUT", "/api/v1/secrets/a?sub=sub-bob", `{"description":"d"}`, "tok-alice", "sub-alice"},
		{"put body owner rejected as unknown field", "PUT", "/api/v1/secrets/a", `{"sub":"sub-bob"}`, "tok-alice", ""},
		{"delete with sub query", "DELETE", "/api/v1/secrets/a?sub=sub-bob", "", "tok-alice", "sub-alice"},
		{"name that looks like a sub", "DELETE", "/api/v1/secrets/sub-bob", "", "tok-alice", "sub-alice"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := &fakeSecrets{}
			rr := do(newHandler(fs), tc.method, tc.path, "Bearer "+tc.token, tc.body)
			if tc.wantSub == "" {
				if rr.Code != 400 || len(fs.calls) != 0 {
					t.Fatalf("status %d calls %v", rr.Code, fs.calls)
				}
				return
			}
			if len(fs.calls) != 1 {
				t.Fatalf("calls = %v", fs.calls)
			}
			if !strings.Contains(fs.calls[0], " "+tc.wantSub+" ") {
				t.Errorf("call %q not for %s", fs.calls[0], tc.wantSub)
			}
		})
	}
}

func TestCookieIgnored(t *testing.T) {
	paths := []struct{ method, path string }{
		{"GET", "/api/v1/secrets"}, {"PUT", "/api/v1/secrets/a"}, {"DELETE", "/api/v1/secrets/a"},
		{"GET", "/api/v1/apps"}, {"GET", "/api/v1/status"},
	}
	for _, p := range paths {
		t.Run(p.method+" "+p.path, func(t *testing.T) {
			fs := &fakeSecrets{}
			req := httptest.NewRequest(p.method, p.path, strings.NewReader(`{}`))
			req.AddCookie(&http.Cookie{Name: "session", Value: "tok-alice"})
			req.AddCookie(&http.Cookie{Name: "Authorization", Value: "Bearer tok-alice"})
			rr := httptest.NewRecorder()
			newHandler(fs).ServeHTTP(rr, req)
			if rr.Code != 401 || errCode(t, rr) != "invalid_token" {
				t.Fatalf("status %d body %q", rr.Code, rr.Body.String())
			}
			if len(fs.calls) != 0 {
				t.Errorf("service called: %v", fs.calls)
			}
		})
	}
}

func TestRequestBodyLimit(t *testing.T) {
	tests := []struct {
		name       string
		size       int
		wantStatus int
	}{
		{"under limit", 1024, 400}, // not valid JSON for the fake, but not 413
		{"at limit", 64 * 1024, 400},
		{"over limit", 64*1024 + 1, 413},
		{"far over limit", 1 << 20, 413},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := &fakeSecrets{}
			body := (`{"description":"` + strings.Repeat("a", tc.size) + `"}`)[:tc.size]
			rr := do(newHandler(fs), "PUT", "/api/v1/secrets/a", "Bearer tok-alice", body)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d", rr.Code, tc.wantStatus)
			}
			if tc.wantStatus == 413 {
				if errCode(t, rr) != "request_too_large" {
					t.Errorf("body %q", rr.Body.String())
				}
				if len(fs.calls) != 0 {
					t.Errorf("service called")
				}
			}
		})
	}
}

// bumpVersions makes the fake clientset enforce resourceVersion like the API server.
func bumpVersions(cs *fake.Clientset) {
	var n int64
	cs.PrependReactor("create", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		a.(k8stesting.CreateAction).GetObject().(metav1.Object).SetResourceVersion(strconv.FormatInt(atomic.AddInt64(&n, 1), 10))
		return false, nil, nil
	})
	cs.PrependReactor("update", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		obj := a.(k8stesting.UpdateAction).GetObject().(*corev1.Secret)
		cur, err := cs.Tracker().Get(corev1.SchemeGroupVersion.WithResource("secrets"), obj.Namespace, obj.Name)
		if err != nil {
			return false, nil, nil
		}
		if cur.(*corev1.Secret).ResourceVersion != obj.ResourceVersion {
			return true, nil, apierrors.NewConflict(corev1.Resource("secrets"), obj.Name, errors.New("stale"))
		}
		obj.ResourceVersion = strconv.FormatInt(atomic.AddInt64(&n, 1), 10)
		return false, nil, nil
	})
}

const failName = "failing"

// flaky fails writes to failName with a plain error, as a down API would.
type flaky struct{ Secrets }

func (f flaky) Upsert(ctx context.Context, u model.Principal, in service.UpsertInput) (model.SecretSummary, bool, error) {
	if in.Name == failName {
		return model.SecretSummary{}, false, errors.New("dial tcp 10.0.0.1: connection refused")
	}
	return f.Secrets.Upsert(ctx, u, in)
}

type nopAudit struct{ audit.AuditSink }

func (nopAudit) SecretWrite(context.Context, string, string, string, string) {}

// TestValueNeverReturned is journey 2: the real service, store and sealer sit
// behind the handler, and no response body contains the value or its base64.
func TestValueNeverReturned(t *testing.T) {
	const value = "zq-unique-value-91"
	b64 := base64.StdEncoding.EncodeToString([]byte(value))
	cs := fake.NewClientset()
	bumpVersions(cs)
	st := store.NewKubernetesSecretStore(cs, "us", time.Now)
	kek := crypto.NewMemoryKEK(map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)}, "k1")
	svc := service.NewSecretService(st, crypto.NewSealer(kek, rand.Reader), nopAudit{}, fakeApps{"notebook", "other"}, service.DefaultLimits(), time.Now)
	var logs bytes.Buffer
	h := NewManagementHandler(fakeVerifier{"tok-alice": alice}, flaky{svc}, fakeApps{"notebook", "other"},
		fakeGuard{guard.GuardState{State: "verified", Mode: "enforced"}}, slog.New(slog.NewJSONHandler(&logs, nil)))
	authz := "Bearer tok-alice"

	steps := []struct {
		name, method, path, body string
		wantStatus               int
	}{
		{"create", "PUT", "/api/v1/secrets/tok", `{"description":"d","value_b64":"` + b64 + `","bindings":[{"app":"notebook","env":"TOK"}]}`, 201},
		{"list", "GET", "/api/v1/secrets", "", 200},
		{"rotate keeps value hidden", "PUT", "/api/v1/secrets/tok", `{"description":"e","value_b64":"` + b64 + `","bindings":[{"app":"notebook","env":"TOK"}]}`, 200},
		{"update absent value", "PUT", "/api/v1/secrets/tok", `{"description":"f","bindings":[{"app":"notebook","env":"TOK"}]}`, 200},
		{"apps", "GET", "/api/v1/apps", "", 200},
		{"status", "GET", "/api/v1/status", "", 200},
		{"error: unknown app", "PUT", "/api/v1/secrets/tok2", `{"value_b64":"` + b64 + `","bindings":[{"app":"nope","env":"A"}]}`, 400},
		{"error: invalid suffix", "PUT", "/api/v1/secrets/tok2", `{"value_b64":"` + b64 + `","bindings":[{"app":"notebook","env":"bad"}]}`, 400},
		{"error: invalid name", "PUT", "/api/v1/secrets/1bad", `{"value_b64":"` + b64 + `"}`, 400},
		{"error: env conflict", "PUT", "/api/v1/secrets/tok3", `{"value_b64":"` + b64 + `","bindings":[{"app":"notebook","env":"TOK"}]}`, 409},
		{"error: bad base64 echoes nothing", "PUT", "/api/v1/secrets/tok2", `{"value_b64":"` + b64 + `!!"}`, 400},
		{"error: unknown field", "PUT", "/api/v1/secrets/tok2", `{"value":"` + value + `"}`, 400},
		{"error: wrong method", "POST", "/api/v1/secrets", `{"value_b64":"` + b64 + `"}`, 405},
		{"error: unauthenticated", "PUT", "/api/v1/secrets/tok", `{"value_b64":"` + b64 + `"}`, 401},
		{"error: too large", "PUT", "/api/v1/secrets/tok2", `{"value_b64":"` + b64 + `","description":"` + strings.Repeat("a", 70000) + `"}`, 413},
		{"error: kubernetes unavailable", "PUT", "/api/v1/secrets/" + failName, `{"value_b64":"` + b64 + `"}`, 503},
		{"error: empty value", "PUT", "/api/v1/secrets/tok2", `{"value_b64":""}`, 400},
		{"delete", "DELETE", "/api/v1/secrets/tok", "", 204},
		{"delete again", "DELETE", "/api/v1/secrets/tok", "", 404},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			a := authz
			if s.name == "error: unauthenticated" {
				a = ""
			}
			rr := do(h, s.method, s.path, a, s.body)
			if rr.Code != s.wantStatus {
				t.Fatalf("status %d, want %d; %q", rr.Code, s.wantStatus, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), value) || strings.Contains(rr.Body.String(), b64) {
				t.Fatalf("response contains the value: %q", rr.Body.String())
			}
			for k, v := range rr.Header() {
				if j := strings.Join(v, ","); strings.Contains(j, value) || strings.Contains(j, b64) {
					t.Fatalf("header %s contains the value", k)
				}
			}
		})
	}
	for _, secret := range []string{value, b64, "tok-alice"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("log output contains %q", secret)
		}
	}
	if logs.Len() == 0 {
		t.Error("no log output captured")
	}
}

func TestStubGuardStatus(t *testing.T) {
	got := StubGuardStatus{}.State()
	want := guard.GuardState{State: "unknown", Mode: "enforced", Reason: "not_started"}
	if got != want {
		t.Errorf("got %+v", got)
	}
}
