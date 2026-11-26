package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
	"github.com/nebari-dev/nebari-user-secrets/internal/guard"
	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"github.com/nebari-dev/nebari-user-secrets/internal/podidentity"
)

const (
	podToken = "pod-token-SECRET"
	noStore  = "no-store"
	jsonType = "application/json"
)

// keycloakJWT looks like a Keycloak access token with user-secrets in aud.
const keycloakJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2tleWNsb2FrIiwiYXVkIjpbInVzZXItc2VjcmV0cyJdLCJ0eXAiOiJCZWFyZXIifQ.c2ln"

var (
	vsTime   = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	goodPod  = model.PodIdentity{Namespace: "jupyterhub", Name: "jupyter-alice", UID: "uid-1", ServiceAccount: "user-pod"}
	seenPod  = model.PodIdentity{Namespace: "jupyterhub", Name: "jupyter-alice", ServiceAccount: "user-pod"} // UID unverified
	goodClm  = model.PodClaim{Pod: goodPod, App: "jupyter", Principal: model.Principal{Kind: "user", Sub: "sub-alice"}, Created: vsTime.Add(time.Minute)}
	twoSecrs = []model.ResolvedSecret{{Env: "NEBARI_SECRET_A", Value: []byte("alpha")}, {Env: "NEBARI_SECRET_B", Value: []byte{0, 1, 0xff}}}
)

type fakePodVerifier struct {
	claim model.PodClaim
	err   error
	calls int
}

func (f *fakePodVerifier) Verify(_ context.Context, bearer string) (model.PodClaim, error) {
	f.calls++
	if bearer != podToken {
		return model.PodClaim{}, &podidentity.DenyError{Reason: podidentity.ReasonNotBound, Status: http.StatusUnauthorized}
	}
	return f.claim, f.err
}

type resolveGuard struct {
	mode    model.GuardMode
	allowed bool
	reason  string
	since   time.Time
}

func (g resolveGuard) Allows() (model.GuardMode, bool) { return g.mode, g.allowed }
func (g resolveGuard) State() guard.GuardState {
	return guard.GuardState{State: "confirmed_bad", Mode: g.mode, Reason: g.reason}
}
func (g resolveGuard) VerifiedSince() time.Time { return g.since }

type deliveryCall struct {
	sub, app string
	count    int
	reason   string
}

type fakeResolver struct {
	secrets   []model.ResolvedSecret
	err       error
	recordErr error
	gotMode   model.GuardMode
	calls     int
	recorded  []deliveryCall
	onResolve func()
	onRecord  func(ctx context.Context)
}

func (f *fakeResolver) Resolve(_ context.Context, _ model.PodClaim, g model.GuardMode) ([]model.ResolvedSecret, error) {
	f.calls++
	f.gotMode = g
	if f.onResolve != nil {
		f.onResolve()
	}
	return f.secrets, f.err
}

func (f *fakeResolver) RecordDelivery(ctx context.Context, c model.PodClaim, count int, reason string) error {
	f.recorded = append(f.recorded, deliveryCall{c.Principal.Sub, string(c.App), count, reason})
	if f.onRecord != nil {
		f.onRecord(ctx)
	}
	return f.recordErr
}

type deniedEvent struct {
	pod    model.PodIdentity
	reason string
}

type recAudit struct {
	mu     sync.Mutex
	denied []deniedEvent
}

func (a *recAudit) SecretRead(context.Context, string, string, string, model.PodClaim, model.GuardMode) {
}
func (a *recAudit) ResolveDenied(_ context.Context, p model.PodIdentity, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.denied = append(a.denied, deniedEvent{p, reason})
}
func (a *recAudit) SecretWrite(context.Context, string, string, string, string) {}
func (a *recAudit) GuardChanged(context.Context, string, string, string)        {}
func (a *recAudit) KeyEvent(context.Context, string, string, string, string)    {}

// rejectingReviewer behaves like a TokenReview that does not recognise the
// token: a Keycloak JWT is not a ServiceAccount token.
type rejectingReviewer struct{}

func (rejectingReviewer) Review(context.Context, string, []string) (authenticationv1.TokenReviewStatus, error) {
	return authenticationv1.TokenReviewStatus{Authenticated: false, Error: "invalid bearer token"}, nil
}

// slowReviewer is a TokenReview that answers only when ctx ends, like an API
// server behind a saturated client rate limiter.
type slowReviewer struct{}

func (slowReviewer) Review(ctx context.Context, _ string, _ []string) (authenticationv1.TokenReviewStatus, error) {
	<-ctx.Done()
	return authenticationv1.TokenReviewStatus{}, ctx.Err()
}

type noPods struct{}

func (noPods) GetPod(context.Context, string, string) (*corev1.Pod, error) {
	return nil, errors.New("must not be called")
}

type allowAll struct{}

func (allowAll) WorkloadAllowed(model.AppID, string, string) bool { return true }

func denyErr(reason string, status int) error {
	return &podidentity.DenyError{Reason: reason, Status: status}
}

func TestResolveHandler(t *testing.T) {
	enforced := resolveGuard{mode: guard.ModeEnforced, allowed: true, since: vsTime}
	old := goodClm
	old.Created = vsTime.Add(-time.Hour)
	sameSecond := goodClm
	sameSecond.Created = vsTime.Add(500 * time.Millisecond)
	nextSecond := goodClm
	nextSecond.Created = vsTime.Add(time.Second)
	unregistered := goodClm
	unregistered.Pod.ServiceAccount = "default"
	unregisteredOld := unregistered
	unregisteredOld.Created = vsTime.Add(-time.Hour)

	tests := []struct {
		name        string
		method      string
		authz       []string
		guard       resolveGuard
		claim       model.PodClaim
		verifyErr   error
		realVerify  bool
		slowVerify  bool // real verifier whose TokenReview never answers
		secrets     []model.ResolvedSecret
		resolveErr  error
		recordErr   error
		wantStatus  int
		wantErr     string
		wantReason  string // guard reason in a guard_not_verified body
		wantDenied  []deniedEvent
		wantRecord  []deliveryCall
		wantSecrets []model.ResolvedSecret
		wantMode    model.GuardMode
		wantVerify  bool
		wantWarn    bool
	}{
		{name: "success", guard: enforced, claim: goodClm, secrets: twoSecrs,
			wantStatus: 200, wantSecrets: twoSecrs, wantMode: guard.ModeEnforced, wantVerify: true,
			wantRecord: []deliveryCall{{"sub-alice", "jupyter", 2, ""}}},
		{name: "none enabled gives an empty array", guard: enforced, claim: goodClm, secrets: []model.ResolvedSecret{},
			wantStatus: 200, wantSecrets: []model.ResolvedSecret{}, wantMode: guard.ModeEnforced, wantVerify: true,
			wantRecord: []deliveryCall{{"sub-alice", "jupyter", 0, ""}}},
		{name: "nil from resolver still an array", guard: enforced, claim: goodClm, secrets: nil,
			wantStatus: 200, wantSecrets: []model.ResolvedSecret{}, wantMode: guard.ModeEnforced, wantVerify: true,
			wantRecord: []deliveryCall{{"sub-alice", "jupyter", 0, ""}}},
		{name: "wrong method", method: http.MethodGet, guard: enforced, claim: goodClm, wantStatus: 405, wantErr: "method_not_allowed"},
		{name: "guard not verified", guard: resolveGuard{mode: guard.ModeEnforced, reason: "binding user-secrets-creators: validationActions lacks Deny"},
			claim: goodClm, wantStatus: 503, wantErr: "guard_not_verified", wantReason: "binding user-secrets-creators: validationActions lacks Deny",
			wantDenied: []deniedEvent{{model.PodIdentity{}, "guard_not_verified"}}},
		{name: "no authorization", authz: []string{}, guard: enforced, claim: goodClm, wantStatus: 401, wantErr: "not_pod_bound",
			wantDenied: []deniedEvent{{model.PodIdentity{}, "not_pod_bound"}}},
		{name: "two bearer headers", authz: []string{"Bearer " + podToken, "Bearer " + podToken}, guard: enforced, claim: goodClm,
			wantStatus: 401, wantErr: "not_pod_bound", wantDenied: []deniedEvent{{model.PodIdentity{}, "not_pod_bound"}}},
		{name: "two tokens in one header", authz: []string{"Bearer " + podToken + " " + podToken}, guard: enforced, claim: goodClm,
			wantStatus: 401, wantErr: "not_pod_bound", wantDenied: []deniedEvent{{model.PodIdentity{}, "not_pod_bound"}}},
		{name: "basic scheme", authz: []string{"Basic " + podToken}, guard: enforced, claim: goodClm,
			wantStatus: 401, wantErr: "not_pod_bound", wantDenied: []deniedEvent{{model.PodIdentity{}, "not_pod_bound"}}},
		{name: "scheme case-insensitive", authz: []string{"bEaReR " + podToken}, guard: enforced, claim: goodClm, secrets: twoSecrs,
			wantStatus: 200, wantSecrets: twoSecrs, wantMode: guard.ModeEnforced, wantVerify: true,
			wantRecord: []deliveryCall{{"sub-alice", "jupyter", 2, ""}}},
		{name: "keycloak jwt rejected by token review (journey 8c)", authz: []string{"Bearer " + keycloakJWT}, realVerify: true,
			guard: enforced, wantStatus: 401, wantErr: "not_pod_bound", wantVerify: true,
			wantDenied: []deniedEvent{{model.PodIdentity{}, "not_pod_bound"}}},
		{name: "uid mismatch audits the token's pod and records no status (journey 17)", guard: enforced,
			claim: model.PodClaim{Pod: seenPod}, verifyErr: denyErr("uid_mismatch", 403),
			wantStatus: 403, wantErr: "uid_mismatch", wantVerify: true, wantDenied: []deniedEvent{{seenPod, "uid_mismatch"}}},
		{name: "pod missing audits the token's pod and records no status", guard: enforced,
			claim: model.PodClaim{Pod: seenPod}, verifyErr: denyErr("pod_missing", 403),
			wantStatus: 403, wantErr: "pod_missing", wantVerify: true, wantDenied: []deniedEvent{{seenPod, "pod_missing"}}},
		{name: "not annotated audits the pod and records no status", guard: enforced,
			claim: model.PodClaim{Pod: goodPod}, verifyErr: denyErr("not_annotated", 403),
			wantStatus: 403, wantErr: "not_annotated", wantVerify: true, wantDenied: []deniedEvent{{goodPod, "not_annotated"}}},
		{name: "not registered and newer than the guard records a failure", guard: enforced, claim: unregistered,
			verifyErr: denyErr("not_registered", 403), wantStatus: 403, wantErr: "not_registered", wantVerify: true,
			wantDenied: []deniedEvent{{unregistered.Pod, "not_registered"}},
			wantRecord: []deliveryCall{{"sub-alice", "jupyter", 0, "not_registered"}}},
		{name: "not registered and predating the guard answers predates and records nothing", guard: enforced,
			claim: unregisteredOld, verifyErr: denyErr("not_registered", 403), wantStatus: 403, wantErr: "pod_predates_guard",
			wantVerify: true, wantDenied: []deniedEvent{{unregisteredOld.Pod, "pod_predates_guard"}}},
		{name: "not registered in override mode skips predates and records", guard: resolveGuard{mode: guard.ModeOverridden, allowed: true},
			claim: unregisteredOld, verifyErr: denyErr("not_registered", 403), wantStatus: 403, wantErr: "not_registered",
			wantVerify: true, wantDenied: []deniedEvent{{unregisteredOld.Pod, "not_registered"}},
			wantRecord: []deliveryCall{{"sub-alice", "jupyter", 0, "not_registered"}}},
		{name: "kubernetes unavailable at verify", guard: enforced, verifyErr: denyErr("kubernetes_unavailable", 503),
			wantStatus: 503, wantErr: "kubernetes_unavailable", wantVerify: true,
			wantDenied: []deniedEvent{{model.PodIdentity{}, "kubernetes_unavailable"}}},
		{name: "slow verifier times out as kubernetes unavailable", guard: enforced, slowVerify: true,
			wantStatus: 503, wantErr: "kubernetes_unavailable", wantVerify: true,
			wantDenied: []deniedEvent{{model.PodIdentity{}, "kubernetes_unavailable"}}},
		{name: "unexpected verify error", guard: enforced, verifyErr: errors.New("boom"),
			wantStatus: 503, wantErr: "kubernetes_unavailable", wantVerify: true,
			wantDenied: []deniedEvent{{model.PodIdentity{}, "kubernetes_unavailable"}}},
		{name: "pod predates guard records nothing", guard: enforced, claim: old, wantStatus: 403, wantErr: "pod_predates_guard",
			wantVerify: true, wantDenied: []deniedEvent{{goodPod, "pod_predates_guard"}}},
		{name: "created in the same second as verifiedSince is refused", guard: enforced, claim: sameSecond,
			wantStatus: 403, wantErr: "pod_predates_guard", wantVerify: true,
			wantDenied: []deniedEvent{{goodPod, "pod_predates_guard"}}},
		{name: "created the next second resolves", guard: enforced, claim: nextSecond, secrets: twoSecrs,
			wantStatus: 200, wantSecrets: twoSecrs, wantMode: guard.ModeEnforced, wantVerify: true,
			wantRecord: []deliveryCall{{"sub-alice", "jupyter", 2, ""}}},
		{name: "overridden skips predates and passes the mode", guard: resolveGuard{mode: guard.ModeOverridden, allowed: true},
			claim: old, secrets: twoSecrs, wantStatus: 200, wantSecrets: twoSecrs, wantMode: guard.ModeOverridden, wantVerify: true,
			wantRecord: []deliveryCall{{"sub-alice", "jupyter", 2, ""}}},
		{name: "kek unavailable", guard: enforced, claim: goodClm, resolveErr: crypto.ErrKEKUnavailable,
			wantStatus: 503, wantErr: "kek_unavailable", wantMode: guard.ModeEnforced, wantVerify: true,
			wantDenied: []deniedEvent{{goodPod, "kek_unavailable"}},
			wantRecord: []deliveryCall{{"sub-alice", "jupyter", 0, "kek_unavailable"}}},
		{name: "decrypt failed", guard: enforced, claim: goodClm, resolveErr: crypto.ErrDecrypt,
			wantStatus: 500, wantErr: "decrypt_failed", wantMode: guard.ModeEnforced, wantVerify: true,
			wantDenied: []deniedEvent{{goodPod, "decrypt_failed"}},
			wantRecord: []deliveryCall{{"sub-alice", "jupyter", 0, "decrypt_failed"}}},
		{name: "store error", guard: enforced, claim: goodClm, resolveErr: errors.New("api down"),
			wantStatus: 503, wantErr: "kubernetes_unavailable", wantMode: guard.ModeEnforced, wantVerify: true,
			wantDenied: []deniedEvent{{goodPod, "kubernetes_unavailable"}}},
		{name: "status write failure is logged and does not change the response", guard: enforced, claim: goodClm,
			secrets: twoSecrs, recordErr: errors.New("status write failed"),
			wantStatus: 200, wantSecrets: twoSecrs, wantMode: guard.ModeEnforced, wantVerify: true, wantWarn: true,
			wantRecord: []deliveryCall{{"sub-alice", "jupyter", 2, ""}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fv := &fakePodVerifier{claim: tt.claim, err: tt.verifyErr}
			var v PodClaimVerifier = fv
			if tt.realVerify {
				v = podidentity.NewPodVerifier(rejectingReviewer{}, noPods{}, allowAll{})
			}
			timeout := resolveTimeout
			if tt.slowVerify {
				v = podidentity.NewPodVerifier(slowReviewer{}, noPods{}, allowAll{})
				timeout = 50 * time.Millisecond
			}
			res := &fakeResolver{secrets: tt.secrets, err: tt.resolveErr, recordErr: tt.recordErr}
			aud := &recAudit{}
			var logs bytes.Buffer
			h := newResolveHandler(v, res, tt.guard, aud, slog.New(slog.NewJSONHandler(&logs, nil)), timeout)

			method := tt.method
			if method == "" {
				method = http.MethodPost
			}
			req := httptest.NewRequest(method, "/api/v1/resolve", nil)
			authz := tt.authz
			if authz == nil {
				authz = []string{"Bearer " + podToken}
			}
			for _, a := range authz {
				req.Header.Add("Authorization", a)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status %d, want %d; body %s", rr.Code, tt.wantStatus, rr.Body)
			}
			checkResolveHeaders(t, rr)
			checkResolveBody(t, rr, tt.wantErr, tt.wantReason, tt.wantSecrets)
			if tt.wantVerify != (fv.calls > 0 || tt.realVerify || tt.slowVerify) {
				t.Errorf("verify calls %d, want called %v", fv.calls, tt.wantVerify)
			}
			if res.gotMode != tt.wantMode {
				t.Errorf("resolver mode %q, want %q", res.gotMode, tt.wantMode)
			}
			if len(aud.denied) != len(tt.wantDenied) {
				t.Fatalf("resolve_denied %+v, want %+v", aud.denied, tt.wantDenied)
			}
			for i := range aud.denied {
				if aud.denied[i] != tt.wantDenied[i] {
					t.Errorf("resolve_denied %+v, want %+v", aud.denied[i], tt.wantDenied[i])
				}
			}
			if len(res.recorded) != len(tt.wantRecord) {
				t.Fatalf("recorded %+v, want %+v", res.recorded, tt.wantRecord)
			}
			for i := range res.recorded {
				if res.recorded[i] != tt.wantRecord[i] {
					t.Errorf("recorded %+v, want %+v", res.recorded[i], tt.wantRecord[i])
				}
			}
			out := logs.String()
			if strings.Contains(out, podToken) || strings.Contains(out, keycloakJWT) || strings.Contains(out, "sub-alice") {
				t.Errorf("log carries a token or raw sub: %s", out)
			}
			for _, s := range twoSecrs {
				if strings.Contains(out, string(s.Value)) {
					t.Errorf("log carries a value: %s", out)
				}
			}
			if got := strings.Count(out, `"level":"WARN"`); (got == 1) != tt.wantWarn || got > 1 {
				t.Errorf("%d warnings, want warn %v: %s", got, tt.wantWarn, out)
			}
			if tt.wantWarn && !strings.Contains(out, `"app":"jupyter"`) {
				t.Errorf("warning lacks the app: %s", out)
			}
		})
	}
}

func checkResolveHeaders(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if cc := rr.Header().Get("Cache-Control"); cc != noStore {
		t.Errorf("Cache-Control %q", cc)
	}
	if ct := rr.Header().Get("Content-Type"); ct != jsonType {
		t.Errorf("Content-Type %q", ct)
	}
	if rr.Code == http.StatusMethodNotAllowed && rr.Header().Get("Allow") != http.MethodPost {
		t.Errorf("Allow %q", rr.Header().Get("Allow"))
	}
}

// checkResolveBody checks an error body carries only the code (and the guard
// reason), and a 200 body exactly the secrets array.
func checkResolveBody(t *testing.T, rr *httptest.ResponseRecorder, wantErr, wantReason string, wantSecrets []model.ResolvedSecret) {
	t.Helper()
	if wantErr != "" {
		var body map[string]string
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"error": wantErr}
		if wantReason != "" {
			want["reason"] = wantReason
		}
		if len(body) != len(want) || body["error"] != want["error"] || body["reason"] != want["reason"] {
			t.Fatalf("body %v, want %v", body, want)
		}
		return
	}
	var body struct {
		Secrets []struct {
			Env      string `json:"env"`
			ValueB64 []byte `json:"value_b64"`
		} `json:"secrets"`
	}
	if !strings.Contains(rr.Body.String(), `"secrets":[`) {
		t.Fatalf("body %s has no secrets array", rr.Body)
	}
	dec := json.NewDecoder(bytes.NewReader(rr.Body.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Secrets) != len(wantSecrets) {
		t.Fatalf("got %d secrets, want %d", len(body.Secrets), len(wantSecrets))
	}
	for i, s := range body.Secrets {
		if s.Env != wantSecrets[i].Env || !bytes.Equal(s.ValueB64, wantSecrets[i].Value) {
			t.Errorf("secret %d = %s %q", i, s.Env, s.ValueB64)
		}
	}
}

// TestResolveHandlerRecordsAfterFlush: the status write starts only once the
// response is flushed, on a context the client's disconnect cannot cancel,
// bounded by its own timeout.
func TestResolveHandlerRecordsAfterFlush(t *testing.T) {
	tests := []struct {
		name       string
		secrets    []model.ResolvedSecret
		resolveErr error
		wantStatus int
	}{
		{name: "success", secrets: twoSecrs, wantStatus: 200},
		{name: "decrypt failed", resolveErr: crypto.ErrDecrypt, wantStatus: 500},
		{name: "kek unavailable", resolveErr: crypto.ErrKEKUnavailable, wantStatus: 503},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqCtx, disconnect := context.WithCancel(context.Background())
			defer disconnect()
			rr := httptest.NewRecorder()
			var (
				recorded, flushed bool
				ctxErr            error
				deadline          time.Time
				hasDeadline       bool
				bodyAtRecord      string
			)
			res := &fakeResolver{secrets: tt.secrets, err: tt.resolveErr,
				onResolve: disconnect, // the client goes away mid-request
				onRecord: func(ctx context.Context) {
					recorded, flushed, bodyAtRecord = true, rr.Flushed, rr.Body.String()
					ctxErr = ctx.Err()
					deadline, hasDeadline = ctx.Deadline()
				}}
			h := NewResolveHandler(&fakePodVerifier{claim: goodClm}, res, resolveGuard{mode: guard.ModeEnforced, allowed: true, since: vsTime},
				&recAudit{}, slog.New(slog.DiscardHandler))
			req := httptest.NewRequest(http.MethodPost, "/api/v1/resolve", nil).WithContext(reqCtx)
			req.Header.Set("Authorization", "Bearer "+podToken)
			start := time.Now()
			h.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status %d, want %d", rr.Code, tt.wantStatus)
			}
			if !recorded {
				t.Fatal("RecordDelivery not called")
			}
			if !flushed || bodyAtRecord == "" || bodyAtRecord != rr.Body.String() {
				t.Errorf("status written before the response was flushed (flushed=%v, body %q)", flushed, bodyAtRecord)
			}
			if ctxErr != nil {
				t.Errorf("status context canceled by the client: %v", ctxErr)
			}
			if !hasDeadline || deadline.Sub(start) > 5*time.Second+time.Second {
				t.Errorf("status context deadline %v (set %v), want about 5 s", deadline.Sub(start), hasDeadline)
			}
		})
	}
}

// blockingRecorder blocks RecordDelivery until release is closed.
type blockingRecorder struct {
	fakeResolver
	started, done, release chan struct{}
}

func (b *blockingRecorder) RecordDelivery(ctx context.Context, c model.PodClaim, count int, reason string) error {
	close(b.started)
	<-b.release
	defer close(b.done)
	return b.fakeResolver.RecordDelivery(ctx, c, count, reason)
}

// TestResolveBodyEndsBeforeStatusWrite runs a real HTTP/1.1 server: the
// client reads the whole body (to EOF) while the status write is still
// blocked, so the status write never delays the pod.
func TestResolveBodyEndsBeforeStatusWrite(t *testing.T) {
	tests := []struct {
		name       string
		resolveErr error
		wantStatus int
		wantBody   string
	}{
		{name: "success", wantStatus: 200, wantBody: `{"secrets":[{"env":"NEBARI_SECRET_A","value_b64":"YWxwaGE="},{"env":"NEBARI_SECRET_B","value_b64":"AAH/"}]}`},
		{name: "decrypt failed", resolveErr: crypto.ErrDecrypt, wantStatus: 500, wantBody: `{"error":"decrypt_failed"}`},
		{name: "kek unavailable", resolveErr: crypto.ErrKEKUnavailable, wantStatus: 503, wantBody: `{"error":"kek_unavailable"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &blockingRecorder{fakeResolver: fakeResolver{secrets: twoSecrs, err: tt.resolveErr},
				started: make(chan struct{}), done: make(chan struct{}), release: make(chan struct{})}
			h := NewResolveHandler(&fakePodVerifier{claim: goodClm}, res,
				resolveGuard{mode: guard.ModeEnforced, allowed: true, since: vsTime}, &recAudit{}, slog.New(slog.DiscardHandler))
			srv := httptest.NewServer(h)
			defer srv.Close()
			released := false
			defer func() {
				if !released {
					close(res.release)
				}
			}()

			req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/resolve", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+podToken)
			type result struct {
				status int
				body   string
				err    error
			}
			got := make(chan result, 1)
			go func() {
				resp, err := srv.Client().Do(req)
				if err != nil {
					got <- result{err: err}
					return
				}
				defer func() { _ = resp.Body.Close() }()
				b, err := io.ReadAll(resp.Body)
				got <- result{resp.StatusCode, string(b), err}
			}()

			select {
			case r := <-got:
				if r.err != nil || r.status != tt.wantStatus || strings.TrimSpace(r.body) != tt.wantBody {
					t.Fatalf("got %d %q %v, want %d %q", r.status, r.body, r.err, tt.wantStatus, tt.wantBody)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("body did not end while the status write was blocked")
			}
			select {
			case <-res.started:
			case <-time.After(3 * time.Second):
				t.Fatal("status write did not start while it was still blocked")
			}
			close(res.release)
			released = true
			select {
			case <-res.done:
			case <-time.After(3 * time.Second):
				t.Fatal("status write did not complete after release")
			}
			if len(res.recorded) != 1 {
				t.Fatalf("recorded %+v", res.recorded)
			}
		})
	}
}

func TestResolveHandlerUnknownPath(t *testing.T) {
	h := NewResolveHandler(&fakePodVerifier{}, &fakeResolver{}, resolveGuard{allowed: true}, &recAudit{}, slog.New(slog.DiscardHandler))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/secrets", nil))
	if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), `"not_found"`) {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
}

func TestResolveHandlerPanicRecovered(t *testing.T) {
	var logs bytes.Buffer
	h := NewResolveHandler(&fakePodVerifier{claim: goodClm}, &panicResolver{}, resolveGuard{mode: guard.ModeEnforced, allowed: true},
		&recAudit{}, slog.New(slog.NewJSONHandler(&logs, nil)))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resolve", nil)
	req.Header.Set("Authorization", "Bearer "+podToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError || strings.Contains(logs.String(), "panic-value") {
		t.Fatalf("%d %s / %s", rr.Code, rr.Body, logs.String())
	}
}

type panicResolver struct{ fakeResolver }

func (panicResolver) Resolve(context.Context, model.PodClaim, model.GuardMode) ([]model.ResolvedSecret, error) {
	panic("panic-value")
}
