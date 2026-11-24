package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/nebari-dev/nebari-user-secrets/internal/audit"
	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
	"github.com/nebari-dev/nebari-user-secrets/internal/guard"
	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"github.com/nebari-dev/nebari-user-secrets/internal/podidentity"
)

// Resolve denial reasons the handler adds to podidentity's.
const (
	reasonGuardNotVerified = "guard_not_verified"
	reasonPredatesGuard    = "pod_predates_guard"
	reasonKEKUnavailable   = "kek_unavailable"
	reasonDecryptFailed    = "decrypt_failed"
)

// PodClaimVerifier turns a projected ServiceAccount token into a pod claim.
// Denials are *podidentity.DenyError; on not_registered the claim built so
// far is returned with the error.
type PodClaimVerifier interface {
	Verify(ctx context.Context, bearer string) (model.PodClaim, error)
}

// GuardAllower is the part of *guard.Guard the resolve handler uses.
type GuardAllower interface {
	Allows() (model.GuardMode, bool)
	State() guard.GuardState
	VerifiedSince() time.Time
}

// Resolver is the part of *service.SecretService the resolve handler uses.
type Resolver interface {
	Resolve(ctx context.Context, c model.PodClaim, g model.GuardMode) ([]model.ResolvedSecret, error)
	RecordDelivery(ctx context.Context, c model.PodClaim, count int, reason string) error
}

var _ GuardAllower = (*guard.Guard)(nil)

type resolveHandler struct {
	v   PodClaimVerifier
	s   Resolver
	g   GuardAllower
	a   audit.AuditSink
	log *slog.Logger
	// timeout bounds token verification, the pod read and the record read.
	timeout time.Duration
}

// NewResolveHandler returns the resolve API: POST /api/v1/resolve with a
// projected ServiceAccount token and no body.
func NewResolveHandler(v PodClaimVerifier, s Resolver, g GuardAllower, a audit.AuditSink, log *slog.Logger) http.Handler {
	return newResolveHandler(v, s, g, a, log, resolveTimeout)
}

// newResolveHandler is NewResolveHandler with the Kubernetes-call timeout
// given, so tests can shorten it.
func newResolveHandler(v PodClaimVerifier, s Resolver, g GuardAllower, a audit.AuditSink, log *slog.Logger,
	timeout time.Duration) http.Handler {
	h := &resolveHandler{v: v, s: s, g: g, a: a, log: log, timeout: timeout}
	mux := http.NewServeMux()
	const path = "/api/v1/resolve"
	mux.Handle("POST "+path, instrument(log, "httpapi.resolve.", "POST "+path, "resolve", h.resolve))
	mux.Handle(path, instrument(log, "httpapi.resolve.", path, "resolve.method", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
	}))
	mux.Handle("/", instrument(log, "httpapi.resolve.", "/", "notfound", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found")
	}))
	return mux
}

type resolvedJSON struct {
	Env      string `json:"env"`
	ValueB64 string `json:"value_b64"`
}

// statusWriteTimeout bounds the delivery status write after the response.
const statusWriteTimeout = 5 * time.Second

// resolveTimeout bounds token verification, the pod read and the record read
// of one resolve call, inside the init client's 30 s budget. A timeout answers
// 503 kubernetes_unavailable.
const resolveTimeout = 20 * time.Second

// resolve answers in the order fixed by the contract: guard, token, pod age,
// then the owner's record. Every denial emits one resolve_denied line.
// Delivery status is recorded only when the guard allowed the call, the pod
// passed verification (or was verified but is not registered), and the pod
// passed the pod age check, so a pod whose annotations cannot be trusted never
// writes into a user's status.
func (h *resolveHandler) resolve(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	mode, ok := h.g.Allows()
	if !ok {
		h.a.ResolveDenied(ctx, model.PodIdentity{}, reasonGuardNotVerified)
		// The reason is fixed text from the guard, never a value.
		writeSized(w, http.StatusServiceUnavailable, reasonGuardNotVerified, struct {
			Error  string `json:"error"`
			Reason string `json:"reason"`
		}{reasonGuardNotVerified, h.g.State().Reason})
		return
	}

	tok, ok := resolveBearer(r)
	if !ok {
		h.deny(w, r, model.PodIdentity{}, http.StatusUnauthorized, podidentity.ReasonNotBound)
		return
	}
	claim, err := h.v.Verify(ctx, tok)
	notRegistered := false
	if err != nil {
		status, reason := http.StatusServiceUnavailable, podidentity.ReasonKubeDown
		var de *podidentity.DenyError
		if errors.As(err, &de) {
			status, reason = de.Status, de.Reason
		}
		// A not_registered claim was read from the API server; it still has to
		// pass the age check below before it may answer or record as such.
		if reason != podidentity.ReasonNotReg || claim.Principal.Sub == "" {
			h.deny(w, r, claim.Pod, status, reason)
			return
		}
		notRegistered = true
	}

	if mode != guard.ModeOverridden {
		created := claim.Created.Truncate(time.Second)
		since := h.g.VerifiedSince().Truncate(time.Second)
		if !created.After(since) {
			h.deny(w, r, claim.Pod, http.StatusForbidden, reasonPredatesGuard)
			return
		}
	}
	if notRegistered {
		h.deny(w, r, claim.Pod, http.StatusForbidden, podidentity.ReasonNotReg)
		h.record(w, r, claim, 0, podidentity.ReasonNotReg)
		return
	}

	secrets, err := h.s.Resolve(ctx, claim, mode)
	if err != nil {
		trace.SpanFromContext(ctx).RecordError(err)
		switch {
		case errors.Is(err, crypto.ErrKEKUnavailable):
			h.deny(w, r, claim.Pod, http.StatusServiceUnavailable, reasonKEKUnavailable)
			h.record(w, r, claim, 0, reasonKEKUnavailable)
		case errors.Is(err, crypto.ErrDecrypt):
			h.deny(w, r, claim.Pod, http.StatusInternalServerError, reasonDecryptFailed)
			h.record(w, r, claim, 0, reasonDecryptFailed)
		default:
			h.deny(w, r, claim.Pod, http.StatusServiceUnavailable, podidentity.ReasonKubeDown)
		}
		return
	}
	out := make([]resolvedJSON, 0, len(secrets))
	for _, s := range secrets {
		out = append(out, resolvedJSON{Env: s.Env, ValueB64: base64.StdEncoding.EncodeToString(s.Value)})
	}
	writeSized(w, http.StatusOK, "", struct {
		Secrets []resolvedJSON `json:"secrets"`
	}{out})
	h.record(w, r, claim, len(out), "")
}

// deny emits the resolve_denied line and writes the code-only error body.
func (h *resolveHandler) deny(w http.ResponseWriter, r *http.Request, pod model.PodIdentity, status int, reason string) {
	h.a.ResolveDenied(r.Context(), pod, reason)
	writeSized(w, status, reason, model.APIError{Error: reason})
}

// writeSized writes v as a JSON body with Content-Length set, so the response
// ends with its last byte: once flushed, an HTTP/1.1 client reads to EOF
// without waiting for the handler to return. code is the error code for the
// request log ("" on success).
func writeSized(w http.ResponseWriter, status int, code string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, code, b = http.StatusInternalServerError, "internal", []byte(`{"error":"internal"}`)
	}
	b = append(b, '\n')
	if rec, ok := w.(*statusRecorder); ok && code != "" {
		rec.code = code
	}
	hdr := w.Header()
	hdr.Set("Content-Type", "application/json")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// record flushes the response already written to w (complete, with its
// Content-Length), then writes delivery
// status on a context detached from the request (a client that disconnects
// cannot cancel it) and bounded by statusWriteTimeout. A failure is logged
// once with the app and the owner's record name (a hash of the sub), never
// the sub, a token or a value, and never changes the response.
func (h *resolveHandler) record(w http.ResponseWriter, r *http.Request, c model.PodClaim, count int, reason string) {
	_ = http.NewResponseController(w).Flush() // best-effort; the client may be gone
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), statusWriteTimeout)
	defer cancel()
	if err := h.s.RecordDelivery(ctx, c, count, reason); err != nil {
		trace.SpanFromContext(ctx).RecordError(err)
		h.log.LogAttrs(ctx, slog.LevelWarn, "delivery status write failed",
			slog.String("owner", model.SecretName(c.Principal.Sub)),
			slog.String("app", string(c.App)),
		)
	}
}

// resolveBearer accepts exactly one Authorization header holding exactly one
// Bearer token.
func resolveBearer(r *http.Request) (string, bool) {
	if len(r.Header.Values("Authorization")) != 1 {
		return "", false
	}
	return bearer(r)
}
