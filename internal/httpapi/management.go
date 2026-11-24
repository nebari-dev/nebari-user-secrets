// Package httpapi serves the management API the landing page calls.
package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/internal/guard"
	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"github.com/nebari-dev/nebari-user-secrets/internal/service"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// maxBodyBytes bounds a request body. A value is at most 32 KiB before base64.
const maxBodyBytes = 64 * 1024

// Verifier turns a bearer token into the caller's identity.
type Verifier interface {
	Verify(ctx context.Context, raw string) (model.Principal, error)
}

// Secrets is the part of *service.SecretService the handler uses.
type Secrets interface {
	ListForOwner(ctx context.Context, u model.Principal) (model.OwnerView, error)
	Upsert(ctx context.Context, u model.Principal, in service.UpsertInput) (model.SecretSummary, bool, error)
	Delete(ctx context.Context, u model.Principal, name string) error
}

// AppLister lists the registered apps.
type AppLister interface {
	Apps() []model.AppID
}

// GuardStatus reports the guard's state.
type GuardStatus interface {
	State() guard.GuardState
}

type handler struct {
	v    Verifier
	s    Secrets
	apps AppLister
	g    GuardStatus
	log  *slog.Logger
}

// NewManagementHandler returns the management API. Every route acts only on
// the principal the token verifies to; cookies are never read.
func NewManagementHandler(v Verifier, s Secrets, apps AppLister, g GuardStatus, log *slog.Logger) http.Handler {
	h := &handler{v: v, s: s, apps: apps, g: g, log: log}
	mux := http.NewServeMux()
	route := func(pattern, name string, fn func(http.ResponseWriter, *http.Request, model.Principal)) {
		mux.Handle(pattern, h.instrument(pattern, name, h.authenticated(fn)))
	}
	// A method-less pattern on the same path catches the other methods, so a
	// wrong method gets a JSON 405 instead of the mux's plain text.
	notAllowed := func(path, name, allow string) {
		mux.Handle(path, h.instrument(path, name, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Allow", allow)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		}))
	}

	route("GET /api/v1/secrets", "secrets.list", h.list)
	route("PUT /api/v1/secrets/{name}", "secrets.put", h.put)
	route("DELETE /api/v1/secrets/{name}", "secrets.delete", h.delete)
	route("GET /api/v1/apps", "apps", h.listApps)
	route("GET /api/v1/status", "status", h.status)
	notAllowed("/api/v1/secrets", "secrets.method", "GET, HEAD")
	notAllowed("/api/v1/secrets/{name}", "secrets.name.method", "PUT, DELETE")
	notAllowed("/api/v1/apps", "apps.method", "GET, HEAD")
	notAllowed("/api/v1/status", "status.method", "GET, HEAD")
	mux.Handle("/", h.instrument("/", "notfound", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found")
	}))
	return mux
}

// statusRecorder captures the status for the request log.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
	code   string // error code of the response, if any
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.wrote = true
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying writer (Flush).
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.ResponseWriter.Write(b)
}

func (h *handler) instrument(pattern, name string, next http.HandlerFunc) http.Handler {
	return instrument(h.log, "httpapi.management.", pattern, name, next)
}

// instrument starts the span and writes one log line per request: method,
// route pattern, status and duration, never the token, body or value.
func instrument(log *slog.Logger, spanPrefix, pattern, name string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx, span := otel.Tracer("nebari-user-secrets").Start(r.Context(), spanPrefix+name)
		defer span.End()
		span.SetAttributes(attribute.String("http.route", pattern), attribute.String("http.method", r.Method))
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		func() {
			defer func() {
				if p := recover(); p != nil {
					if p == http.ErrAbortHandler {
						panic(p) // net/http's intended abort path
					}
					// The panic value may hold a secret: log only its type.
					span.RecordError(errors.New("handler panic"))
					log.LogAttrs(ctx, slog.LevelError, "panic",
						slog.String("method", r.Method),
						slog.String("route", pattern),
						slog.String("panic_type", fmt.Sprintf("%T", p)),
					)
					if !rec.wrote {
						writeError(rec, http.StatusInternalServerError, "internal")
					}
				}
			}()
			next(rec, r.WithContext(ctx))
		}()
		span.SetAttributes(attribute.Int("http.status_code", rec.status))
		attrs := []slog.Attr{
			slog.String("method", r.Method),
			slog.String("route", pattern),
			slog.Int("status", rec.status),
			slog.Duration("duration", time.Since(start)),
		}
		if rec.code != "" {
			attrs = append(attrs, slog.String("code", rec.code))
		}
		log.LogAttrs(ctx, slog.LevelInfo, "request", attrs...)
	})
}

// bearer extracts the token from "Bearer <token>": scheme matched without
// case, exactly one space, exactly one token.
func bearer(r *http.Request) (string, bool) {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" || strings.ContainsAny(tok, " \t") {
		return "", false
	}
	return tok, true
}

func (h *handler) authenticated(fn func(http.ResponseWriter, *http.Request, model.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := bearer(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		p, err := h.v.Verify(r.Context(), tok)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		fn(w, r, p)
	}
}

// fail records err on the request span and answers with its mapped code. The
// error text goes to the span only, never to the response.
func fail(w http.ResponseWriter, r *http.Request, err error) {
	trace.SpanFromContext(r.Context()).RecordError(err)
	status, code := statusFor(err)
	writeError(w, status, code)
}

func (h *handler) list(w http.ResponseWriter, r *http.Request, p model.Principal) {
	view, err := h.s.ListForOwner(r.Context(), p)
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

type putRequest struct {
	Description string          `json:"description"`
	ValueB64    *string         `json:"value_b64"`
	Bindings    []model.Binding `json:"bindings"`
	Grants      []model.Grant   `json:"grants"`
}

func (h *handler) put(w http.ResponseWriter, r *http.Request, p model.Principal) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	var req putRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	in := service.UpsertInput{
		Name:        r.PathValue("name"),
		Description: req.Description,
		Bindings:    req.Bindings,
		Grants:      req.Grants,
	}
	if req.ValueB64 != nil {
		val, err := base64.StdEncoding.Strict().DecodeString(*req.ValueB64)
		// An empty value is meaningless, and a form sending "" for an
		// untouched field must not wipe the secret.
		if err != nil || len(val) == 0 {
			writeError(w, http.StatusBadRequest, "invalid_value")
			return
		}
		in.Value = val
	}
	sum, created, err := h.s.Upsert(r.Context(), p, in)
	if err != nil {
		fail(w, r, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, sum)
}

func (h *handler) delete(w http.ResponseWriter, r *http.Request, p model.Principal) {
	if err := h.s.Delete(r.Context(), p, r.PathValue("name")); err != nil {
		fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) listApps(w http.ResponseWriter, _ *http.Request, _ model.Principal) {
	apps := h.apps.Apps()
	if apps == nil {
		apps = []model.AppID{}
	}
	writeJSON(w, http.StatusOK, struct {
		Apps []model.AppID `json:"apps"`
	}{apps})
}

func (h *handler) status(w http.ResponseWriter, _ *http.Request, _ model.Principal) {
	st := h.g.State()
	type guardJSON struct {
		State  string          `json:"state"`
		Mode   model.GuardMode `json:"mode"`
		Reason string          `json:"reason"`
	}
	writeJSON(w, http.StatusOK, struct {
		Guard guardJSON `json:"guard"`
	}{guardJSON{st.State, st.Mode, st.Reason}})
}
