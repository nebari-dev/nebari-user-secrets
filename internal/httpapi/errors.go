package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"github.com/nebari-dev/nebari-user-secrets/internal/service"
)

// writeJSON writes v as the response body. Every management response is
// uncacheable: bodies describe one user's secrets.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes an APIError with only a code: Detail is never set, so no
// input can be echoed back.
func writeError(w http.ResponseWriter, status int, code string) {
	if rec, ok := w.(*statusRecorder); ok {
		rec.code = code
	}
	writeJSON(w, status, model.APIError{Error: code})
}

// serviceErrors maps service sentinel errors to their status and code.
var serviceErrors = []struct {
	err    error
	status int
	code   string
}{
	{service.ErrInvalidName, http.StatusBadRequest, "invalid_name"},
	{service.ErrInvalidSuffix, http.StatusBadRequest, "invalid_suffix"},
	{service.ErrUnknownApp, http.StatusBadRequest, "unknown_app"},
	{service.ErrGrantsNotSupported, http.StatusBadRequest, "grants_not_supported"},
	{service.ErrLimitExceeded, http.StatusBadRequest, "limit_exceeded"},
	{service.ErrValueRequired, http.StatusBadRequest, "value_required"},
	{service.ErrNotFound, http.StatusNotFound, "not_found"},
	{service.ErrEnvConflict, http.StatusConflict, "env_conflict"},
	{crypto.ErrKEKUnavailable, http.StatusServiceUnavailable, "kek_unavailable"},
}

// statusFor returns the HTTP status and code for an error from the service.
// Anything unrecognised is reported as an unavailable Kubernetes API, never
// with the error's text.
func statusFor(err error) (int, string) {
	for _, m := range serviceErrors {
		if errors.Is(err, m.err) {
			return m.status, m.code
		}
	}
	return http.StatusServiceUnavailable, "kubernetes_unavailable"
}
