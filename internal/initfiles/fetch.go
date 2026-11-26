package initfiles

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

const (
	firstBackoff = 500 * time.Millisecond
	maxBackoff   = 5 * time.Second
	maxDetail    = 200
	// maxStatus bounds a whole .status line ("error <code> <detail>").
	maxStatus = 200
)

// ResolveClient calls the resolve API with a projected ServiceAccount token.
type ResolveClient interface {
	Resolve(ctx context.Context, token string) ([]model.ResolvedSecret, error)
}

// clock is the time source for backoff, so tests do not sleep.
type clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// retryPolicy is the backoff schedule: first wait, doubling, capped at max.
type retryPolicy struct{ first, max time.Duration }

var defaultRetry = retryPolicy{first: firstBackoff, max: maxBackoff}

// Fetch resolves the pod's secrets and delivers them through w, then writes
// .status and returns its text: "ok <count>" or "error <code> <detail>".
//
// It reads the token from tokenPath on every attempt (kubelet rotates it).
// A 503 or a network error is retried with exponential backoff (500 ms,
// doubling, capped at 5 s) while the next attempt can still start within
// budget; any other answer is final. When retries run out the status keeps
// the last answer the server gave, if any.
//
// Delivery is all or nothing: every failure, including a 200 with an entry
// that is not valid, goes through w.Fail, so a rerun never leaves old values.
// No status, error or span attribute carries a token or a value.
func Fetch(ctx context.Context, c ResolveClient, tokenPath string, w *FileWriter, budget time.Duration) (string, bool) {
	ctx, span := otel.Tracer("nebari-user-secrets").Start(ctx, "initfiles.Fetch")
	defer span.End()
	status, ok := fetch(ctx, c, tokenPath, w, budget, realClock{}, defaultRetry)
	code := statusCode(status)
	span.SetAttributes(attribute.String("initfiles.status_code", code))
	if !ok {
		span.SetStatus(codes.Error, code)
	}
	return status, ok
}

// statusCode is "ok" or the <code> of an "error <code> <detail>" status.
func statusCode(status string) string {
	f := strings.Fields(status)
	if len(f) >= 2 && f[0] == "error" {
		return f[1]
	}
	return "ok"
}

func fetch(ctx context.Context, c ResolveClient, tokenPath string, w *FileWriter, budget time.Duration,
	clk clock, rp retryPolicy) (string, bool) {
	status, ok := resolveAndWrite(ctx, c, tokenPath, w, budget, clk, rp)
	if ok {
		err := w.WriteStatus(status)
		if err == nil {
			return status, true
		}
		// Without a status the delivery counts as failed.
		status = failure("write_failed", "status: "+oneLine(err.Error()))
	}
	if err := w.Fail(status); err != nil {
		return failure("write_failed", oneLine(err.Error())), false
	}
	return status, false
}

// lastAnswer is the most recent transient failure, kept for the final status.
type lastAnswer struct {
	code, detail string
	fromServer   bool
}

func resolveAndWrite(ctx context.Context, c ResolveClient, tokenPath string, w *FileWriter, budget time.Duration,
	clk clock, rp retryPolicy) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	deadline := clk.Now().Add(budget)
	backoff := rp.first
	var last lastAnswer
	for attempt := 1; ; attempt++ {
		token, code, err := readToken(tokenPath)
		if err != nil {
			return failure(code, oneLine(err.Error())), false
		}
		secrets, err := c.Resolve(ctx, token)
		if err == nil {
			return deliver(w, secrets)
		}
		code, detail, transient := classify(err)
		if !transient {
			return failure(code, detail), false
		}
		// A failure caused by the spent budget must not hide what the
		// server said on an earlier attempt.
		if ctx.Err() == nil || !last.fromServer {
			var apiErr *APIError
			last = lastAnswer{code: code, detail: detail, fromServer: errors.As(err, &apiErr)}
		}
		// Start another attempt only if it can begin before the budget ends.
		if ctx.Err() != nil || !clk.Now().Add(backoff).Before(deadline) || clk.Sleep(ctx, backoff) != nil {
			return failureAfter(last.code, last.detail, attempt), false
		}
		backoff = min(2*backoff, rp.max)
	}
}

// deliver writes a 200's secrets. An entry with a name outside the delivered
// name rule fails the whole delivery before anything is written.
func deliver(w *FileWriter, secrets []model.ResolvedSecret) (string, bool) {
	for i, s := range secrets {
		if !model.ValidDeliveredName(s.Env) {
			return failure("invalid_response", fmt.Sprintf("secret %d: invalid delivered name", i)), false
		}
	}
	if err := w.WriteAll(secrets); err != nil {
		return failure("write_failed", oneLine(err.Error())), false
	}
	return fmt.Sprintf("ok %d", len(secrets)), true
}

// Fail records a failed delivery: it removes every NEBARI_SECRET_* file and
// every leftover .tmp-* file (a write killed before its rename) in the
// directory, so no earlier value survives, then writes status to .status. The
// status is written even when a removal fails. It returns the first error.
func (w *FileWriter) Fail(status string) error {
	clearErr := w.clearSecrets()
	statusErr := w.WriteStatus(status)
	if clearErr != nil {
		return fmt.Errorf("secret files not removed: %w", clearErr)
	}
	return statusErr
}

func (w *FileWriter) clearSecrets() error {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), namePrefix) && !strings.HasPrefix(e.Name(), tempPrefix) {
			continue
		}
		if err := os.Remove(filepath.Join(w.dir, e.Name())); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// readToken returns the trimmed token, or a status code and an error that
// never quotes the token.
func readToken(path string) (token, code string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "token_missing", err
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", "token_missing", fmt.Errorf("%s is empty", path)
	}
	for i := 0; i < len(t); i++ {
		if t[i] < 0x20 || t[i] == 0x7f {
			return "", "token_invalid", fmt.Errorf("%s holds a control byte", path)
		}
	}
	return t, "", nil
}

// classify maps a Resolve error to a status code and detail, and says whether
// it is worth retrying: 503s and network errors are; other answers are not.
func classify(err error) (code, detail string, transient bool) {
	var apiErr *APIError
	switch {
	case errors.As(err, &apiErr):
		return apiErr.Code, fmt.Sprintf("http %d", apiErr.Status), apiErr.Status == http.StatusServiceUnavailable
	case errors.Is(err, errInvalidResponse):
		return "invalid_response", oneLine(err.Error()), false
	case errors.Is(err, errBadResponse), errors.Is(err, ErrBadURL):
		return "bad_response", oneLine(err.Error()), false
	default:
		return "unreachable", oneLine(err.Error()), true
	}
}

// oneLine collapses whitespace in an error message and bounds its length.
func oneLine(s string) string {
	return cut(strings.Join(strings.Fields(s), " "), maxDetail)
}

// FailureStatus formats an error status for a failure found outside Fetch:
// the detail is collapsed to one line, and the status bounded like Fetch's.
func FailureStatus(code, detail string) string { return failure(code, oneLine(detail)) }

// failure formats an error status. The detail is never empty, so the status
// always has the "error <code> <detail>" shape, and it is cut so the whole
// line is at most maxStatus bytes; the code is never cut.
func failure(code, detail string) string { return failureSuffix(code, detail, "") }

// failureAfter is failure for a retried failure: the detail ends
// "after <n> attempts", and only the part before that is cut.
func failureAfter(code, detail string, attempts int) string {
	return failureSuffix(code, detail, fmt.Sprintf(" after %d attempts", attempts))
}

func failureSuffix(code, detail, suffix string) string {
	if detail == "" {
		detail = "-"
	}
	prefix := "error " + code + " "
	return prefix + cut(detail, max(maxStatus-len(prefix)-len(suffix), 1)) + suffix
}

// cut returns at most n bytes of s, never splitting a UTF-8 sequence.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
