package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

func newSink(buf *bytes.Buffer) *SlogAuditSink {
	return NewSlogAuditSink(slog.New(slog.NewJSONHandler(buf, nil)))
}

func decode(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want exactly one line, got %d: %q", len(lines), buf.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("line is not JSON: %v", err)
	}
	return m
}

var claim = model.PodClaim{
	Pod:       model.PodIdentity{Namespace: "ns1", Name: "nb-0", UID: "uid-1", ServiceAccount: "sa1"},
	App:       "notebook",
	Principal: model.Principal{Kind: "user", Sub: "reader-sub"},
}

var calls = []struct {
	name string
	call func(*SlogAuditSink)
	want map[string]any
}{
	{"secret_read", func(s *SlogAuditSink) {
		s.SecretRead(context.Background(), "owner-sub", "reader-sub", "API_KEY", claim, model.GuardMode("enforced"))
	}, map[string]any{
		"event": "secret_read", "audit": true, "owner_sub": "owner-sub", "reader_sub": "reader-sub",
		"secret": "API_KEY", "app": "notebook", "pod": "ns1/nb-0", "pod_uid": "uid-1", "sa": "sa1", "guard": "enforced",
	}},
	{"secret_read_overridden", func(s *SlogAuditSink) {
		s.SecretRead(context.Background(), "o", "r", "X", claim, model.GuardMode("overridden"))
	}, map[string]any{"event": "secret_read", "guard": "overridden"}},
	{"resolve_denied", func(s *SlogAuditSink) {
		s.ResolveDenied(context.Background(), claim.Pod, "uid_mismatch")
	}, map[string]any{
		"event": "resolve_denied", "audit": true, "pod": "ns1/nb-0", "pod_uid": "uid-1", "sa": "sa1", "reason": "uid_mismatch",
	}},
	{"secret_write", func(s *SlogAuditSink) {
		s.SecretWrite(context.Background(), "owner-sub", "actor-sub", "API_KEY", "upsert")
	}, map[string]any{
		"event": "secret_write", "audit": true, "owner_sub": "owner-sub", "actor_sub": "actor-sub", "secret": "API_KEY", "action": "upsert",
	}},
	{"guard_state", func(s *SlogAuditSink) {
		s.GuardChanged(context.Background(), "confirmed_bad", "enforced", "probe admitted")
	}, map[string]any{
		"event": "guard_state", "audit": true, "state": "confirmed_bad", "mode": "enforced", "reason": "probe admitted",
	}},
	{"key_event", func(s *SlogAuditSink) {
		s.KeyEvent(context.Background(), "kek_rotated", "owner-sub", "admin", "records=3")
	}, map[string]any{
		"event": "key_event", "audit": true, "key_event": "kek_rotated", "owner_sub": "owner-sub", "actor": "admin", "detail": "records=3",
	}},
}

func TestAuditLines(t *testing.T) {
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			tc.call(newSink(&buf))
			m := decode(t, &buf)
			for k, v := range tc.want {
				if m[k] != v {
					t.Errorf("%s = %v, want %v", k, m[k], v)
				}
			}
			ts, ok := m["ts"].(string)
			if !ok {
				t.Fatalf("ts missing: %v", m)
			}
			parsed, err := time.Parse(time.RFC3339Nano, ts)
			if err != nil || !strings.HasSuffix(ts, "Z") {
				t.Errorf("ts %q is not RFC 3339 UTC (%v)", ts, err)
			}
			if time.Since(parsed) > time.Minute {
				t.Errorf("ts %q is not current", ts)
			}
		})
	}
}

func TestAuditNeverLogsSecrets(t *testing.T) {
	forbidden := []string{"value", "token", "data_key"}
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			tc.call(newSink(&buf))
			m := decode(t, &buf)
			if len(m) < 5 {
				t.Fatalf("line suspiciously small, test would be vacuous: %v", m)
			}
			for _, k := range forbidden {
				if _, found := m[k]; found {
					t.Errorf("line has forbidden key %q: %v", k, m)
				}
			}
		})
	}
}
