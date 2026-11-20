// Package audit emits the service's audit lines. The methods are leaf logging
// calls, so they take a context for the logger but start no spans. No method
// accepts a secret value, token or data key, so none can be logged.
package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

// AuditSink receives one call per auditable event.
type AuditSink interface {
	SecretRead(ctx context.Context, ownerSub, readerSub, secret string, c model.PodClaim, g model.GuardMode)
	ResolveDenied(ctx context.Context, pod model.PodIdentity, reason string)
	SecretWrite(ctx context.Context, ownerSub, actorSub, secret, action string)
	GuardChanged(ctx context.Context, state, mode, reason string)
	KeyEvent(ctx context.Context, event, ownerSub, actor, detail string)
}

// SlogAuditSink writes audit lines through an slog.Logger at Info level.
type SlogAuditSink struct{ l *slog.Logger }

var _ AuditSink = (*SlogAuditSink)(nil)

func NewSlogAuditSink(l *slog.Logger) *SlogAuditSink { return &SlogAuditSink{l: l} }

func (s *SlogAuditSink) emit(ctx context.Context, event string, attrs ...slog.Attr) {
	all := append([]slog.Attr{
		slog.Bool("audit", true),
		slog.String("event", event),
		slog.String("ts", time.Now().UTC().Format(time.RFC3339Nano)),
	}, attrs...)
	s.l.LogAttrs(ctx, slog.LevelInfo, "audit", all...)
}

func podName(p model.PodIdentity) string { return p.Namespace + "/" + p.Name }

func (s *SlogAuditSink) SecretRead(ctx context.Context, ownerSub, readerSub, secret string, c model.PodClaim, g model.GuardMode) {
	s.emit(ctx, "secret_read",
		slog.String("owner_sub", ownerSub),
		slog.String("reader_sub", readerSub),
		slog.String("secret", secret),
		slog.String("app", string(c.App)),
		slog.String("pod", podName(c.Pod)),
		slog.String("pod_uid", c.Pod.UID),
		slog.String("sa", c.Pod.ServiceAccount),
		slog.String("guard", string(g)),
	)
}

func (s *SlogAuditSink) ResolveDenied(ctx context.Context, pod model.PodIdentity, reason string) {
	s.emit(ctx, "resolve_denied",
		slog.String("pod", podName(pod)),
		slog.String("pod_uid", pod.UID),
		slog.String("sa", pod.ServiceAccount),
		slog.String("reason", reason),
	)
}

func (s *SlogAuditSink) SecretWrite(ctx context.Context, ownerSub, actorSub, secret, action string) {
	s.emit(ctx, "secret_write",
		slog.String("owner_sub", ownerSub),
		slog.String("actor_sub", actorSub),
		slog.String("secret", secret),
		slog.String("action", action),
	)
}

func (s *SlogAuditSink) GuardChanged(ctx context.Context, state, mode, reason string) {
	s.emit(ctx, "guard_state",
		slog.String("state", state),
		slog.String("mode", mode),
		slog.String("reason", reason),
	)
}

func (s *SlogAuditSink) KeyEvent(ctx context.Context, event, ownerSub, actor, detail string) {
	s.emit(ctx, "key_event",
		slog.String("key_event", event),
		slog.String("owner_sub", ownerSub),
		slog.String("actor", actor),
		slog.String("detail", detail),
	)
}
