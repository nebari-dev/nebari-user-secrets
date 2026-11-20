// Package service holds the business logic behind the management and resolve
// APIs.
package service

import (
	"context"
	"errors"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/internal/audit"
	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"github.com/nebari-dev/nebari-user-secrets/internal/registry"
	"github.com/nebari-dev/nebari-user-secrets/internal/store"
)

// Typed errors the management API maps to response codes.
var (
	ErrInvalidName        = errors.New("invalid_name")
	ErrInvalidSuffix      = errors.New("invalid_suffix")
	ErrUnknownApp         = errors.New("unknown_app")
	ErrLimitExceeded      = errors.New("limit_exceeded")
	ErrNotFound           = errors.New("not_found")
	ErrEnvConflict        = errors.New("env_conflict")
	ErrValueRequired      = errors.New("value_required")
	ErrGrantsNotSupported = errors.New("grants_not_supported")
)

// Limits bounds what one user may store.
type Limits struct {
	MaxSecrets     int // secrets per user
	MaxValueBytes  int // plaintext bytes per value
	MaxRecordBytes int // encoded record.json bytes
}

// DefaultLimits returns the limits from the spec.
func DefaultLimits() Limits {
	return Limits{MaxSecrets: 50, MaxValueBytes: 32768, MaxRecordBytes: store.MaxRecordBytes}
}

// Sealer is the part of *crypto.Sealer the service uses.
type Sealer interface {
	NewDataKey(ctx context.Context, ownerSub string) (model.WrappedKey, error)
	Seal(ctx context.Context, rec *model.OwnerRecord, name string, value []byte) ([]byte, error)
	Open(ctx context.Context, rec *model.OwnerRecord, e model.SecretEntry) ([]byte, error)
}

// AppLister names the registered apps.
type AppLister interface{ Apps() []model.AppID }

var (
	_ Sealer    = (*crypto.Sealer)(nil)
	_ AppLister = (*registry.Registry)(nil)
)

// SecretService implements the user-facing secret operations.
type SecretService struct {
	store  store.SecretStore
	sealer Sealer
	audit  audit.AuditSink
	apps   AppLister
	limits Limits
	now    func() time.Time
}

// NewSecretService returns a SecretService. now supplies timestamps.
func NewSecretService(s store.SecretStore, c Sealer, a audit.AuditSink, apps AppLister, l Limits, now func() time.Time) *SecretService {
	return &SecretService{store: s, sealer: c, audit: a, apps: apps, limits: l, now: now}
}
