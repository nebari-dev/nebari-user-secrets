// Package store persists owner records and per-app delivery status as
// Kubernetes Secrets.
package store

import (
	"context"
	"errors"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

var (
	// ErrNotFound is returned when the owner has no record.
	ErrNotFound = errors.New("not_found")
	// ErrConflict is returned when a write lost an optimistic-concurrency race,
	// or a create found the record already present.
	ErrConflict = errors.New("conflict")
	// ErrOwnerMismatch is returned when the record stored under a sub's Secret
	// name names a different owner.
	ErrOwnerMismatch = errors.New("owner_mismatch")
	// ErrRecordTooLarge is returned when the encoded record exceeds MaxRecordBytes.
	ErrRecordTooLarge = errors.New("record_too_large")
)

// MaxRecordBytes is the largest encoded record.json the store will write.
const MaxRecordBytes = 524288

// SecretStore persists owner records and delivery status.
type SecretStore interface {
	// Get returns the owner's record and its resourceVersion.
	Get(ctx context.Context, ownerSub string) (*model.OwnerRecord, string, error)
	// Put writes rec; expectedVersion "" means create. It returns the new resourceVersion.
	Put(ctx context.Context, rec *model.OwnerRecord, expectedVersion string) (string, error)
	Delete(ctx context.Context, ownerSub string) error
	// RecordDelivery is rate-limited per app (a skipped call returns nil) and
	// returns a failed write's error; callers log it and never fail a resolve.
	RecordDelivery(ctx context.Context, ownerSub string, s model.DeliveryStatus) error
	Deliveries(ctx context.Context, ownerSub string) ([]model.DeliveryStatus, error)
	// AnyRecords reports whether any owner record exists.
	AnyRecords(ctx context.Context) (bool, error)
	// ListOwners returns the ownerSub of every record, as read from the records.
	ListOwners(ctx context.Context) ([]string, error)
}
