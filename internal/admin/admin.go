// Package admin implements the master-key and data-key rotation commands that
// admins run as one-off Jobs. No function here logs, and none puts a value, a
// data key or a master key in an error or an audit detail.
package admin

import (
	"context"
	"errors"
	"fmt"

	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"github.com/nebari-dev/nebari-user-secrets/internal/store"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// maxConflictTries bounds the Get/modify/Put loop per record.
const maxConflictTries = 5

// Store is the part of store.SecretStore the admin commands use.
type Store interface {
	Get(ctx context.Context, ownerSub string) (*model.OwnerRecord, string, error)
	Put(ctx context.Context, rec *model.OwnerRecord, expectedVersion string) (string, error)
	ListOwners(ctx context.Context) ([]string, error)
}

// KEK is the part of *crypto.KubernetesKEK the admin commands use.
type KEK interface {
	AddKey(ctx context.Context) (string, error)
	Retire(ctx context.Context, id string, inUse func(ctx context.Context) (map[string]int, error)) error
	PrimaryID(ctx context.Context) (string, error)
}

var _ KEK = (*crypto.KubernetesKEK)(nil)

// Report summarizes a command. Rewrapped is the number of records the command
// changed; ByKEK counts records per master key id, read back after the pass.
type Report struct {
	Rewrapped int
	ByKEK     map[string]int
}

func span(ctx context.Context, fn string) (context.Context, trace.Span) {
	return otel.Tracer("nebari-user-secrets").Start(ctx, "admin."+fn)
}

// updateRecord applies fn to owner's record with resourceVersion concurrency.
// On ErrConflict it re-reads and re-applies fn, up to maxConflictTries times.
// fn returns false when the record needs no write.
func updateRecord(ctx context.Context, s Store, owner string, fn func(rec *model.OwnerRecord) (bool, error)) (bool, error) {
	for range maxConflictTries {
		rec, version, err := s.Get(ctx, owner)
		if err != nil {
			return false, err
		}
		changed, err := fn(rec)
		if err != nil || !changed {
			return false, err
		}
		if _, err := s.Put(ctx, rec, version); err != nil {
			if errors.Is(err, store.ErrConflict) {
				continue
			}
			return false, err
		}
		return true, nil
	}
	return false, store.ErrConflict
}

// countByKEK counts records per master key id.
func countByKEK(ctx context.Context, s Store) (map[string]int, error) {
	owners, err := s.ListOwners(ctx)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, o := range owners {
		rec, _, err := s.Get(ctx, o)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		counts[rec.DataKey.KEKID]++
	}
	return counts, nil
}

// RotateKEK adds a master key, makes it primary and rewraps every record's
// data key under it. It fails the whole command if any record cannot be
// rewrapped, naming how many were done.
func RotateKEK(ctx context.Context, s Store, k KEK, seal *crypto.Sealer, a crypto.KeyAuditor, actor string) (Report, error) {
	ctx, sp := span(ctx, "RotateKEK")
	defer sp.End()

	id, err := k.AddKey(ctx)
	if err != nil {
		sp.RecordError(err)
		return Report{}, fmt.Errorf("add master key: %w", err)
	}
	a.KeyEvent(ctx, "kek_created", "", actor, id)
	if primary, err := k.PrimaryID(ctx); err != nil || primary != id {
		if err == nil {
			err = errors.New("primary changed concurrently")
		}
		sp.RecordError(err)
		return Report{}, fmt.Errorf("new master key %s is not primary: %w", id, err)
	}

	owners, err := s.ListOwners(ctx)
	if err != nil {
		sp.RecordError(err)
		return Report{}, fmt.Errorf("list owners: %w", err)
	}
	rewrapped := 0
	for i, o := range owners {
		changed, err := updateRecord(ctx, s, o, func(rec *model.OwnerRecord) (bool, error) {
			return seal.Rewrap(ctx, rec)
		})
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			sp.RecordError(err)
			return Report{Rewrapped: rewrapped}, fmt.Errorf("rewrap failed after %d of %d owners: %w", i, len(owners), err)
		}
		if changed {
			rewrapped++
		}
	}
	by, err := countByKEK(ctx, s)
	if err != nil {
		sp.RecordError(err)
		return Report{Rewrapped: rewrapped}, fmt.Errorf("count key usage: %w", err)
	}
	a.KeyEvent(ctx, "kek_rotated", "", actor, fmt.Sprintf("%s rewrapped=%d", id, rewrapped))
	return Report{Rewrapped: rewrapped, ByKEK: by}, nil
}

// RetireKEK removes master key id. It refuses while any record uses it.
func RetireKEK(ctx context.Context, s Store, k KEK, id string) error {
	ctx, sp := span(ctx, "RetireKEK")
	defer sp.End()
	err := k.Retire(ctx, id, func(ctx context.Context) (map[string]int, error) {
		return countByKEK(ctx, s)
	})
	if err != nil {
		sp.RecordError(err)
	}
	return err
}

// reseal replaces rec's data key and re-encrypts every value under it. rec is
// left unmodified unless every value was re-sealed.
func reseal(ctx context.Context, seal *crypto.Sealer, rec *model.OwnerRecord) error {
	plain := make([][]byte, len(rec.Secrets))
	defer func() {
		for _, p := range plain {
			for i := range p {
				p[i] = 0
			}
		}
	}()
	for i, e := range rec.Secrets {
		p, err := seal.Open(ctx, rec, e)
		if err != nil {
			return fmt.Errorf("open secret %d of %d: %w", i+1, len(rec.Secrets), err)
		}
		plain[i] = p
	}
	next := *rec
	dk, err := seal.NewDataKey(ctx, rec.OwnerSub)
	if err != nil {
		return fmt.Errorf("new data key: %w", err)
	}
	next.DataKey = dk
	sealed := make([][]byte, len(plain))
	for i, p := range plain {
		sealed[i], err = seal.Seal(ctx, &next, rec.Secrets[i].Name, p)
		if err != nil {
			return fmt.Errorf("seal secret %d of %d: %w", i+1, len(plain), err)
		}
	}
	entries := make([]model.SecretEntry, len(rec.Secrets))
	copy(entries, rec.Secrets)
	for i := range entries {
		entries[i].Sealed = sealed[i]
	}
	rec.DataKey = dk
	rec.Secrets = entries
	return nil
}

// RotateDEK replaces the data key of one owner, or of every owner when owner
// is empty, and re-encrypts all of that owner's values under the new key.
func RotateDEK(ctx context.Context, s Store, seal *crypto.Sealer, a crypto.KeyAuditor, actor, owner string) (Report, error) {
	ctx, sp := span(ctx, "RotateDEK")
	defer sp.End()

	owners := []string{owner}
	if owner == "" {
		var err error
		if owners, err = s.ListOwners(ctx); err != nil {
			sp.RecordError(err)
			return Report{}, fmt.Errorf("list owners: %w", err)
		}
	}
	rotated := 0
	for i, o := range owners {
		_, err := updateRecord(ctx, s, o, func(rec *model.OwnerRecord) (bool, error) {
			return true, reseal(ctx, seal, rec)
		})
		if errors.Is(err, store.ErrNotFound) {
			if owner == "" {
				continue
			}
			return Report{}, fmt.Errorf("owner %s: %w", owner, err)
		}
		if err != nil {
			sp.RecordError(err)
			return Report{Rewrapped: rotated}, fmt.Errorf("rotate data key failed after %d of %d owners: %w", i, len(owners), err)
		}
		rotated++
		a.KeyEvent(ctx, "dek_rotated", o, actor, "")
	}
	by, err := countByKEK(ctx, s)
	if err != nil {
		sp.RecordError(err)
		return Report{Rewrapped: rotated}, fmt.Errorf("count key usage: %w", err)
	}
	return Report{Rewrapped: rotated, ByKEK: by}, nil
}
