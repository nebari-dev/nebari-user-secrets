package service

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"github.com/nebari-dev/nebari-user-secrets/internal/store"
)

// resolvedEntry is one delivery: a record entry and the name it is delivered as.
type resolvedEntry struct {
	env   string
	entry model.SecretEntry
}

// Resolve returns the secrets of c's principal that have a binding for c's
// app, each under its delivered name NEBARI_SECRET_<suffix>, sorted by name.
// A stored binding whose suffix fails ^[A-Z][A-Z0-9_]{0,63}$ is skipped, so
// nothing is ever returned unprefixed or under a malformed name. An owner with no record gets
// an empty list. If any value fails to decrypt, or the record names another
// owner, nothing is returned: the error is crypto.ErrDecrypt and one key_event
// decrypt_failed is emitted (detail: the secret name, or owner_mismatch). A master
// key that is not loaded gives crypto.ErrKEKUnavailable. Each returned secret
// emits one secret_read audit line carrying g.
func (s *SecretService) Resolve(ctx context.Context, c model.PodClaim, g model.GuardMode) ([]model.ResolvedSecret, error) {
	ctx, sp := span(ctx, "Resolve")
	defer sp.End()
	owner := c.Principal.Sub
	rec, _, err := s.store.Get(ctx, owner)
	if errors.Is(err, store.ErrNotFound) {
		return []model.ResolvedSecret{}, nil
	}
	// A record naming another owner is tampered or colliding: like one that
	// does not open under its own owner's key, it is a decrypt failure.
	if errors.Is(err, store.ErrOwnerMismatch) || (err == nil && rec.OwnerSub != owner) {
		s.audit.KeyEvent(ctx, "decrypt_failed", owner, "", "owner_mismatch")
		sp.RecordError(crypto.ErrDecrypt)
		return nil, crypto.ErrDecrypt
	}
	if err != nil {
		sp.RecordError(err)
		return nil, err
	}

	var picked []resolvedEntry
	for _, e := range rec.Secrets {
		for _, b := range e.Bindings {
			if b.App != c.App {
				continue
			}
			if model.ValidSuffix(b.Env) {
				picked = append(picked, resolvedEntry{env: model.DeliveredName(b.Env), entry: e})
			}
		}
	}
	slices.SortFunc(picked, func(a, b resolvedEntry) int { return strings.Compare(a.env, b.env) })

	out := make([]model.ResolvedSecret, 0, len(picked))
	for _, p := range picked {
		v, err := s.sealer.Open(ctx, rec, p.entry)
		if err != nil {
			for _, r := range out {
				clear(r.Value)
			}
			if errors.Is(err, crypto.ErrKEKUnavailable) {
				sp.RecordError(err)
				return nil, err
			}
			s.audit.KeyEvent(ctx, "decrypt_failed", owner, "", p.entry.Name)
			sp.RecordError(crypto.ErrDecrypt)
			return nil, crypto.ErrDecrypt
		}
		out = append(out, model.ResolvedSecret{Env: p.env, Value: v})
	}
	for _, p := range picked {
		s.audit.SecretRead(ctx, rec.OwnerSub, owner, p.entry.Name, c, g)
	}
	return out, nil
}

// RecordDelivery stores the outcome of a resolve for c's principal and app:
// reason "" is a success delivering count secrets, anything else a failure
// with that reason. The store rate-limits writes; a write error is returned so
// the caller can log it, and it never changes the resolve response.
func (s *SecretService) RecordDelivery(ctx context.Context, c model.PodClaim, count int, reason string) error {
	ctx, sp := span(ctx, "RecordDelivery")
	defer sp.End()
	d := model.DeliveryStatus{App: c.App}
	if reason == "" {
		d.LastOK, d.LastCount = s.now(), count
	} else {
		d.LastFailure, d.LastReason = s.now(), reason
	}
	if err := s.store.RecordDelivery(ctx, c.Principal.Sub, d); err != nil {
		sp.RecordError(err)
		return err
	}
	return nil
}
