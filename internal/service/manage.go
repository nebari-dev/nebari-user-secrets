package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"github.com/nebari-dev/nebari-user-secrets/internal/store"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

const (
	maxAttempts  = 5
	deliveryRoot = "/var/run/nebari/secrets/"
)

// UpsertInput describes a create, rotate or rebind. A nil Value keeps the
// stored value. Bindings replace the secret's bindings.
type UpsertInput struct {
	Name        string
	Description string
	Value       []byte
	Bindings    []model.Binding
	Grants      []model.Grant // rejected in the MVP
}

func span(ctx context.Context, name string) (context.Context, trace.Span) {
	return otel.Tracer("nebari-user-secrets").Start(ctx, "service.SecretService."+name)
}

func viewOf(e model.SecretEntry) model.SecretSummary {
	bs := make([]model.BindingView, 0, len(e.Bindings))
	for _, b := range e.Bindings {
		n := model.DeliveredName(b.Env)
		bs = append(bs, model.BindingView{App: b.App, Env: b.Env, Name: n, Path: deliveryRoot + n})
	}
	return model.SecretSummary{Name: e.Name, Description: e.Description, Bindings: bs, UpdatedAt: e.UpdatedAt}
}

func encodedSize(rec *model.OwnerRecord) (int, error) {
	b, err := json.Marshal(rec)
	if err != nil {
		return 0, fmt.Errorf("encode record: %w", err)
	}
	return len(b), nil
}

// ListForOwner returns the owner's secrets without values, delivery status and
// usage. An owner with no record gets an empty view.
func (s *SecretService) ListForOwner(ctx context.Context, u model.Principal) (model.OwnerView, error) {
	ctx, sp := span(ctx, "ListForOwner")
	defer sp.End()
	view := model.OwnerView{Secrets: []model.SecretSummary{}, Deliveries: []model.DeliveryStatus{}}
	view.Usage = model.Usage{MaxCount: s.limits.MaxSecrets, MaxBytes: s.limits.MaxRecordBytes}
	rec, _, err := s.store.Get(ctx, u.Sub)
	if errors.Is(err, store.ErrNotFound) {
		return view, nil
	}
	if err != nil {
		sp.RecordError(err)
		return model.OwnerView{}, err
	}
	for _, e := range rec.Secrets {
		view.Secrets = append(view.Secrets, viewOf(e))
	}
	slices.SortFunc(view.Secrets, func(a, b model.SecretSummary) int { return strings.Compare(a.Name, b.Name) })
	ds, err := s.store.Deliveries(ctx, u.Sub)
	if err != nil {
		sp.RecordError(err)
		return model.OwnerView{}, err
	}
	if ds != nil {
		view.Deliveries = ds
	}
	view.Usage.Count = len(rec.Secrets)
	if view.Usage.Bytes, err = encodedSize(rec); err != nil {
		sp.RecordError(err)
		return model.OwnerView{}, err
	}
	return view, nil
}

func (s *SecretService) validate(in UpsertInput) error {
	if !model.ValidSecretName(in.Name) {
		return ErrInvalidName
	}
	if len(in.Grants) > 0 {
		return ErrGrantsNotSupported
	}
	if len(in.Value) > s.limits.MaxValueBytes {
		return fmt.Errorf("%w: value exceeds %d bytes", ErrLimitExceeded, s.limits.MaxValueBytes)
	}
	apps := s.apps.Apps()
	seen := map[model.Binding]bool{}
	for _, b := range in.Bindings {
		if !model.ValidSuffix(b.Env) {
			return ErrInvalidSuffix
		}
		if !slices.Contains(apps, b.App) {
			return ErrUnknownApp
		}
		if seen[b] {
			return ErrEnvConflict
		}
		seen[b] = true
	}
	return nil
}

// Upsert creates or replaces a secret and reports whether it was created.
// Each attempt re-reads the record and applies in from scratch, so a lost
// race never reuses state from a failed attempt.
func (s *SecretService) Upsert(ctx context.Context, u model.Principal, in UpsertInput) (model.SecretSummary, bool, error) {
	ctx, sp := span(ctx, "Upsert")
	defer sp.End()
	if err := s.validate(in); err != nil {
		sp.RecordError(err)
		return model.SecretSummary{}, false, err
	}
	for range maxAttempts {
		sum, created, rotated, err := s.upsertOnce(ctx, u, in)
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		if err != nil {
			sp.RecordError(err)
			return model.SecretSummary{}, false, err
		}
		action := "update"
		switch {
		case created:
			action = "create"
		case rotated:
			action = "rotate"
		}
		s.audit.SecretWrite(ctx, u.Sub, u.Sub, in.Name, action)
		return sum, created, nil
	}
	err := fmt.Errorf("upsert: too many concurrent changes: %w", store.ErrConflict)
	sp.RecordError(err)
	return model.SecretSummary{}, false, err
}

func (s *SecretService) upsertOnce(ctx context.Context, u model.Principal, in UpsertInput) (sum model.SecretSummary, created, rotated bool, err error) {
	rec, version, err := s.store.Get(ctx, u.Sub)
	switch {
	case errors.Is(err, store.ErrNotFound):
		dk, kerr := s.sealer.NewDataKey(ctx, u.Sub)
		if kerr != nil {
			return sum, false, false, kerr
		}
		rec = &model.OwnerRecord{SchemaVersion: 1, OwnerSub: u.Sub, OwnerUsername: u.Username, DataKey: dk}
		version = ""
	case err != nil:
		return sum, false, false, err
	}

	idx := slices.IndexFunc(rec.Secrets, func(e model.SecretEntry) bool { return e.Name == in.Name })
	created = idx < 0
	if created && in.Value == nil {
		return sum, false, false, ErrValueRequired
	}
	if created && len(rec.Secrets) >= s.limits.MaxSecrets {
		return sum, false, false, fmt.Errorf("%w: at most %d secrets", ErrLimitExceeded, s.limits.MaxSecrets)
	}
	for i, e := range rec.Secrets {
		if i == idx {
			continue
		}
		for _, have := range e.Bindings {
			for _, want := range in.Bindings {
				if have == want {
					return sum, false, false, ErrEnvConflict
				}
			}
		}
	}

	now := s.now()
	entry := model.SecretEntry{Name: in.Name, CreatedAt: now}
	if !created {
		entry = rec.Secrets[idx]
	}
	entry.Description = in.Description
	entry.Bindings = slices.Clone(in.Bindings)
	entry.UpdatedAt = now
	if in.Value != nil {
		if entry.Sealed, err = s.sealer.Seal(ctx, rec, in.Name, in.Value); err != nil {
			return sum, false, false, err
		}
		rotated = !created
	}
	if created {
		rec.Secrets = append(rec.Secrets, entry)
	} else {
		rec.Secrets[idx] = entry
	}

	size, err := encodedSize(rec)
	if err != nil {
		return sum, false, false, err
	}
	if size > s.limits.MaxRecordBytes {
		return sum, false, false, fmt.Errorf("%w: stored secrets would exceed %d bytes", ErrLimitExceeded, s.limits.MaxRecordBytes)
	}
	if _, err := s.store.Put(ctx, rec, version); err != nil {
		if errors.Is(err, store.ErrRecordTooLarge) {
			return sum, false, false, fmt.Errorf("%w: %v", ErrLimitExceeded, err)
		}
		return sum, false, false, err
	}
	return viewOf(entry), created, rotated, nil
}

// Delete removes one of the owner's secrets. The record, and its data key,
// stays when the last secret goes.
func (s *SecretService) Delete(ctx context.Context, u model.Principal, name string) error {
	ctx, sp := span(ctx, "Delete")
	defer sp.End()
	for range maxAttempts {
		err := s.deleteOnce(ctx, u, name)
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		if err != nil {
			sp.RecordError(err)
			return err
		}
		s.audit.SecretWrite(ctx, u.Sub, u.Sub, name, "delete")
		return nil
	}
	err := fmt.Errorf("delete: too many concurrent changes: %w", store.ErrConflict)
	sp.RecordError(err)
	return err
}

func (s *SecretService) deleteOnce(ctx context.Context, u model.Principal, name string) error {
	rec, version, err := s.store.Get(ctx, u.Sub)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	idx := slices.IndexFunc(rec.Secrets, func(e model.SecretEntry) bool { return e.Name == name })
	if idx < 0 {
		return ErrNotFound
	}
	rec.Secrets = slices.Delete(rec.Secrets, idx, idx+1)
	_, err = s.store.Put(ctx, rec, version)
	return err
}
