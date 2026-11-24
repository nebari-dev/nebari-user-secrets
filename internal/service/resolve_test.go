package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"github.com/nebari-dev/nebari-user-secrets/internal/store"
)

var bob = model.Principal{Kind: "user", Sub: "sub-bob", Username: "bob"}

func claimFor(sub, app string) model.PodClaim {
	return model.PodClaim{
		Pod:       model.PodIdentity{Namespace: "jupyterhub", Name: "jupyter-" + sub, UID: "uid-" + sub, ServiceAccount: "user-pod"},
		App:       model.AppID(app),
		Principal: model.Principal{Kind: "user", Sub: sub},
	}
}

// rawEntry is a record entry written straight to the store, bypassing the
// service's validation, as a corrupted or hand-edited record would be.
type rawEntry struct {
	name     string
	value    string
	bindings []model.Binding
}

// putRaw writes a record for sub holding entries, sealed with sub's own key.
func (e *env) putRaw(t *testing.T, sub string, entries ...rawEntry) *model.OwnerRecord {
	t.Helper()
	ctx := context.Background()
	dk, err := e.sealer.NewDataKey(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	rec := &model.OwnerRecord{SchemaVersion: 1, OwnerSub: sub, DataKey: dk}
	for _, re := range entries {
		sealed, err := e.sealer.Seal(ctx, rec, re.name, []byte(re.value))
		if err != nil {
			t.Fatal(err)
		}
		rec.Secrets = append(rec.Secrets, model.SecretEntry{Name: re.name, Sealed: sealed, Bindings: re.bindings})
	}
	if _, err := e.st.Put(ctx, rec, ""); err != nil {
		t.Fatal(err)
	}
	return rec
}

// replaceRecord overwrites sub's stored record with rec.
func (e *env) replaceRecord(t *testing.T, rec *model.OwnerRecord) {
	t.Helper()
	ctx := context.Background()
	_, v, err := e.st.Get(ctx, rec.OwnerSub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Put(ctx, rec, v); err != nil {
		t.Fatal(err)
	}
}

func envs(rs []model.ResolvedSecret) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Env)
	}
	return out
}

func TestResolveFiltersByApp(t *testing.T) {
	tests := []struct {
		name     string
		app      string
		wantEnvs []string
		wantVals []string
	}{
		{name: "notebook gets its bindings sorted by env", app: "notebook",
			wantEnvs: []string{"NEBARI_SECRET_A_KEY", "NEBARI_SECRET_B_KEY", "NEBARI_SECRET_SHARED"},
			wantVals: []string{"va", "vb", "vs"}},
		{name: "other gets only its own", app: "other",
			wantEnvs: []string{"NEBARI_SECRET_SHARED_OTHER"}, wantVals: []string{"vs"}},
		{name: "dask with only notebook bindings gets an empty list (journey 8b)", app: "dask",
			wantEnvs: []string{}, wantVals: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, nil)
			ctx := context.Background()
			e.putRaw(t, alice.Sub,
				rawEntry{name: "b", value: "vb", bindings: bind("notebook", "B_KEY")},
				rawEntry{name: "a", value: "va", bindings: bind("notebook", "A_KEY")},
				rawEntry{name: "s", value: "vs", bindings: []model.Binding{{App: "notebook", Env: "SHARED"}, {App: "other", Env: "SHARED_OTHER"}}},
				rawEntry{name: "unbound", value: "vu"},
			)
			got, err := e.svc.Resolve(ctx, claimFor(alice.Sub, tt.app), "enforced")
			if err != nil {
				t.Fatal(err)
			}
			if got == nil {
				t.Fatal("Resolve returned nil, want a non-nil slice")
			}
			if !slices.Equal(envs(got), tt.wantEnvs) {
				t.Fatalf("envs %v, want %v", envs(got), tt.wantEnvs)
			}
			for i, r := range got {
				if string(r.Value) != tt.wantVals[i] {
					t.Errorf("%s = %q, want %q", r.Env, r.Value, tt.wantVals[i])
				}
			}
			if len(e.audit.reads) != len(tt.wantEnvs) {
				t.Fatalf("%d secret_read lines, want %d", len(e.audit.reads), len(tt.wantEnvs))
			}
		})
	}
}

func TestResolveNeverUnprefixed(t *testing.T) {
	tests := []struct {
		name     string
		suffix   string
		wantEnvs []string
	}{
		// LD_PRELOAD is a valid suffix: delivered as NEBARI_SECRET_LD_PRELOAD it
		// cannot affect the dynamic loader, so it is allowed.
		{name: "LD_PRELOAD is delivered only prefixed", suffix: "LD_PRELOAD", wantEnvs: []string{"NEBARI_SECRET_LD_PRELOAD"}},
		{name: "lowercase skipped", suffix: "ld_preload", wantEnvs: []string{}},
		{name: "equals skipped", suffix: "A=B", wantEnvs: []string{}},
		{name: "empty skipped", suffix: "", wantEnvs: []string{}},
		{name: "traversal skipped", suffix: "../x", wantEnvs: []string{}},
		{name: "over-long skipped", suffix: "A" + string(bytes.Repeat([]byte("B"), 64)), wantEnvs: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.putRaw(t, alice.Sub, rawEntry{name: "s", value: "v", bindings: bind("notebook", tt.suffix)})
			got, err := e.svc.Resolve(context.Background(), claimFor(alice.Sub, "notebook"), "enforced")
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(envs(got), tt.wantEnvs) {
				t.Fatalf("envs %v, want %v", envs(got), tt.wantEnvs)
			}
			for _, r := range got {
				if !strings.HasPrefix(r.Env, "NEBARI_SECRET_") || !model.ValidSuffix(strings.TrimPrefix(r.Env, "NEBARI_SECRET_")) {
					t.Fatalf("returned %q, want NEBARI_SECRET_ plus a valid suffix", r.Env)
				}
			}
			if len(e.audit.reads) != len(tt.wantEnvs) {
				t.Fatalf("%d secret_read lines, want %d", len(e.audit.reads), len(tt.wantEnvs))
			}
		})
	}
}

func TestResolveDecryptFailed(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(t *testing.T, a, b *model.OwnerRecord)
	}{
		{name: "another owner's sealed entry copied in", corrupt: func(t *testing.T, a, b *model.OwnerRecord) {
			a.Secrets = append(a.Secrets, model.SecretEntry{Name: "vendor_key", Sealed: b.Secrets[0].Sealed, Bindings: bind("notebook", "VENDOR")})
		}},
		{name: "another owner's wrapped data key copied in", corrupt: func(t *testing.T, a, b *model.OwnerRecord) {
			a.DataKey = b.DataKey
		}},
		{name: "tampered ciphertext", corrupt: func(t *testing.T, a, _ *model.OwnerRecord) {
			s := slices.Clone(a.Secrets[0].Sealed)
			s[len(s)-1] ^= 1
			a.Secrets[0].Sealed = s
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, nil)
			a := e.putRaw(t, alice.Sub, rawEntry{name: "a_ok", value: "alice-value", bindings: bind("notebook", "A_OK")})
			b := e.putRaw(t, bob.Sub, rawEntry{name: "vendor_key", value: "bob-value", bindings: bind("notebook", "VENDOR")})
			tt.corrupt(t, a, b)
			e.replaceRecord(t, a)

			got, err := e.svc.Resolve(context.Background(), claimFor(alice.Sub, "notebook"), "enforced")
			if !errors.Is(err, crypto.ErrDecrypt) {
				t.Fatalf("err %v, want ErrDecrypt", err)
			}
			if got != nil {
				t.Fatalf("returned %d secrets, want nothing", len(got))
			}
			if len(e.audit.reads) != 0 {
				t.Fatalf("%d secret_read lines, want 0", len(e.audit.reads))
			}
			if len(e.audit.keys) != 1 || e.audit.keys[0].event != "decrypt_failed" || e.audit.keys[0].owner != alice.Sub {
				t.Fatalf("key events %+v, want one decrypt_failed for alice", e.audit.keys)
			}
			for _, k := range e.audit.keys {
				for _, s := range []string{k.event, k.owner, k.actor, k.detail} {
					if bytes.Contains([]byte(s), []byte("value")) {
						t.Fatalf("key event carries a value: %+v", k)
					}
				}
			}
			if err.Error() != "decrypt_failed" {
				t.Fatalf("error text %q carries detail", err.Error())
			}
		})
	}
}

func TestResolveNeverReturnsOtherOwners(t *testing.T) {
	e := newEnv(t, nil)
	e.putRaw(t, alice.Sub, rawEntry{name: "k", value: "alice-value", bindings: bind("notebook", "KEY")})
	e.putRaw(t, bob.Sub,
		rawEntry{name: "k", value: "bob-value", bindings: bind("notebook", "KEY")},
		rawEntry{name: "other", value: "bob-other", bindings: bind("notebook", "OTHER")})
	got, err := e.svc.Resolve(context.Background(), claimFor(alice.Sub, "notebook"), "enforced")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Env != "NEBARI_SECRET_KEY" || string(got[0].Value) != "alice-value" {
		t.Fatalf("got %+v", got)
	}
	for _, r := range e.audit.reads {
		if r.owner != alice.Sub || r.reader != alice.Sub {
			t.Fatalf("read event %+v names another owner", r)
		}
	}
}

// failingGet fails every Get with err.
type failingGet struct {
	store.SecretStore
	err error
}

func (f failingGet) Get(context.Context, string) (*model.OwnerRecord, string, error) {
	return nil, "", f.err
}

// otherOwner returns the stored record relabelled with another owner, as a
// tampered or colliding record would read, bypassing the store's own check.
type otherOwner struct{ store.SecretStore }

func (o otherOwner) Get(ctx context.Context, sub string) (*model.OwnerRecord, string, error) {
	rec, v, err := o.SecretStore.Get(ctx, sub)
	if err != nil {
		return nil, "", err
	}
	rec.OwnerSub = "sub-mallory"
	return rec, v, nil
}

// kekDown fails every Open with ErrKEKUnavailable, as the KubernetesKEK does
// when the record's master key id is not loaded.
type kekDown struct{ Sealer }

func (kekDown) Open(context.Context, *model.OwnerRecord, model.SecretEntry) ([]byte, error) {
	return nil, crypto.ErrKEKUnavailable
}

func TestResolveErrors(t *testing.T) {
	boom := errors.New("api down")
	tests := []struct {
		name      string
		wrapStore func(store.SecretStore) store.SecretStore
		kekDown   bool
		noRecord  bool
		wantErr   error
		wantEmpty bool
		wantKeys  int
	}{
		{name: "no record gives an empty list", noRecord: true, wantEmpty: true},
		{name: "store error passes through", wrapStore: func(s store.SecretStore) store.SecretStore { return failingGet{s, boom} }, wantErr: boom},
		{name: "store owner mismatch is a decrypt failure", wrapStore: func(s store.SecretStore) store.SecretStore {
			return failingGet{s, store.ErrOwnerMismatch}
		}, wantErr: crypto.ErrDecrypt, wantKeys: 1},
		{name: "record naming another owner is a decrypt failure", wrapStore: func(s store.SecretStore) store.SecretStore {
			return otherOwner{s}
		}, wantErr: crypto.ErrDecrypt, wantKeys: 1},
		{name: "kek unavailable is not a decrypt failure", kekDown: true, wantErr: crypto.ErrKEKUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, tt.wrapStore)
			if !tt.noRecord {
				e.putRaw(t, alice.Sub, rawEntry{name: "k", value: "v", bindings: bind("notebook", "KEY")})
			}
			if tt.kekDown {
				e.svc.sealer = kekDown{e.sealer}
			}
			got, err := e.svc.Resolve(context.Background(), claimFor(alice.Sub, "notebook"), "enforced")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err %v, want %v", err, tt.wantErr)
			}
			if tt.wantEmpty && (got == nil || len(got) != 0) {
				t.Fatalf("got %#v, want an empty non-nil list", got)
			}
			if tt.wantErr != nil && got != nil {
				t.Fatalf("got %d secrets with an error", len(got))
			}
			if len(e.audit.keys) != tt.wantKeys || len(e.audit.reads) != 0 {
				t.Fatalf("keys %+v reads %+v", e.audit.keys, e.audit.reads)
			}
			for _, k := range e.audit.keys {
				if k != (keyEvent{event: "decrypt_failed", owner: alice.Sub, detail: "owner_mismatch"}) {
					t.Fatalf("key event %+v, want decrypt_failed owner_mismatch for alice", k)
				}
			}
		})
	}
}

func TestResolveAuditCarriesGuardMode(t *testing.T) {
	for _, mode := range []model.GuardMode{"enforced", "overridden"} {
		t.Run(string(mode), func(t *testing.T) {
			e := newEnv(t, nil)
			e.putRaw(t, alice.Sub,
				rawEntry{name: "k1", value: "v1", bindings: bind("notebook", "K1")},
				rawEntry{name: "k2", value: "v2", bindings: bind("notebook", "K2")})
			c := claimFor(alice.Sub, "notebook")
			got, err := e.svc.Resolve(context.Background(), c, mode)
			if err != nil || len(got) != 2 {
				t.Fatalf("%v %v", got, err)
			}
			want := []readEvent{
				{owner: alice.Sub, reader: alice.Sub, secret: "k1", claim: c, mode: mode},
				{owner: alice.Sub, reader: alice.Sub, secret: "k2", claim: c, mode: mode},
			}
			if fmt.Sprint(e.audit.reads) != fmt.Sprint(want) {
				t.Fatalf("reads %+v, want %+v", e.audit.reads, want)
			}
		})
	}
}

// failingStatus fails every RecordDelivery with err and remembers what it got.
type failingStatus struct {
	store.SecretStore
	err  error
	got  []model.DeliveryStatus
	subs []string
}

func (f *failingStatus) RecordDelivery(_ context.Context, sub string, d model.DeliveryStatus) error {
	f.subs = append(f.subs, sub)
	f.got = append(f.got, d)
	return f.err
}

func TestServiceRecordDelivery(t *testing.T) {
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		count   int
		reason  string
		err     error
		want    model.DeliveryStatus
		wantErr bool
	}{
		{name: "success", count: 3, want: model.DeliveryStatus{App: "notebook", LastOK: clock, LastCount: 3}},
		{name: "success with none", count: 0, want: model.DeliveryStatus{App: "notebook", LastOK: clock}},
		{name: "failure", reason: "not_registered", want: model.DeliveryStatus{App: "notebook", LastFailure: clock, LastReason: "not_registered"}},
		{name: "store error returned", count: 1, err: errors.New("boom"), want: model.DeliveryStatus{App: "notebook", LastOK: clock, LastCount: 1}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &failingStatus{err: tt.err}
			e := newEnv(t, func(s store.SecretStore) store.SecretStore { fs.SecretStore = s; return fs })
			err := e.svc.RecordDelivery(context.Background(), claimFor(alice.Sub, "notebook"), tt.count, tt.reason)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err %v, wantErr %v", err, tt.wantErr)
			}
			if len(fs.got) != 1 || fs.got[0] != tt.want || fs.subs[0] != alice.Sub {
				t.Fatalf("recorded %+v for %v, want %+v", fs.got, fs.subs, tt.want)
			}
		})
	}
}
