package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"github.com/nebari-dev/nebari-user-secrets/internal/store"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const ns = "us"

type writeEvent struct{ owner, actor, secret, action string }

type readEvent struct {
	owner, reader, secret string
	claim                 model.PodClaim
	mode                  model.GuardMode
}

type keyEvent struct{ event, owner, actor, detail string }

type fakeAudit struct {
	mu     sync.Mutex
	events []writeEvent
	reads  []readEvent
	keys   []keyEvent
}

func (f *fakeAudit) SecretRead(_ context.Context, owner, reader, secret string, c model.PodClaim, g model.GuardMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads = append(f.reads, readEvent{owner, reader, secret, c, g})
}
func (f *fakeAudit) ResolveDenied(context.Context, model.PodIdentity, string) {}
func (f *fakeAudit) GuardChanged(context.Context, string, string, string)     {}
func (f *fakeAudit) KeyEvent(_ context.Context, event, owner, actor, detail string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = append(f.keys, keyEvent{event, owner, actor, detail})
}
func (f *fakeAudit) SecretWrite(_ context.Context, owner, actor, secret, action string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, writeEvent{owner, actor, secret, action})
}

type fakeApps []model.AppID

func (f fakeApps) Apps() []model.AppID { return f }

// bumpVersions makes the fake clientset enforce resourceVersion like the API server.
func bumpVersions(cs *fake.Clientset) {
	var n int64
	cs.PrependReactor("create", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		a.(k8stesting.CreateAction).GetObject().(metav1.Object).SetResourceVersion(strconv.FormatInt(atomic.AddInt64(&n, 1), 10))
		return false, nil, nil
	})
	cs.PrependReactor("update", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		obj := a.(k8stesting.UpdateAction).GetObject().(*corev1.Secret)
		cur, err := cs.Tracker().Get(corev1.SchemeGroupVersion.WithResource("secrets"), obj.Namespace, obj.Name)
		if err != nil {
			return false, nil, nil
		}
		if cur.(*corev1.Secret).ResourceVersion != obj.ResourceVersion {
			return true, nil, apierrors.NewConflict(corev1.Resource("secrets"), obj.Name, errors.New("stale"))
		}
		obj.ResourceVersion = strconv.FormatInt(atomic.AddInt64(&n, 1), 10)
		return false, nil, nil
	})
}

// conflictOnce wraps a store and fails the first Put with ErrConflict, as if
// another writer had won the race.
type conflictOnce struct {
	store.SecretStore
	fired atomic.Bool
	puts  atomic.Int32
}

func (c *conflictOnce) Put(ctx context.Context, rec *model.OwnerRecord, v string) (string, error) {
	c.puts.Add(1)
	if c.fired.CompareAndSwap(false, true) {
		return "", store.ErrConflict
	}
	return c.SecretStore.Put(ctx, rec, v)
}

type alwaysConflict struct{ store.SecretStore }

func (alwaysConflict) Put(context.Context, *model.OwnerRecord, string) (string, error) {
	return "", store.ErrConflict
}

type env struct {
	cs     *fake.Clientset
	st     *store.KubernetesSecretStore
	sealer *crypto.Sealer
	audit  *fakeAudit
	svc    *SecretService
	clock  time.Time
}

var alice = model.Principal{Kind: "user", Sub: "sub-alice", Username: "alice"}

func newEnv(t *testing.T, wrap func(store.SecretStore) store.SecretStore) *env {
	t.Helper()
	cs := fake.NewClientset()
	bumpVersions(cs)
	st := store.NewKubernetesSecretStore(cs, ns, time.Now)
	kek := crypto.NewMemoryKEK(map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)}, "k1")
	sealer := crypto.NewSealer(kek, rand.Reader)
	a := &fakeAudit{}
	e := &env{cs: cs, st: st, sealer: sealer, audit: a, clock: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	var s store.SecretStore = st
	if wrap != nil {
		s = wrap(st)
	}
	e.svc = NewSecretService(s, sealer, a, fakeApps{"notebook", "other"}, DefaultLimits(), func() time.Time { return e.clock })
	return e
}

func (e *env) record(t *testing.T, sub string) *model.OwnerRecord {
	t.Helper()
	rec, _, err := e.st.Get(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func bind(app, env string) []model.Binding { return []model.Binding{{App: model.AppID(app), Env: env}} }

func TestBindings(t *testing.T) {
	tests := []struct {
		name     string
		first    *UpsertInput
		in       UpsertInput
		wantErr  error
		wantName string
	}{
		{name: "valid suffix", in: UpsertInput{Name: "s", Value: []byte("v"), Bindings: bind("notebook", "VENDOR_API_KEY")}, wantName: "NEBARI_SECRET_VENDOR_API_KEY"},
		{name: "lowercase", in: UpsertInput{Name: "s", Value: []byte("v"), Bindings: bind("notebook", "ld_preload")}, wantErr: ErrInvalidSuffix},
		{name: "equals", in: UpsertInput{Name: "s", Value: []byte("v"), Bindings: bind("notebook", "A=B")}, wantErr: ErrInvalidSuffix},
		{name: "traversal", in: UpsertInput{Name: "s", Value: []byte("v"), Bindings: bind("notebook", "../x")}, wantErr: ErrInvalidSuffix},
		{name: "empty", in: UpsertInput{Name: "s", Value: []byte("v"), Bindings: bind("notebook", "")}, wantErr: ErrInvalidSuffix},
		{name: "unknown app", in: UpsertInput{Name: "s", Value: []byte("v"), Bindings: bind("nope", "X")}, wantErr: ErrUnknownApp},
		{name: "same suffix across secrets", first: &UpsertInput{Name: "a", Value: []byte("v"), Bindings: bind("notebook", "X")},
			in: UpsertInput{Name: "b", Value: []byte("v"), Bindings: bind("notebook", "X")}, wantErr: ErrEnvConflict},
		{name: "same suffix other app", first: &UpsertInput{Name: "a", Value: []byte("v"), Bindings: bind("notebook", "X")},
			in: UpsertInput{Name: "b", Value: []byte("v"), Bindings: bind("other", "X")}, wantName: "NEBARI_SECRET_X"},
		{name: "rebind same secret", first: &UpsertInput{Name: "a", Value: []byte("v"), Bindings: bind("notebook", "X")},
			in: UpsertInput{Name: "a", Bindings: bind("notebook", "X")}, wantName: "NEBARI_SECRET_X"},
		{name: "duplicate in one request", in: UpsertInput{Name: "s", Value: []byte("v"),
			Bindings: []model.Binding{{App: "notebook", Env: "X"}, {App: "notebook", Env: "X"}}}, wantErr: ErrEnvConflict},
		{name: "grants", in: UpsertInput{Name: "s", Value: []byte("v"), Grants: []model.Grant{{Kind: "user", Subject: "x"}}}, wantErr: ErrGrantsNotSupported},
		{name: "bad secret name", in: UpsertInput{Name: "1bad", Value: []byte("v")}, wantErr: ErrInvalidName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, nil)
			ctx := context.Background()
			if tt.first != nil {
				if _, _, err := e.svc.Upsert(ctx, alice, *tt.first); err != nil {
					t.Fatal(err)
				}
			}
			sum, _, err := e.svc.Upsert(ctx, alice, tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}
			b := sum.Bindings[0]
			if b.Name != tt.wantName || b.Path != "/var/run/nebari/secrets/"+tt.wantName {
				t.Fatalf("binding %+v", b)
			}
		})
	}
}

func TestEnvNameAlwaysPrefixed(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	sum, _, err := e.svc.Upsert(ctx, alice, UpsertInput{Name: "s", Value: []byte("v"), Bindings: bind("notebook", "OPENAI")})
	if err != nil {
		t.Fatal(err)
	}
	view, err := e.svc.ListForOwner(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	all := append([]model.SecretSummary{sum}, view.Secrets...)
	for _, s := range all {
		for _, b := range s.Bindings {
			if b.Env != "OPENAI" || b.Name != "NEBARI_SECRET_OPENAI" {
				t.Fatalf("binding %+v", b)
			}
		}
	}
	for _, s := range e.record(t, alice.Sub).Secrets {
		for _, b := range s.Bindings {
			if b.Env != "OPENAI" {
				t.Fatalf("stored binding %+v", b)
			}
		}
	}
}

func TestUpsertCreateRequiresValue(t *testing.T) {
	e := newEnv(t, nil)
	_, _, err := e.svc.Upsert(context.Background(), alice, UpsertInput{Name: "s"})
	if !errors.Is(err, ErrValueRequired) {
		t.Fatalf("err %v", err)
	}
}

func TestUpsertKeepsValueWhenNil(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	if _, _, err := e.svc.Upsert(ctx, alice, UpsertInput{Name: "s", Value: []byte("old")}); err != nil {
		t.Fatal(err)
	}
	e.clock = e.clock.Add(time.Hour)
	sum, created, err := e.svc.Upsert(ctx, alice, UpsertInput{Name: "s", Description: "d", Bindings: bind("notebook", "X")})
	if err != nil || created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if !sum.UpdatedAt.Equal(e.clock) {
		t.Fatalf("updatedAt %v", sum.UpdatedAt)
	}
	rec := e.record(t, alice.Sub)
	got, err := e.sealer.Open(ctx, rec, rec.Secrets[0])
	if err != nil || string(got) != "old" {
		t.Fatalf("value %q err %v", got, err)
	}
	if !rec.Secrets[0].CreatedAt.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("createdAt changed: %v", rec.Secrets[0].CreatedAt)
	}
}

func TestFirstWriteCreatesDataKey(t *testing.T) {
	e := newEnv(t, nil)
	if _, created, err := e.svc.Upsert(context.Background(), alice, UpsertInput{Name: "s", Value: []byte("v")}); err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	rec := e.record(t, alice.Sub)
	if rec.DataKey.KEKID != "k1" || len(rec.DataKey.Ciphertext) == 0 || rec.SchemaVersion != 1 || rec.OwnerUsername != "alice" {
		t.Fatalf("record %+v", rec)
	}
}

func TestValueTooLarge(t *testing.T) {
	e := newEnv(t, nil)
	_, _, err := e.svc.Upsert(context.Background(), alice, UpsertInput{Name: "s", Value: make([]byte, 32769)})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err %v", err)
	}
	if _, _, err := e.svc.Upsert(context.Background(), alice, UpsertInput{Name: "s", Value: make([]byte, 32768)}); err != nil {
		t.Fatal(err)
	}
}

func TestSecretCountLimit(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	for i := range 50 {
		if _, _, err := e.svc.Upsert(ctx, alice, UpsertInput{Name: fmt.Sprintf("s%d", i), Value: []byte("v")}); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	if _, _, err := e.svc.Upsert(ctx, alice, UpsertInput{Name: "s50", Value: []byte("v")}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err %v", err)
	}
	// Updating an existing secret at the limit is allowed.
	if _, _, err := e.svc.Upsert(ctx, alice, UpsertInput{Name: "s0", Value: []byte("w")}); err != nil {
		t.Fatal(err)
	}
}

func TestLimitCountsEncodedSize(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	val := bytes.Repeat([]byte{'x'}, 32768)
	accepted, rejected := 0, false
	for i := range 40 {
		_, _, err := e.svc.Upsert(ctx, alice, UpsertInput{Name: fmt.Sprintf("big%d", i), Value: val})
		if errors.Is(err, ErrLimitExceeded) {
			rejected = true
			break
		}
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		accepted++
	}
	if !rejected || accepted == 0 {
		t.Fatalf("accepted %d rejected %v", accepted, rejected)
	}
	sec, err := e.cs.CoreV1().Secrets(ns).Get(ctx, model.SecretName(alice.Sub), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	size := len(sec.Data["record.json"])
	if size > 524288 {
		t.Fatalf("stored record %d bytes", size)
	}
	if len(e.record(t, alice.Sub).Secrets) != accepted {
		t.Fatal("stored count differs from accepted count")
	}
	// The rejection was because one more would not fit: another secret of the
	// same size would have pushed the encoded record over the limit.
	rec := e.record(t, alice.Sub)
	sealed, _ := e.sealer.Seal(ctx, rec, "probe", val)
	rec.Secrets = append(rec.Secrets, model.SecretEntry{Name: "big99", Sealed: sealed, CreatedAt: e.clock, UpdatedAt: e.clock})
	b, _ := json.Marshal(rec)
	if len(b) <= 524288 {
		t.Fatalf("probe record %d bytes would have fit", len(b))
	}
	view, err := e.svc.ListForOwner(ctx, alice)
	if err != nil || view.Usage.Bytes != size || view.Usage.Count != accepted || view.Usage.MaxBytes != 524288 || view.Usage.MaxCount != 50 {
		t.Fatalf("usage %+v size %d err %v", view.Usage, size, err)
	}
}

func TestConcurrentUpsertsBothPersist(t *testing.T) {
	var co *conflictOnce
	e := newEnv(t, func(s store.SecretStore) store.SecretStore { co = &conflictOnce{SecretStore: s}; return co })
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, n := range []string{"first", "second"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, errs[i] = e.svc.Upsert(ctx, alice, UpsertInput{Name: n, Value: []byte("v-" + n)})
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	rec := e.record(t, alice.Sub)
	if len(rec.Secrets) != 2 {
		t.Fatalf("secrets %d", len(rec.Secrets))
	}
	for _, s := range rec.Secrets {
		got, err := e.sealer.Open(ctx, rec, s)
		if err != nil || string(got) != "v-"+s.Name {
			t.Fatalf("%s: %q %v", s.Name, got, err)
		}
	}
	if co.puts.Load() < 3 {
		t.Fatalf("puts %d, conflict not exercised", co.puts.Load())
	}
}

func TestConflictGivesUp(t *testing.T) {
	e := newEnv(t, func(s store.SecretStore) store.SecretStore { return alwaysConflict{s} })
	_, _, err := e.svc.Upsert(context.Background(), alice, UpsertInput{Name: "s", Value: []byte("v")})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("err %v", err)
	}
	if len(e.audit.events) != 0 {
		t.Fatalf("audited a failed write: %+v", e.audit.events)
	}
}

func TestSecretWriteAudited(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	steps := []struct {
		do     func() error
		action string
	}{
		{func() error {
			_, _, err := e.svc.Upsert(ctx, alice, UpsertInput{Name: "s", Value: []byte("SECRETVALUE")})
			return err
		}, "create"},
		{func() error {
			_, _, err := e.svc.Upsert(ctx, alice, UpsertInput{Name: "s", Description: "d"})
			return err
		}, "update"},
		{func() error {
			_, _, err := e.svc.Upsert(ctx, alice, UpsertInput{Name: "s", Value: []byte("NEWVALUE")})
			return err
		}, "rotate"},
		{func() error { return e.svc.Delete(ctx, alice, "s") }, "delete"},
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.audit.events) != len(steps) {
		t.Fatalf("events %+v", e.audit.events)
	}
	for i, ev := range e.audit.events {
		want := writeEvent{alice.Sub, alice.Sub, "s", steps[i].action}
		if ev != want {
			t.Fatalf("event %d %+v want %+v", i, ev, want)
		}
	}
}

func TestDelete(t *testing.T) {
	tests := []struct {
		name    string
		seed    bool
		del     string
		wantErr error
	}{
		{name: "unknown name", seed: true, del: "other", wantErr: ErrNotFound},
		{name: "no record", seed: false, del: "s", wantErr: ErrNotFound},
		{name: "last secret keeps record", seed: true, del: "s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, nil)
			ctx := context.Background()
			if tt.seed {
				if _, _, err := e.svc.Upsert(ctx, alice, UpsertInput{Name: "s", Value: []byte("v")}); err != nil {
					t.Fatal(err)
				}
			}
			e.audit.events = nil
			err := e.svc.Delete(ctx, alice, tt.del)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err %v", err)
			}
			if tt.wantErr != nil {
				if len(e.audit.events) != 0 {
					t.Fatalf("audited failure %+v", e.audit.events)
				}
				return
			}
			rec := e.record(t, alice.Sub)
			if len(rec.Secrets) != 0 || len(rec.DataKey.Ciphertext) == 0 {
				t.Fatalf("record %+v", rec)
			}
		})
	}
}

func TestListForOwner(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	view, err := e.svc.ListForOwner(ctx, alice)
	if err != nil || view.Secrets == nil || len(view.Secrets) != 0 || view.Usage.MaxCount != 50 || view.Usage.Count != 0 {
		t.Fatalf("empty view %+v err %v", view, err)
	}
	for _, n := range []string{"zeta", "alpha"} {
		if _, _, err := e.svc.Upsert(ctx, alice, UpsertInput{Name: n, Value: []byte("topsecret"), Bindings: bind("notebook", "K_"+strings.ToUpper(n[:1]))}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.st.RecordDelivery(ctx, alice.Sub, model.DeliveryStatus{App: "notebook", LastOK: e.clock, LastCount: 2}); err != nil {
		t.Fatal(err)
	}
	view, err = e.svc.ListForOwner(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Secrets) != 2 || view.Secrets[0].Name != "alpha" || view.Secrets[1].Name != "zeta" {
		t.Fatalf("order %+v", view.Secrets)
	}
	if len(view.Deliveries) != 1 || view.Deliveries[0].App != "notebook" || view.Usage.Count != 2 || view.Usage.Bytes == 0 {
		t.Fatalf("view %+v", view)
	}
	b, _ := json.Marshal(view)
	if bytes.Contains(b, []byte("topsecret")) {
		t.Fatal("value in view")
	}
}

func TestKEKUnavailablePassesThrough(t *testing.T) {
	e := newEnv(t, nil)
	e.svc.sealer = failingSealer{}
	_, _, err := e.svc.Upsert(context.Background(), alice, UpsertInput{Name: "s", Value: []byte("v")})
	if !errors.Is(err, crypto.ErrKEKUnavailable) {
		t.Fatalf("err %v", err)
	}
}

type failingSealer struct{ Sealer }

func (failingSealer) NewDataKey(context.Context, string) (model.WrappedKey, error) {
	return model.WrappedKey{}, fmt.Errorf("load: %w", crypto.ErrKEKUnavailable)
}

// barrierStore makes the first two Gets rendezvous after reading, so two
// concurrent callers both observe the same pre-write state.
type barrierStore struct {
	store.SecretStore
	gets    atomic.Int32
	arrived chan struct{}
	release chan struct{}
}

func (b *barrierStore) Get(ctx context.Context, sub string) (*model.OwnerRecord, string, error) {
	rec, v, err := b.SecretStore.Get(ctx, sub)
	if b.gets.Add(1) <= 2 {
		b.arrived <- struct{}{}
		<-b.release
	}
	return rec, v, err
}

func TestFirstWritesRaceForNewOwner(t *testing.T) {
	var bs *barrierStore
	e := newEnv(t, func(s store.SecretStore) store.SecretStore {
		bs = &barrierStore{SecretStore: s, arrived: make(chan struct{}, 2), release: make(chan struct{})}
		return bs
	})
	ctx := context.Background()
	names := []string{"first", "second"}
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, errs[i] = e.svc.Upsert(ctx, alice, UpsertInput{Name: n, Value: []byte("v-" + n)})
		}()
	}
	<-bs.arrived
	<-bs.arrived
	close(bs.release)
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	// Both saw NotFound, so both tried to create; exactly one lost and
	// re-read, which makes three Gets in total.
	if g := bs.gets.Load(); g != 3 {
		t.Fatalf("gets %d, want 3 (one retry)", g)
	}
	rec := e.record(t, alice.Sub)
	if len(rec.Secrets) != 2 {
		t.Fatalf("secrets %d", len(rec.Secrets))
	}
	for _, s := range rec.Secrets {
		got, err := e.sealer.Open(ctx, rec, s)
		if err != nil || string(got) != "v-"+s.Name {
			t.Fatalf("%s: %q %v (data key mismatch?)", s.Name, got, err)
		}
	}
}
