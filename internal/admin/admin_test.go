package admin

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

type auditEvent struct{ event, owner, actor, detail string }

type fakeAudit struct {
	mu     sync.Mutex
	events []auditEvent
}

func (f *fakeAudit) KeyEvent(_ context.Context, event, owner, actor, detail string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, auditEvent{event, owner, actor, detail})
}

func (f *fakeAudit) count(event string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, e := range f.events {
		if e.event == event {
			n++
		}
	}
	return n
}

// bumpVersions makes the fake clientset behave like the API server for
// resourceVersion: a stale update is a Conflict.
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

type env struct {
	cs     *fake.Clientset
	st     *store.KubernetesSecretStore
	kek    *crypto.KubernetesKEK
	sealer *crypto.Sealer
	audit  *fakeAudit
}

// newEnv bootstraps a KEK (id returned) and writes three records with two
// values each.
func newEnv(t *testing.T) (*env, string) {
	t.Helper()
	ctx := context.Background()
	cs := fake.NewClientset()
	bumpVersions(cs)
	st := store.NewKubernetesSecretStore(cs, ns, time.Now)
	a := &fakeAudit{}
	kek := crypto.NewKubernetesKEK(cs, ns, st, a)
	if err := kek.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	sealer := crypto.NewSealer(kek, rand.Reader)
	first, err := kek.PrimaryID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		writeRecord(t, st, sealer, fmt.Sprintf("sub-%d", i))
	}
	a.events = nil
	return &env{cs, st, kek, sealer, a}, first
}

func value(sub, name string) []byte { return []byte("value-of-" + sub + "-" + name) }

func writeRecord(t *testing.T, st *store.KubernetesSecretStore, sealer *crypto.Sealer, sub string) {
	t.Helper()
	ctx := context.Background()
	dk, err := sealer.NewDataKey(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	rec := &model.OwnerRecord{SchemaVersion: 1, OwnerSub: sub, OwnerUsername: sub, DataKey: dk}
	for _, n := range []string{"A_ONE", "B_TWO"} {
		sealed, err := sealer.Seal(ctx, rec, n, value(sub, n))
		if err != nil {
			t.Fatal(err)
		}
		rec.Secrets = append(rec.Secrets, model.SecretEntry{Name: n, Sealed: sealed})
	}
	if _, err := st.Put(ctx, rec, ""); err != nil {
		t.Fatal(err)
	}
}

func assertValuesOpen(t *testing.T, e *env) { t.Helper(); assertValuesOpenN(t, e, 3) }

func assertValuesOpenN(t *testing.T, e *env, wantOwners int) {
	t.Helper()
	ctx := context.Background()
	owners, err := e.st.ListOwners(ctx)
	if err != nil || len(owners) != wantOwners {
		t.Fatalf("owners %v err %v", owners, err)
	}
	for _, o := range owners {
		rec, _, err := e.st.Get(ctx, o)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range rec.Secrets {
			got, err := e.sealer.Open(ctx, rec, s)
			if err != nil || !bytes.Equal(got, value(o, s.Name)) {
				t.Fatalf("%s/%s: open failed or wrong value (%v)", o, s.Name, err)
			}
		}
	}
}

func TestRotateKEKRewrapsAll(t *testing.T) {
	ctx := context.Background()
	e, old := newEnv(t)
	rep, err := RotateKEK(ctx, e.st, e.kek, e.sealer, e.audit, "admin-1")
	if err != nil {
		t.Fatal(err)
	}
	newID, _ := e.kek.PrimaryID(ctx)
	if newID == old {
		t.Fatal("primary did not change")
	}
	if rep.Rewrapped != 3 || len(rep.ByKEK) != 1 || rep.ByKEK[newID] != 3 {
		t.Fatalf("report %+v, want 3 under %s", rep, newID)
	}
	assertValuesOpen(t, e)
	if e.audit.count("kek_rotated") != 1 {
		t.Fatalf("events %+v", e.audit.events)
	}
	for _, ev := range e.audit.events {
		if ev.event == "kek_rotated" && (ev.actor != "admin-1" || ev.detail != newID+" rewrapped=3") {
			t.Fatalf("bad event %+v", ev)
		}
	}
}

const concurrentName = "changed"

var concurrentSeq atomic.Int64

// concurrentWrite applies mutate to the stored record behind the store's back
// (through the tracker, so no reactor runs) and bumps its resourceVersion,
// like another writer winning a race.
func concurrentWrite(t *testing.T, e *env, secretName string, mutate func(rec *model.OwnerRecord)) {
	t.Helper()
	gvr := corev1.SchemeGroupVersion.WithResource("secrets")
	cur, err := e.cs.Tracker().Get(gvr, ns, secretName)
	if err != nil {
		t.Fatal(err)
	}
	sec := cur.(*corev1.Secret).DeepCopy()
	var rec model.OwnerRecord
	if err := json.Unmarshal(sec.Data["record.json"], &rec); err != nil {
		t.Fatal(err)
	}
	mutate(&rec)
	if sec.Data["record.json"], err = json.Marshal(&rec); err != nil {
		t.Fatal(err)
	}
	sec.ResourceVersion = "conc-" + strconv.FormatInt(concurrentSeq.Add(1), 10)
	if err := e.cs.Tracker().Update(gvr, sec, ns); err != nil {
		t.Fatal(err)
	}
}

// injectConflicts makes the first n record updates lose a race: a concurrent
// writer changes the username and appends a third value sealed under the
// record's current data key, then the update returns Conflict.
func injectConflicts(t *testing.T, e *env, n int32) {
	t.Helper()
	var left atomic.Int32
	left.Store(n)
	e.cs.PrependReactor("update", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		obj := a.(k8stesting.UpdateAction).GetObject().(*corev1.Secret)
		if obj.Name == "user-secrets-kek" || left.Add(-1) < 0 {
			return false, nil, nil
		}
		concurrentWrite(t, e, obj.Name, func(rec *model.OwnerRecord) {
			rec.OwnerUsername = concurrentName
			if len(rec.Secrets) == 2 {
				sealed, err := e.sealer.Seal(context.Background(), rec, "C_THREE", value(rec.OwnerSub, "C_THREE"))
				if err != nil {
					t.Error(err)
				}
				rec.Secrets = append(rec.Secrets, model.SecretEntry{Name: "C_THREE", Sealed: sealed})
			}
		})
		return true, nil, apierrors.NewConflict(corev1.Resource("secrets"), obj.Name, errors.New("injected"))
	})
}

// assertConcurrentSurvived checks that the concurrent change was kept on the
// conflicted record (retry re-read it rather than re-writing the stale copy).
func assertConcurrentSurvived(t *testing.T, e *env) {
	t.Helper()
	found := 0
	for _, o := range []string{"sub-0", "sub-1", "sub-2"} {
		rec, _, err := e.st.Get(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		if rec.OwnerUsername == concurrentName {
			found++
			if len(rec.Secrets) != 3 {
				t.Fatalf("%s: concurrent entry lost, %d secrets", o, len(rec.Secrets))
			}
		}
	}
	if found != 1 {
		t.Fatalf("%d records carry the concurrent change, want 1", found)
	}
}

var conflictCases = []struct {
	name      string
	conflicts int32
	wantErr   bool
}{
	{"one conflict is retried", 1, false},
	{"four conflicts still succeed", 4, false},
	{"five conflicts exhaust the retries", 5, true},
	{"persistent conflicts fail the command", 100, true},
}

func TestRotateKEKRetriesConflict(t *testing.T) {
	for _, tc := range conflictCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			e, old := newEnv(t)
			injectConflicts(t, e, tc.conflicts)
			_, err := RotateKEK(ctx, e.st, e.kek, e.sealer, e.audit, "admin")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				if e.audit.count("kek_rotated") != 0 {
					t.Fatal("kek_rotated emitted on failure")
				}
				return
			}
			assertValuesOpenN(t, e, 3)
			assertConcurrentSurvived(t, e)
			newID, _ := e.kek.PrimaryID(ctx)
			for _, o := range []string{"sub-0", "sub-1", "sub-2"} {
				rec, _, _ := e.st.Get(ctx, o)
				if rec.DataKey.KEKID != newID || newID == old {
					t.Fatalf("%s not rewrapped: %s", o, rec.DataKey.KEKID)
				}
			}
		})
	}
}

func TestRotateDEKRetriesConflict(t *testing.T) {
	for _, tc := range conflictCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			e, _ := newEnv(t)
			before, _, _ := e.st.Get(ctx, "sub-0")
			injectConflicts(t, e, tc.conflicts)
			_, err := RotateDEK(ctx, e.st, e.sealer, e.audit, "admin", "sub-0")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				if e.audit.count("dek_rotated") != 0 {
					t.Fatal("dek_rotated emitted on failure")
				}
				return
			}
			rec, _, _ := e.st.Get(ctx, "sub-0")
			if rec.OwnerUsername != concurrentName || len(rec.Secrets) != 3 {
				t.Fatalf("concurrent change lost: %q, %d secrets", rec.OwnerUsername, len(rec.Secrets))
			}
			if bytes.Equal(rec.DataKey.Ciphertext, before.DataKey.Ciphertext) {
				t.Fatal("data key not rotated")
			}
			for i, s := range rec.Secrets {
				got, err := e.sealer.Open(ctx, rec, s)
				if err != nil || !bytes.Equal(got, value("sub-0", s.Name)) {
					t.Fatalf("secret %s: %v", s.Name, err)
				}
				if bytes.Equal(s.Sealed, before.Secrets[min(i, 1)].Sealed) {
					t.Fatalf("secret %s not re-sealed", s.Name)
				}
			}
		})
	}
}

func TestRotateDEKReencrypts(t *testing.T) {
	tests := []struct {
		name      string
		owner     string
		wantCount int
	}{
		{"one owner", "sub-1", 1},
		{"all owners", "", 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			e, _ := newEnv(t)
			before := map[string]*model.OwnerRecord{}
			for _, o := range []string{"sub-0", "sub-1", "sub-2"} {
				r, _, _ := e.st.Get(ctx, o)
				before[o] = r
			}
			rep, err := RotateDEK(ctx, e.st, e.sealer, e.audit, "admin-2", tc.owner)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Rewrapped != tc.wantCount {
				t.Fatalf("rotated %d, want %d", rep.Rewrapped, tc.wantCount)
			}
			for o, old := range before {
				now, _, _ := e.st.Get(ctx, o)
				rotated := tc.owner == "" || tc.owner == o
				if bytes.Equal(old.DataKey.Ciphertext, now.DataKey.Ciphertext) == rotated {
					t.Fatalf("%s: data key rotated=%v mismatch", o, rotated)
				}
				if bytes.Equal(old.Secrets[0].Sealed, now.Secrets[0].Sealed) == rotated {
					t.Fatalf("%s: sealed value rotated=%v mismatch", o, rotated)
				}
			}
			assertValuesOpen(t, e)
			if got := e.audit.count("dek_rotated"); got != tc.wantCount {
				t.Fatalf("dek_rotated events = %d, want %d", got, tc.wantCount)
			}
			for _, ev := range e.audit.events {
				if ev.event == "dek_rotated" && (ev.actor != "admin-2" || ev.owner == "" || ev.detail != "") {
					t.Fatalf("bad event %+v", ev)
				}
			}
		})
	}
}

func TestRotateDEKNeverPersistsUnopenable(t *testing.T) {
	ctx := context.Background()
	e, _ := newEnv(t)
	rec, v, _ := e.st.Get(ctx, "sub-1")
	rec.Secrets[1].Sealed[len(rec.Secrets[1].Sealed)-1] ^= 0xff // corrupt
	if _, err := e.st.Put(ctx, rec, v); err != nil {
		t.Fatal(err)
	}
	if _, err := RotateDEK(ctx, e.st, e.sealer, e.audit, "admin", "sub-1"); err == nil {
		t.Fatal("expected error")
	}
	after, _, _ := e.st.Get(ctx, "sub-1")
	if !bytes.Equal(after.DataKey.Ciphertext, rec.DataKey.Ciphertext) || !bytes.Equal(after.Secrets[0].Sealed, rec.Secrets[0].Sealed) {
		t.Fatal("record changed despite failure")
	}
	if e.audit.count("dek_rotated") != 0 {
		t.Fatal("dek_rotated emitted on failure")
	}
}

func TestRetireAfterRotate(t *testing.T) {
	ctx := context.Background()
	e, old := newEnv(t)
	if err := RetireKEK(ctx, e.st, e.kek, old); err == nil {
		t.Fatal("retire before rotate must be refused (primary and in use)")
	}
	if _, err := RotateKEK(ctx, e.st, e.kek, e.sealer, e.audit, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := RetireKEK(ctx, e.st, e.kek, old); err != nil {
		t.Fatalf("retire after rotate: %v", err)
	}
	assertValuesOpen(t, e)
	if e.audit.count("kek_retired") != 1 {
		t.Fatalf("events %+v", e.audit.events)
	}
}

func TestRotateDEKUnknownOwnerNamesOwner(t *testing.T) {
	e, _ := newEnv(t)
	_, err := RotateDEK(context.Background(), e.st, e.sealer, e.audit, "admin", "nobody")
	if !errors.Is(err, store.ErrNotFound) || !strings.Contains(err.Error(), "owner nobody") {
		t.Fatalf("err = %v", err)
	}
}

func TestRetireRefusedWhileInUse(t *testing.T) {
	ctx := context.Background()
	e, old := newEnv(t)
	// Rotate the key only, leaving records on the old id.
	if _, err := e.kek.AddKey(ctx); err != nil {
		t.Fatal(err)
	}
	if err := RetireKEK(ctx, e.st, e.kek, old); err == nil {
		t.Fatal("retire must be refused while records use the key")
	}
	assertValuesOpen(t, e)
}
