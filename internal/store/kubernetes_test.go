package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const ns = "us"

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newStore(t *testing.T) (*KubernetesSecretStore, *fake.Clientset, *fakeClock) {
	t.Helper()
	cs := fake.NewClientset()
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	return NewKubernetesSecretStore(cs, ns, clk.now), cs, clk
}

func rec(sub string) *model.OwnerRecord {
	return &model.OwnerRecord{SchemaVersion: 1, OwnerSub: sub, OwnerUsername: "u"}
}

// bumpVersions makes the fake clientset behave like the API server for
// resourceVersion: writes bump it and a stale update is a Conflict.
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

func TestGetMissingReturnsNotFound(t *testing.T) {
	s, _, _ := newStore(t)
	_, _, err := s.Get(context.Background(), "nobody")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestPutCreatesThenUpdatesWithResourceVersion(t *testing.T) {
	ctx := context.Background()
	s, cs, _ := newStore(t)
	bumpVersions(cs)

	v1, err := s.Put(ctx, rec("alice"), "")
	if err != nil || v1 == "" {
		t.Fatalf("create: %q %v", v1, err)
	}
	if _, err := s.Put(ctx, rec("alice"), ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("create over existing: got %v, want ErrConflict", err)
	}
	r := rec("alice")
	r.OwnerUsername = "renamed"
	v2, err := s.Put(ctx, r, v1)
	if err != nil || v2 == v1 {
		t.Fatalf("update: %q %v", v2, err)
	}
	if _, err := s.Put(ctx, r, v1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update: got %v, want ErrConflict", err)
	}
	got, ver, err := s.Get(ctx, "alice")
	if err != nil || ver != v2 || got.OwnerUsername != "renamed" {
		t.Fatalf("get: %+v %q %v", got, ver, err)
	}
	sec, _ := cs.CoreV1().Secrets(ns).Get(ctx, model.SecretName("alice"), metav1.GetOptions{})
	if sec.Labels[recordLabel] != "owner" || sec.Type != corev1.SecretTypeOpaque {
		t.Fatalf("labels/type: %v %v", sec.Labels, sec.Type)
	}
}

func TestPutUpdateMissingIsConflict(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{"deleted since read", "7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _, _ := newStore(t)
			if _, err := s.Put(context.Background(), rec("alice"), tt.version); !errors.Is(err, ErrConflict) {
				t.Fatalf("got %v, want ErrConflict", err)
			}
		})
	}
}

func TestPutCreateNotFoundIsNotConflict(t *testing.T) {
	s, cs, _ := newStore(t)
	cs.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(corev1.Resource("namespaces"), ns)
	})
	_, err := s.Put(context.Background(), rec("alice"), "")
	if err == nil || errors.Is(err, ErrConflict) {
		t.Fatalf("got %v, want a non-conflict error", err)
	}
}

func TestPutRejectsOversize(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*model.OwnerRecord)
		want error
	}{
		{"too large", func(r *model.OwnerRecord) {
			r.Secrets = []model.SecretEntry{{Name: "A", Sealed: make([]byte, 400000)}}
		}, ErrRecordTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, cs, _ := newStore(t)
			r := rec("alice")
			tt.mod(r)
			if _, err := s.Put(context.Background(), r, ""); !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			if len(cs.Actions()) != 0 {
				t.Fatalf("API touched: %v", cs.Actions())
			}
		})
	}
}

func TestOwnerMismatchAndSchema(t *testing.T) {
	tests := []struct {
		name    string
		stored  model.OwnerRecord
		wantErr error
		anyErr  bool
	}{
		{"mismatch", model.OwnerRecord{SchemaVersion: 1, OwnerSub: "bob"}, ErrOwnerMismatch, false},
		{"schema 2", model.OwnerRecord{SchemaVersion: 2, OwnerSub: "alice"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, cs, _ := newStore(t)
			b, _ := json.Marshal(tt.stored)
			_, err := cs.CoreV1().Secrets(ns).Create(context.Background(), &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: model.SecretName("alice")},
				Data:       map[string][]byte{recordKey: b},
			}, metav1.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = s.Get(context.Background(), "alice")
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("got %v, want %v", err, tt.wantErr)
			}
			if tt.anyErr && err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestNonUUIDSub(t *testing.T) {
	tests := []string{"f:ldap:jdoe", "UPPER/odd sub", "a-b-c"}
	for _, sub := range tests {
		t.Run(sub, func(t *testing.T) {
			ctx := context.Background()
			s, _, _ := newStore(t)
			if _, err := s.Put(ctx, rec(sub), ""); err != nil {
				t.Fatal(err)
			}
			got, _, err := s.Get(ctx, sub)
			if err != nil || got.OwnerSub != sub {
				t.Fatalf("%+v %v", got, err)
			}
		})
	}
}

func TestRecordDeliveryRateLimited(t *testing.T) {
	ctx := context.Background()
	s, cs, clk := newStore(t)
	writes := 0
	cs.PrependReactor("*", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetVerb() == "create" || a.GetVerb() == "update" {
			writes++
		}
		return false, nil, nil
	})
	ok := func(app string) model.DeliveryStatus {
		return model.DeliveryStatus{App: model.AppID(app), LastOK: clk.now(), LastCount: 1}
	}
	steps := []struct {
		advance time.Duration
		app     string
		wantW   int
	}{
		{0, "jupyter", 1},
		{30 * time.Second, "jupyter", 1},
		{0, "other", 2},
		{31 * time.Second, "jupyter", 3},
	}
	for i, st := range steps {
		clk.t = clk.t.Add(st.advance)
		if err := s.RecordDelivery(ctx, "alice", ok(st.app)); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if writes != st.wantW {
			t.Fatalf("step %d: writes=%d want %d", i, writes, st.wantW)
		}
	}
	got, err := s.Deliveries(ctx, "alice")
	if err != nil || len(got) != 2 {
		t.Fatalf("deliveries: %+v %v", got, err)
	}
}

func TestRecordDeliveryFailureReturnsNilNoRetry(t *testing.T) {
	ctx := context.Background()
	s, cs, clk := newStore(t)
	attempts := 0
	cs.PrependReactor("*", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetVerb() == "create" || a.GetVerb() == "update" {
			attempts++
			return true, nil, errors.New("boom")
		}
		return false, nil, nil
	})
	d := model.DeliveryStatus{App: "jupyter", LastOK: clk.now()}
	if err := s.RecordDelivery(ctx, "alice", d); err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if err := s.RecordDelivery(ctx, "alice", d); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("attempts=%d, want 1 (no retry within the minute)", attempts)
	}
}

func TestDeliveriesRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, cs, clk := newStore(t)
	if got, err := s.Deliveries(ctx, "alice"); err != nil || len(got) != 0 {
		t.Fatalf("empty: %+v %v", got, err)
	}
	want := model.DeliveryStatus{App: "jupyter", LastOK: clk.now(), LastCount: 3, LastFailure: clk.now(), LastReason: "denied"}
	if err := s.RecordDelivery(ctx, "alice", want); err != nil {
		t.Fatal(err)
	}
	got, err := s.Deliveries(ctx, "alice")
	if err != nil || len(got) != 1 || got[0] != want {
		t.Fatalf("%+v %v", got, err)
	}
	sec, _ := cs.CoreV1().Secrets(ns).Get(ctx, model.StatusSecretName("alice"), metav1.GetOptions{})
	if sec.Labels[recordLabel] != "status" || sec.Data[statusKey] == nil {
		t.Fatalf("status secret: %+v", sec)
	}
}

func TestAnyRecords(t *testing.T) {
	ctx := context.Background()
	s, _, clk := newStore(t)
	if ok, err := s.AnyRecords(ctx); err != nil || ok {
		t.Fatalf("empty: %v %v", ok, err)
	}
	_ = s.RecordDelivery(ctx, "alice", model.DeliveryStatus{App: "a", LastOK: clk.now()})
	if ok, err := s.AnyRecords(ctx); err != nil || ok {
		t.Fatalf("status only: %v %v", ok, err)
	}
	if _, err := s.Put(ctx, rec("alice"), ""); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.AnyRecords(ctx); err != nil || !ok {
		t.Fatalf("after put: %v %v", ok, err)
	}
}

func TestListOwners(t *testing.T) {
	ctx := context.Background()
	s, _, clk := newStore(t)
	for _, sub := range []string{"f:ldap:a", "b"} {
		if _, err := s.Put(ctx, rec(sub), ""); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.RecordDelivery(ctx, "c", model.DeliveryStatus{App: "a", LastOK: clk.now()})
	got, err := s.ListOwners(ctx)
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	if strings.Join(got, ",") != "b,f:ldap:a" && strings.Join(got, ",") != "f:ldap:a,b" {
		t.Fatalf("got %v", got)
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	s, cs, clk := newStore(t)
	if err := s.Delete(ctx, "alice"); err != nil {
		t.Fatalf("missing delete: %v", err)
	}
	_, _ = s.Put(ctx, rec("alice"), "")
	_ = s.RecordDelivery(ctx, "alice", model.DeliveryStatus{App: "a", LastOK: clk.now()})
	if err := s.Delete(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	l, _ := cs.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
	if len(l.Items) != 0 {
		t.Fatalf("left: %d", len(l.Items))
	}
}
