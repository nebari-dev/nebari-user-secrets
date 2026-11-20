package crypto

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

type fakeLister struct {
	any bool
	err error
}

func (f fakeLister) AnyRecords(context.Context) (bool, error) { return f.any, f.err }

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

func kekSecret(primary string, keys map[string][]byte) *corev1.Secret {
	d := map[string][]byte{"primary": []byte(primary)}
	for id, k := range keys {
		d[id] = k
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: kekSecretName, Namespace: "ns"},
		Type:       corev1.SecretTypeOpaque,
		Data:       d,
	}
}

func key32(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestBootstrap(t *testing.T) {
	gr := schema.GroupResource{Resource: "secrets"}
	tests := []struct {
		name        string
		existing    *corev1.Secret
		lister      fakeLister
		alreadyRace bool
		wantErr     error
		wantCreated bool
		wantEvents  []string
		wantDetail  string
	}{
		{name: "no secret no records creates", wantCreated: true, wantEvents: []string{"kek_created"}},
		{name: "no secret with records fails closed", lister: fakeLister{any: true}, wantErr: ErrKEKUnavailable, wantEvents: []string{"kek_unavailable"}, wantDetail: "records_exist"},
		{name: "no secret list error fails closed", lister: fakeLister{err: errors.New("boom")}, wantErr: ErrKEKUnavailable, wantEvents: []string{"kek_unavailable"}, wantDetail: "record_list_failed"},
		{name: "secret present loads", existing: kekSecret("ka", map[string][]byte{"ka": key32(1)}), lister: fakeLister{any: true}},
		{name: "present but short key", existing: kekSecret("ka", map[string][]byte{"ka": []byte("short")}), wantErr: ErrKEKUnavailable},
		{name: "present but primary missing", existing: kekSecret("kb", map[string][]byte{"ka": key32(1)}), wantErr: ErrKEKUnavailable},
		{name: "present without primary", existing: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kekSecretName, Namespace: "ns"}, Data: map[string][]byte{"ka": key32(1)}}, wantErr: ErrKEKUnavailable},
		{name: "create races AlreadyExists", alreadyRace: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewClientset()
			if tc.existing != nil {
				cs = fake.NewClientset(tc.existing)
			}
			creates := 0
			cs.PrependReactor("create", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
				creates++
				if tc.alreadyRace {
					_ = cs.Tracker().Add(kekSecret("kwin", map[string][]byte{"kwin": key32(9)}))
					return true, nil, apierrors.NewAlreadyExists(gr, kekSecretName)
				}
				return false, nil, nil
			})
			au := &fakeAudit{}
			k := NewKubernetesKEK(cs, "ns", tc.lister, au)
			err := k.Bootstrap(context.Background())
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil && creates != 0 {
				t.Fatalf("created %d secrets on failure", creates)
			}
			if tc.existing != nil && creates != 0 {
				t.Fatal("created over an existing secret")
			}
			if tc.wantCreated {
				s, gerr := cs.CoreV1().Secrets("ns").Get(context.Background(), kekSecretName, metav1.GetOptions{})
				if gerr != nil {
					t.Fatal(gerr)
				}
				if s.Labels["nebari.dev/user-secrets-record"] != "kek" || s.Type != corev1.SecretTypeOpaque {
					t.Fatalf("bad labels/type: %v %v", s.Labels, s.Type)
				}
				p := string(s.Data["primary"])
				if !strings.HasPrefix(p, "k") || len(s.Data[p]) != 32 {
					t.Fatalf("bad primary %q", p)
				}
				if len(au.events) != 1 || au.events[0].detail != p {
					t.Fatalf("events %v", au.events)
				}
			}
			var got []string
			for _, e := range au.events {
				got = append(got, e.event)
			}
			if strings.Join(got, ",") != strings.Join(tc.wantEvents, ",") {
				t.Fatalf("events = %v, want %v", got, tc.wantEvents)
			}
			if tc.wantDetail != "" && (len(au.events) != 1 || au.events[0].detail != tc.wantDetail) {
				t.Fatalf("detail = %v, want %q", au.events, tc.wantDetail)
			}
			if tc.wantErr == nil {
				if _, werr := k.Wrap(context.Background(), key32(5), "sub"); werr != nil {
					t.Fatalf("wrap after bootstrap: %v", werr)
				}
			}
			if tc.alreadyRace {
				id, _ := k.PrimaryID(context.Background())
				if id != "kwin" {
					t.Fatalf("primary = %q, want kwin", id)
				}
			}
			for _, e := range au.events {
				if strings.Contains(e.detail, string(key32(9))) {
					t.Fatal("key material in audit")
				}
			}
		})
	}
}

func TestUnavailableBeforeBootstrap(t *testing.T) {
	k := NewKubernetesKEK(fake.NewClientset(), "ns", fakeLister{}, &fakeAudit{})
	ctx := context.Background()
	if _, err := k.PrimaryID(ctx); !errors.Is(err, ErrKEKUnavailable) {
		t.Fatalf("PrimaryID err = %v", err)
	}
	if _, err := k.Wrap(ctx, key32(1), "s"); !errors.Is(err, ErrKEKUnavailable) {
		t.Fatalf("Wrap err = %v", err)
	}
}

func TestWrapUsesPrimary(t *testing.T) {
	cs := fake.NewClientset(kekSecret("kb", map[string][]byte{"ka": key32(1), "kb": key32(2)}))
	k := NewKubernetesKEK(cs, "ns", fakeLister{}, &fakeAudit{})
	ctx := context.Background()
	if err := k.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	dek := key32(7)
	w, err := k.Wrap(ctx, dek, "sub")
	if err != nil {
		t.Fatal(err)
	}
	if w.KEKID != "kb" {
		t.Fatalf("KEKID = %q", w.KEKID)
	}
	if _, err := UnwrapWithKey(key32(2), w.Ciphertext, "sub"); err != nil {
		t.Fatalf("not wrapped under primary: %v", err)
	}
	got, err := k.Unwrap(ctx, w, "sub")
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := k.Unwrap(ctx, w, "other"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong sub err = %v", err)
	}
}

func TestUnwrapUnknownID(t *testing.T) {
	cs := fake.NewClientset(kekSecret("ka", map[string][]byte{"ka": key32(1)}))
	k := NewKubernetesKEK(cs, "ns", fakeLister{}, &fakeAudit{})
	ctx := context.Background()
	if err := k.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	_, err := k.Unwrap(ctx, model.WrappedKey{KEKID: "kzz", Ciphertext: make([]byte, 60)}, "s")
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Fatalf("err = %v", err)
	}
	// A key added by another replica is found after one re-read.
	ct, _ := WrapWithKey(key32(3), key32(4), "s")
	sec, _ := cs.CoreV1().Secrets("ns").Get(ctx, kekSecretName, metav1.GetOptions{})
	sec.Data["kc"] = key32(3)
	if _, err := cs.CoreV1().Secrets("ns").Update(ctx, sec, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if got, err := k.Unwrap(ctx, model.WrappedKey{KEKID: "kc", Ciphertext: ct}, "s"); err != nil || !bytes.Equal(got, key32(4)) {
		t.Fatalf("re-read unwrap: %v", err)
	}
}

func TestAddKeyAndRetire(t *testing.T) {
	cs := fake.NewClientset(kekSecret("ka", map[string][]byte{"ka": key32(1)}))
	au := &fakeAudit{}
	k := NewKubernetesKEK(cs, "ns", fakeLister{}, au)
	ctx := context.Background()
	if err := k.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	id, err := k.AddKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := k.PrimaryID(ctx); p != id {
		t.Fatalf("primary %q, want %q", p, id)
	}
	id2, err := k.AddKey(ctx)
	if err != nil || id2 == id {
		t.Fatalf("second id %q err %v (first %q)", id2, err, id)
	}
	s, _ := cs.CoreV1().Secrets("ns").Get(ctx, kekSecretName, metav1.GetOptions{})
	if string(s.Data["primary"]) != id2 || len(s.Data[id]) != 32 || len(s.Data["ka"]) != 32 {
		t.Fatalf("secret state wrong: primary=%s", s.Data["primary"])
	}
	if len(au.events) != 0 {
		t.Fatalf("AddKey emitted %v", au.events)
	}
}

func TestAddKeyRetriesOnConflict(t *testing.T) {
	cs := fake.NewClientset(kekSecret("ka", map[string][]byte{"ka": key32(1)}))
	k := NewKubernetesKEK(cs, "ns", fakeLister{}, &fakeAudit{})
	ctx := context.Background()
	if err := k.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	n := 0
	cs.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		n++
		if n <= 2 {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, kekSecretName, errors.New("c"))
		}
		return false, nil, nil
	})
	if _, err := k.AddKey(ctx); err != nil {
		t.Fatal(err)
	}
	n = -100
	cs.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, kekSecretName, errors.New("c"))
	})
	if _, err := k.AddKey(ctx); err == nil {
		t.Fatal("expected error after 5 conflicts")
	}
}

func TestRetireRefusesPrimary(t *testing.T) {
	cs := fake.NewClientset(kekSecret("ka", map[string][]byte{"ka": key32(1)}))
	k := NewKubernetesKEK(cs, "ns", fakeLister{}, &fakeAudit{})
	ctx := context.Background()
	if err := k.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if err := k.Retire(ctx, "ka", func(context.Context) (map[string]int, error) { return nil, nil }); err == nil {
		t.Fatal("retired primary")
	}
}

func TestRetireRefusesInUse(t *testing.T) {
	tests := []struct {
		name    string
		inUse   map[string]int
		inErr   error
		id      string
		wantErr bool
		removed bool
	}{
		{name: "in use", inUse: map[string]int{"ka": 2}, id: "ka", wantErr: true},
		{name: "unused retired", inUse: map[string]int{"ka": 0}, id: "ka", removed: true},
		{name: "lookup error", inErr: errors.New("x"), id: "ka", wantErr: true},
		{name: "unknown id", id: "kzz", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewClientset(kekSecret("kb", map[string][]byte{"ka": key32(1), "kb": key32(2)}))
			au := &fakeAudit{}
			k := NewKubernetesKEK(cs, "ns", fakeLister{}, au)
			ctx := context.Background()
			if err := k.Bootstrap(ctx); err != nil {
				t.Fatal(err)
			}
			err := k.Retire(ctx, tc.id, func(context.Context) (map[string]int, error) { return tc.inUse, tc.inErr })
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			s, _ := cs.CoreV1().Secrets("ns").Get(ctx, kekSecretName, metav1.GetOptions{})
			if _, present := s.Data["ka"]; present == tc.removed {
				t.Fatalf("ka present = %v", present)
			}
			if tc.removed && (len(au.events) != 1 || au.events[0].event != "kek_retired" || au.events[0].detail != "ka") {
				t.Fatalf("events %v", au.events)
			}
			if !tc.removed && len(au.events) != 0 {
				t.Fatalf("events %v", au.events)
			}
		})
	}
}

func TestLivePrimary(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(t *testing.T, cs *fake.Clientset)
		wantID  string
		wantErr error
	}{
		{name: "external rotation", wantID: "k2", mutate: func(t *testing.T, cs *fake.Clientset) {
			if _, err := cs.CoreV1().Secrets("ns").Update(context.Background(),
				kekSecret("k2", map[string][]byte{"ka": key32(1), "k2": key32(2)}), metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unchanged", wantID: "ka", mutate: func(*testing.T, *fake.Clientset) {}},
		{name: "secret deleted", wantErr: ErrKEKUnavailable, mutate: func(t *testing.T, cs *fake.Clientset) {
			if err := cs.CoreV1().Secrets("ns").Delete(context.Background(), kekSecretName, metav1.DeleteOptions{}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "secret malformed", wantErr: ErrKEKUnavailable, mutate: func(t *testing.T, cs *fake.Clientset) {
			if _, err := cs.CoreV1().Secrets("ns").Update(context.Background(),
				kekSecret("ka", map[string][]byte{"ka": []byte("x")}), metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewClientset(kekSecret("ka", map[string][]byte{"ka": key32(1)}))
			k := NewKubernetesKEK(cs, "ns", fakeLister{}, &fakeAudit{})
			ctx := context.Background()
			if err := k.Bootstrap(ctx); err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, cs)
			w, err := k.Wrap(ctx, key32(7), "sub")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Wrap err = %v, want %v", err, tc.wantErr)
			}
			if err == nil && w.KEKID != tc.wantID {
				t.Fatalf("KEKID = %q, want %q", w.KEKID, tc.wantID)
			}
			id, err := k.PrimaryID(ctx)
			if !errors.Is(err, tc.wantErr) || id != tc.wantID {
				t.Fatalf("PrimaryID = %q, %v; want %q, %v", id, err, tc.wantID, tc.wantErr)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name     string
		existing *corev1.Secret
		wantErr  error
	}{
		{name: "present", existing: kekSecret("ka", map[string][]byte{"ka": key32(1)})},
		{name: "missing"},
		{name: "short key", existing: kekSecret("ka", map[string][]byte{"ka": []byte("short")}), wantErr: ErrKEKUnavailable},
		{name: "primary absent", existing: kekSecret("kb", map[string][]byte{"ka": key32(1)}), wantErr: ErrKEKUnavailable},
	}
	tests[1].wantErr = ErrKEKUnavailable
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewClientset()
			if tc.existing != nil {
				cs = fake.NewClientset(tc.existing)
			}
			writes := 0
			for _, verb := range []string{"create", "update"} {
				cs.PrependReactor(verb, "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
					writes++
					return false, nil, nil
				})
			}
			k := NewKubernetesKEK(cs, "ns", fakeLister{}, &fakeAudit{})
			err := k.Load(context.Background())
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if writes != 0 {
				t.Fatalf("Load wrote %d times", writes)
			}
			if tc.wantErr == nil {
				if id, err := k.PrimaryID(context.Background()); err != nil || id != "ka" {
					t.Fatalf("primary %q %v", id, err)
				}
			}
		})
	}
}
