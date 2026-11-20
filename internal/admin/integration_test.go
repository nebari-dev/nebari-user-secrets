//go:build integration

package admin

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
	"github.com/nebari-dev/nebari-user-secrets/internal/store"
	"github.com/nebari-dev/nebari-user-secrets/internal/testkube"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestKEKRotationOnKind: journey 21, store-level. Reads keep working during
// rotate-kek, and retire-kek succeeds afterwards.
func TestKEKRotationOnKind(t *testing.T) {
	ctx := context.Background()
	cs, ns := testkube.Namespace(t)
	st := store.NewKubernetesSecretStore(cs, ns, time.Now)
	a := &fakeAudit{}
	kek := crypto.NewKubernetesKEK(cs, ns, st, a)
	if err := kek.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	sealer := crypto.NewSealer(kek, rand.Reader)
	old, _ := kek.PrimaryID(ctx)
	subs := []string{"sub-0", "sub-1", "sub-2"}
	for _, s := range subs {
		writeRecord(t, st, sealer, s)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var failures, opens atomic.Int64
	var firstErr atomic.Value
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, s := range subs {
					rec, _, err := st.Get(ctx, s)
					if err == nil {
						for _, e := range rec.Secrets {
							if _, err = sealer.Open(ctx, rec, e); err != nil {
								break
							}
						}
					}
					opens.Add(1)
					if err != nil {
						failures.Add(1)
						firstErr.CompareAndSwap(nil, err.Error())
					}
				}
			}
		}()
	}

	rep, err := RotateKEK(ctx, st, kek, sealer, a, "admin")
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if failures.Load() != 0 {
		t.Fatalf("%d of %d opens failed during rotation, first: %v", failures.Load(), opens.Load(), firstErr.Load())
	}
	newID, _ := kek.PrimaryID(ctx)
	if rep.Rewrapped != 3 || len(rep.ByKEK) != 1 || rep.ByKEK[newID] != 3 {
		t.Fatalf("report %+v", rep)
	}
	if err := RetireKEK(ctx, st, kek, old); err != nil {
		t.Fatalf("retire after rotate: %v", err)
	}
	for _, s := range subs {
		rec, _, err := st.Get(ctx, s)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sealer.Open(ctx, rec, rec.Secrets[0]); err != nil {
			t.Fatalf("open after retire: %v", err)
		}
	}
	t.Logf("opens during rotation: %d", opens.Load())
}

// TestKEKMissingFailsClosed: with records present and the master-key Secret
// deleted, Bootstrap returns ErrKEKUnavailable and creates no Secret.
func TestKEKMissingFailsClosed(t *testing.T) {
	ctx := context.Background()
	cs, ns := testkube.Namespace(t)
	st := store.NewKubernetesSecretStore(cs, ns, time.Now)
	a := &fakeAudit{}
	kek := crypto.NewKubernetesKEK(cs, ns, st, a)
	if err := kek.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	writeRecord(t, st, crypto.NewSealer(kek, rand.Reader), "sub-0")
	if err := cs.CoreV1().Secrets(ns).Delete(ctx, "user-secrets-kek", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}

	fresh := crypto.NewKubernetesKEK(cs, ns, st, a)
	if err := fresh.Bootstrap(ctx); !errors.Is(err, crypto.ErrKEKUnavailable) {
		t.Fatalf("Bootstrap = %v, want ErrKEKUnavailable", err)
	}
	if _, err := cs.CoreV1().Secrets(ns).Get(ctx, "user-secrets-kek", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("master key Secret must not be recreated, got %v", err)
	}
	if a.count("kek_unavailable") != 1 {
		t.Fatalf("events %+v", a.events)
	}
}
