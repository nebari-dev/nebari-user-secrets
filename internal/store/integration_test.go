//go:build integration

package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func testNamespace(t *testing.T) (kubernetes.Interface, string) {
	t.Helper()
	cfg, err := clientcmd.BuildConfigFromFlags("", filepath.Join(repoRoot(t), ".kube", "kind"))
	if err != nil {
		t.Fatalf("kubeconfig (run make kind-up): %v", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	name := fmt.Sprintf("us-test-%d", time.Now().UnixNano())
	if _, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cs.CoreV1().Namespaces().Delete(context.Background(), name, metav1.DeleteOptions{})
	})
	return cs, name
}

// TestRecordsHoldNoPlaintext: journey 20. The raw Secret holds neither a
// value nor its base64.
func TestRecordsHoldNoPlaintext(t *testing.T) {
	ctx := context.Background()
	cs, ns := testNamespace(t)
	st := NewKubernetesSecretStore(cs, ns, time.Now)

	kek := crypto.NewMemoryKEK(map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)}, "k1")
	sealer := crypto.NewSealer(kek, rand.Reader)
	const sub = "f:ldap:alice"
	dk, err := sealer.NewDataKey(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	rec := &model.OwnerRecord{SchemaVersion: 1, OwnerSub: sub, OwnerUsername: "alice", DataKey: dk}
	plaintext := []byte("hunter2-very-secret-value")
	sealed, err := sealer.Seal(ctx, rec, "DB_PASSWORD", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	rec.Secrets = []model.SecretEntry{{Name: "DB_PASSWORD", Sealed: sealed}}
	if _, err := st.Put(ctx, rec, ""); err != nil {
		t.Fatal(err)
	}

	raw, err := cs.CoreV1().Secrets(ns).Get(ctx, model.SecretName(sub), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b64 := []byte(base64.StdEncoding.EncodeToString(plaintext))
	for k, v := range raw.Data {
		if bytes.Contains(v, plaintext) || bytes.Contains(v, b64) {
			t.Fatalf("data key %q holds the value or its base64", k)
		}
	}

	got, _, err := st.Get(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := sealer.Open(ctx, got, got.Secrets[0])
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("round trip failed: %v", err)
	}
}
