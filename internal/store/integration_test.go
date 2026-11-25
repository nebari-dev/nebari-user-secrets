//go:build integration

package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"github.com/nebari-dev/nebari-user-secrets/internal/testkube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// testNamespace is testkube.Namespace: the kind cluster from
// USER_SECRETS_TEST_KUBECONFIG or .kube/kind, and a throwaway namespace.
func testNamespace(t *testing.T) (kubernetes.Interface, string) {
	t.Helper()
	return testkube.Namespace(t)
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
