//go:build integration

// Package testkube gives integration tests a client for the kind cluster and a
// throwaway namespace.
package testkube

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// Namespace returns a client for the kind cluster and a new namespace that is
// deleted when the test ends.
func Namespace(t *testing.T) (kubernetes.Interface, string) {
	t.Helper()
	cfg, err := clientcmd.BuildConfigFromFlags("", filepath.Join(repoRoot(t), ".kube", "kind"))
	if err != nil {
		t.Fatalf("kubeconfig (run make kind-up): %v", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("us-test-%d", time.Now().UnixNano())
	if _, err := cs.CoreV1().Namespaces().Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cs.CoreV1().Namespaces().Delete(context.Background(), name, metav1.DeleteOptions{})
	})
	return cs, name
}
