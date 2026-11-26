//go:build journeys

package journeys

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

var (
	applicationGVR = schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"}
	certificateGVR = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
)

// guardTimeout bounds the guard's first verified evaluation after the
// cluster bundle synced.
const guardTimeout = 2 * time.Minute

// TestChartConvergesOnNebari: platform check P3.1. The chart and the cluster
// bundle, installed through NIC's root App-of-Apps, converge on a real
// Nebari: both Applications Synced and Healthy, the service Available with a
// serving certificate from NIC's cluster CA that chains to the trust bundle,
// and the admission guard verified.
func TestChartConvergesOnNebari(t *testing.T) {
	tests := []struct {
		name  string
		check func(t *testing.T)
	}{
		{"Application user-secrets Synced and Healthy", applicationConverged("user-secrets")},
		{"Application user-secrets-cluster Synced and Healthy", applicationConverged("user-secrets-cluster")},
		{"Deployment Available", deploymentAvailable},
		{"Certificate Ready from " + caIssuer, certificateFromCAIssuer},
		{"serving certificate chains to the trust bundle", servingCertChains},
		{"guard verified", guardVerified},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.check)
	}
}

// applicationConverged returns a check that the Argo CD Application name is
// Synced and Healthy.
func applicationConverged(name string) func(t *testing.T) {
	return func(t *testing.T) {
		app, err := dyn(t).Resource(applicationGVR).Namespace(argoNS).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get Application %s: %v", name, err)
		}
		sync, _, _ := unstructured.NestedString(app.Object, "status", "sync", "status")
		health, _, _ := unstructured.NestedString(app.Object, "status", "health", "status")
		if sync != "Synced" || health != "Healthy" {
			t.Fatalf("Application %s is %s/%s, want Synced/Healthy", name, sync, health)
		}
	}
}

func deploymentAvailable(t *testing.T) {
	dep, err := kube(t).AppsV1().Deployments(serviceNS).Get(context.Background(), releaseName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get Deployment %s/%s: %v", serviceNS, releaseName, err)
	}
	for _, c := range dep.Status.Conditions {
		if c.Type == appsv1.DeploymentAvailable && c.Status == corev1.ConditionTrue {
			return
		}
	}
	t.Fatalf("Deployment %s/%s is not Available: %+v", serviceNS, releaseName, dep.Status.Conditions)
}

func certificateFromCAIssuer(t *testing.T) {
	certs := dyn(t).Resource(certificateGVR).Namespace(serviceNS)
	cert, err := certs.Get(context.Background(), tlsSecret, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get Certificate %s/%s: %v", serviceNS, tlsSecret, err)
	}
	kind, _, _ := unstructured.NestedString(cert.Object, "spec", "issuerRef", "kind")
	name, _, _ := unstructured.NestedString(cert.Object, "spec", "issuerRef", "name")
	if kind != "ClusterIssuer" || name != caIssuer {
		t.Errorf("issuerRef = %s/%s, want ClusterIssuer/%s", kind, name, caIssuer)
	}
	conds, _, _ := unstructured.NestedSlice(cert.Object, "status", "conditions")
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m["type"] == "Ready" && m["status"] == "True" {
			return
		}
	}
	t.Fatalf("Certificate %s/%s is not Ready: %v", serviceNS, tlsSecret, conds)
}

// servingCertChains checks the Secret's public parts only: its ca.crt is a
// certificate of the trust bundle in the service namespace, and its leaf
// verifies against that bundle alone for the Service name clients dial.
func servingCertChains(t *testing.T) {
	sec, err := kube(t).CoreV1().Secrets(serviceNS).Get(context.Background(), tlsSecret, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get Secret %s/%s: %v", serviceNS, tlsSecret, err)
	}
	pool, bundle := trustBundle(t, serviceNS)
	ca := parseCerts(t, sec.Data["ca.crt"])
	root := ca[len(ca)-1]
	inBundle := false
	for _, b := range bundle {
		if bytes.Equal(b.Raw, root.Raw) {
			inBundle = true
			break
		}
	}
	if !inBundle {
		t.Errorf("ca.crt root %q is not in %s/%s", root.Subject, serviceNS, bundleName)
	}
	chain := parseCerts(t, sec.Data["tls.crt"])
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, DNSName: serviceHost}); err != nil {
		t.Fatalf("serving certificate does not verify against %s for %s: %v", bundleName, serviceHost, err)
	}
}

// guardVerified waits for the guard-state ConfigMap to record a verified
// evaluation: verifiedSince is written only after the guard's probes passed,
// and badMarker is present while a replica has seen confirmed_bad since.
func guardVerified(t *testing.T) {
	cms := kube(t).CoreV1().ConfigMaps(serviceNS)
	eventually(t, guardTimeout, guardState+" verified", func() error {
		cm, err := cms.Get(context.Background(), guardState, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("%s/%s not created yet", serviceNS, guardState)
		}
		if err != nil {
			return err
		}
		if _, err := time.Parse(time.RFC3339, cm.Data["verifiedSince"]); err != nil {
			return fmt.Errorf("verifiedSince %q: %w", cm.Data["verifiedSince"], err)
		}
		if _, bad := cm.Data["badMarker"]; bad {
			return fmt.Errorf("badMarker present")
		}
		return nil
	})
}

type putBody struct {
	Description string          `json:"description"`
	ValueB64    string          `json:"value_b64"`
	Bindings    []model.Binding `json:"bindings"`
}

// TestManagementOnNebari: journey check J1.3. A user of the Nebari realm,
// with a token from Keycloak's password grant for the chart's client, stores
// vendor_key bound to an app and lists it with its binding, through a pod in
// the landing namespace that carries the landing frontend's labels. Neither
// response contains the value.
func TestManagementOnNebari(t *testing.T) {
	issuer := mustEnv(t, "KEYCLOAK_ISSUER")
	domain := mustEnv(t, "NEBARI_DOMAIN")
	tok := userToken(t)
	c := claims(t, tok)
	if want := "https://keycloak." + domain + "/realms/" + realm; issuer != want {
		t.Fatalf("KEYCLOAK_ISSUER = %q, want %q for domain %s", issuer, want, domain)
	}
	if c.Iss != issuer || c.Azp != clientID || c.Sub == "" {
		t.Fatalf("token iss/azp/sub = %q/%q/%q, want %q/%q/non-empty", c.Iss, c.Azp, c.Sub, issuer, clientID)
	}

	// Start from an empty record, as a new user would, also on a rerun
	// against a kept cluster.
	secrets := kube(t).CoreV1().Secrets(serviceNS)
	for _, name := range []string{model.SecretName(c.Sub), model.StatusSecretName(c.Sub)} {
		err := secrets.Delete(context.Background(), name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			t.Fatalf("delete %s/%s: %v", serviceNS, name, err)
		}
	}

	api := mgmtClient(t)
	value := "vendor-" + rand.Text()
	status, body := api.do(t, http.MethodPut, "/api/v1/secrets/vendor_key", tok, putBody{
		Description: "vendor API key",
		ValueB64:    base64.StdEncoding.EncodeToString([]byte(value)),
		Bindings:    []model.Binding{{App: consumerApp, Env: "VENDOR_KEY"}},
	})
	if status != http.StatusCreated {
		t.Fatalf("PUT status = %d, want 201; body %s", status, body)
	}
	if strings.Contains(string(body), value) {
		t.Fatal("PUT response contains the value")
	}

	status, body = api.do(t, http.MethodGet, "/api/v1/secrets", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("GET status = %d, want 200; body %s", status, body)
	}
	if strings.Contains(string(body), value) {
		t.Fatal("GET response contains the value")
	}
	var view model.OwnerView
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode OwnerView: %v; body %s", err, body)
	}
	want := model.BindingView{
		App: consumerApp, Env: "VENDOR_KEY", Name: "NEBARI_SECRET_VENDOR_KEY",
		Path: "/var/run/nebari/secrets/NEBARI_SECRET_VENDOR_KEY",
	}
	if len(view.Secrets) != 1 || view.Secrets[0].Name != "vendor_key" ||
		len(view.Secrets[0].Bindings) != 1 || view.Secrets[0].Bindings[0] != want {
		t.Fatalf("secrets = %+v, want vendor_key bound as %+v", view.Secrets, want)
	}
}
