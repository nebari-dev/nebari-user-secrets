//go:build journeys

// Package journeys drives the chart installed through Argo CD on a real
// Nebari: the Tier 3 deployment of .github/workflows/journeys.yml. It reads
// KUBECONFIG, NEBARI_DOMAIN, KEYCLOAK_ISSUER (the nebari realm's issuer, the
// value of the chart's keycloak.issuers) and JOURNEY_USER/JOURNEY_PASSWORD
// (written by test/journeys/seed-keycloak.sh) from the environment.
package journeys

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Values shared with test/journeys/gitops, seed-keycloak.sh and NIC.
const (
	// serviceNS is the namespace cluster/ is built for and the chart's
	// Application deploys to.
	serviceNS   = "us-system"
	releaseName = "user-secrets"
	serviceHost = "user-secrets." + serviceNS + ".svc"
	tlsSecret   = "user-secrets-tls"
	guardState  = "user-secrets-guard-state"

	// NIC's trust bundle, projected into every namespace.
	bundleName = "nebari-trust-bundle"
	bundleKey  = "ca-certificates.crt"
	caIssuer   = "nebari-ca-issuer"

	// NIC's landing namespace, and the landing frontend's selector labels
	// that values-nebari.yaml admits to the management port. The proxy pod
	// leaves out app.kubernetes.io/instance so the landing frontend's own
	// Service does not select it.
	landingNS    = "nebari-system"
	landingProxy = "journeys-landing-proxy"
	socatImage   = "alpine/socat:1.8.1.1"

	// NIC's Keycloak Service (pkg/argocd/writer.go KeycloakServiceURL) and the
	// client and app the journeys use.
	keycloakNS   = "keycloak"
	keycloakSvc  = "svc/keycloak-keycloakx-http"
	keycloakPort = "8080"
	realm        = "nebari"
	clientID     = "user-secrets-journeys"
	consumerApp  = "test-consumer"

	argoNS = "argocd"
)

var landingLabels = map[string]string{
	"app.kubernetes.io/name":      "nebari-landing",
	"app.kubernetes.io/component": "frontend",
}

// mustEnv returns the environment variable key, failing the test when it is
// unset: every value comes from the Tier 3 workflow.
func mustEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Fatalf("%s is not set (the Tier 3 workflow sets it)", key)
	}
	return v
}

var restConfig = sync.OnceValues(func() (*rest.Config, error) {
	return clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
})

// kube returns a client for the Tier 3 cluster.
func kube(t *testing.T) *kubernetes.Clientset {
	t.Helper()
	rc, err := restConfig()
	if err != nil {
		t.Fatalf("kubeconfig: %v", err)
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		t.Fatalf("kube client: %v", err)
	}
	return cs
}

// dyn returns a dynamic client, for Argo CD and cert-manager resources.
func dyn(t *testing.T) *dynamic.DynamicClient {
	t.Helper()
	rc, err := restConfig()
	if err != nil {
		t.Fatalf("kubeconfig: %v", err)
	}
	d, err := dynamic.NewForConfig(rc)
	if err != nil {
		t.Fatalf("dynamic client: %v", err)
	}
	return d
}

// eventually calls check every 2 s until it returns nil or timeout passes,
// then fails with its last error.
func eventually(t *testing.T, timeout time.Duration, what string, check func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		err := check()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not within %s: %v", what, timeout, err)
		}
		time.Sleep(2 * time.Second)
	}
}

var forwardRE = regexp.MustCompile(`Forwarding from 127\.0\.0\.1:(\d+)`)

// portForward runs kubectl port-forward to port of target in ns for the rest
// of the test and returns the local port.
func portForward(t *testing.T, ns, target, port string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "kubectl", "-n", ns, "port-forward", target, ":"+port)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatalf("port-forward pipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("port-forward: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})
	portc := make(chan string, 1)
	go func() {
		defer close(portc)
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if m := forwardRE.FindStringSubmatch(sc.Text()); m != nil {
				portc <- m[1]
				break
			}
		}
		_, _ = io.Copy(io.Discard, stdout)
	}()
	select {
	case p, ok := <-portc:
		if !ok {
			_ = cmd.Wait()
			t.Fatalf("port-forward to %s/%s exited: %s", ns, target, stderr.String())
		}
		return p
	case <-time.After(30 * time.Second):
		t.Fatalf("port-forward to %s/%s did not start: %s", ns, target, stderr.String())
	}
	return ""
}

// userToken returns an access token for the journey user from the password
// grant of clientID, requested from Keycloak's in-cluster Service. Keycloak
// puts its configured external hostname in iss whichever address it is
// reached on.
func userToken(t *testing.T) string {
	t.Helper()
	port := portForward(t, keycloakNS, keycloakSvc, keycloakPort)
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {clientID},
		"username":   {mustEnv(t, "JOURNEY_USER")},
		"password":   {mustEnv(t, "JOURNEY_PASSWORD")},
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.PostForm("http://127.0.0.1:"+port+"/realms/"+realm+"/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("token response (HTTP %d): %v", resp.StatusCode, err)
	}
	if body.AccessToken == "" {
		t.Fatalf("no token for the journey user (HTTP %d): %s %s", resp.StatusCode, body.Error, body.Description)
	}
	return body.AccessToken
}

// tokenClaims are the claims the journeys read from their own token
// (unverified: the test only reads what Keycloak just issued it).
type tokenClaims struct {
	Iss string `json:"iss"`
	Azp string `json:"azp"`
	Sub string `json:"sub"`
}

func claims(t *testing.T, tok string) tokenClaims {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode token payload: %v", err)
	}
	var c tokenClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatalf("token payload: %v", err)
	}
	return c
}

// trustBundle returns a pool holding only nebari-trust-bundle's certificates
// as projected into ns (never the system pool), and the parsed certificates.
func trustBundle(t *testing.T, ns string) (*x509.CertPool, []*x509.Certificate) {
	t.Helper()
	cm, err := kube(t).CoreV1().ConfigMaps(ns).Get(context.Background(), bundleName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get %s/%s: %v", ns, bundleName, err)
	}
	certs := parseCerts(t, []byte(cm.Data[bundleKey]))
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, certs
}

// parseCerts decodes every CERTIFICATE block in pemData.
func parseCerts(t *testing.T, pemData []byte) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse certificate: %v", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		t.Fatal("no certificate in PEM data")
	}
	return out
}

// ensureLandingProxy starts (once per cluster) a pod in the landing
// namespace with the landing frontend's labels that forwards its :8444 to the
// service, the reach method of test/e2e: the chart's NetworkPolicy admits it
// to the management port.
func ensureLandingProxy(t *testing.T) {
	t.Helper()
	pods := kube(t).CoreV1().Pods(landingNS)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: landingProxy, Labels: landingLabels},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "socat",
				Image: socatImage,
				Args:  []string{"TCP-LISTEN:8444,fork,reuseaddr", "TCP:" + serviceHost + ":8444"},
				Ports: []corev1.ContainerPort{{ContainerPort: 8444}},
			}},
		},
	}
	_, err := pods.Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create %s/%s: %v", landingNS, landingProxy, err)
	}
	eventually(t, 3*time.Minute, landingProxy+" ready", func() error {
		p, err := pods.Get(context.Background(), landingProxy, metav1.GetOptions{})
		if err != nil {
			return err
		}
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				return nil
			}
		}
		return fmt.Errorf("phase %s", p.Status.Phase)
	})
}

// mgmtAPI calls the management API through a port-forward to the landing
// proxy, trusting only the trust bundle and checking the certificate for
// user-secrets.<ns>.svc, since the dial target is localhost.
type mgmtAPI struct {
	base   string
	client *http.Client
}

func mgmtClient(t *testing.T) *mgmtAPI {
	t.Helper()
	ensureLandingProxy(t)
	port := portForward(t, landingNS, "pod/"+landingProxy, "8444")
	pool, _ := trustBundle(t, landingNS)
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: serviceHost},
		DisableKeepAlives: true,
	}
	return &mgmtAPI{base: "https://127.0.0.1:" + port, client: &http.Client{Transport: tr, Timeout: 10 * time.Second}}
}

// do sends a request with the bearer token and a JSON body (when body is
// non-nil), failing the test on a transport error, and returns the status
// and response body.
func (m *mgmtAPI) do(t *testing.T, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, m.base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := m.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: read body: %v", method, path, err)
	}
	return resp.StatusCode, b
}
