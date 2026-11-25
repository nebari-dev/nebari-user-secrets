//go:build e2e

// Package e2e drives the installed service on the kind cluster us-e2e that
// test/e2e/setup.sh (make e2e-up) builds.
package e2e

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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"github.com/nebari-dev/nebari-user-secrets/test/journeys/catalog"
)

// Values shared with test/e2e/setup.sh and test/e2e/fixtures.
const (
	serviceNS   = "us-system"
	landingNS   = "nebari-system"
	workloadNS  = "e2e-workload"
	releaseName = "user-secrets"
	serviceHost = "user-secrets." + serviceNS + ".svc"
	chartDir    = "../../chart"
	bundleName  = "nebari-trust-bundle"
	bundleKey   = "ca-certificates.crt"

	// Keycloak (test/e2e/fixtures/keycloak): the realm's in-cluster issuer,
	// the client the service accepts (keycloak.clientID), and the pod the
	// tests request tokens from.
	keycloakNS   = "e2e-keycloak"
	keycloakHost = "keycloak." + keycloakNS + ".svc:8443"
	issuer       = "https://" + keycloakHost + "/realms/nebari"
	clientID     = "user-secrets-e2e"
	tokenClient  = "kc-client"
	realmFile    = "test/e2e/fixtures/keycloak/realm.json"
)

// repoPath resolves a path relative to the repository root (tests run in
// test/e2e).
func repoPath(rel string) string {
	p, err := filepath.Abs(filepath.Join("..", "..", rel))
	if err != nil {
		panic(err)
	}
	return p
}

var pins = sync.OnceValues(func() (catalog.Pins, error) {
	f, err := os.Open(repoPath("ci/pins.env"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return catalog.LoadPins(f)
})

// pin returns key's value from ci/pins.env, the only place external versions
// are written. It panics if the file or the key is missing: no test can run
// without it.
func pin(key string) string {
	p, err := pins()
	if err != nil {
		panic(fmt.Sprintf("ci/pins.env: %v", err))
	}
	if p[key] == "" {
		panic("ci/pins.env has no " + key)
	}
	return p[key]
}

func kubeconfig() string {
	if p := os.Getenv("E2E_KUBECONFIG"); p != "" {
		return p
	}
	return repoPath(".kube/e2e")
}

var kubeClient = sync.OnceValues(func() (*kubernetes.Clientset, error) {
	rc, err := clientcmd.BuildConfigFromFlags("", kubeconfig())
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(rc)
})

// kube returns a client for us-e2e.
func kube(t *testing.T) *kubernetes.Clientset {
	t.Helper()
	cs, err := kubeClient()
	if err != nil {
		t.Fatalf("kube client (run make e2e-up first): %v", err)
	}
	return cs
}

// run executes a command with KUBECONFIG pointing at us-e2e and returns its
// combined output.
func run(ctx context.Context, name string, args ...string) (string, error) {
	return runStdin(ctx, "", name, args...)
}

// runStdin is run with stdin.
func runStdin(ctx context.Context, stdin, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig())
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// mustRun is run that fails the test on error.
func mustRun(t *testing.T, timeout time.Duration, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if out, err := run(ctx, name, args...); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// realmPassword returns user's password from the realm fixture (a fixture
// value, not a secret).
func realmPassword(t *testing.T, user string) string {
	t.Helper()
	raw, err := os.ReadFile(repoPath(realmFile))
	if err != nil {
		t.Fatalf("read %s: %v", realmFile, err)
	}
	var realm struct {
		Users []struct {
			Username    string `json:"username"`
			Credentials []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"credentials"`
		} `json:"users"`
	}
	if err := json.Unmarshal(raw, &realm); err != nil {
		t.Fatalf("decode %s: %v", realmFile, err)
	}
	for _, u := range realm.Users {
		if u.Username != user {
			continue
		}
		for _, c := range u.Credentials {
			if c.Type == "password" {
				return c.Value
			}
		}
	}
	t.Fatalf("%s has no password for user %s", realmFile, user)
	return ""
}

// userToken returns an access token Keycloak issues to user for client by the
// password grant, requested from inside the cluster (kubectl exec in
// kc-client, trusting only the projected trust bundle).
func userToken(t *testing.T, user, client string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := run(ctx, "kubectl", "-n", keycloakNS, "exec", tokenClient, "--",
		"curl", "-sS", "--max-time", "20", "--cacert", "/etc/nebari/trust/"+bundleKey,
		"--data-urlencode", "grant_type=password",
		"--data-urlencode", "client_id="+client,
		"--data-urlencode", "username="+user,
		"--data-urlencode", "password="+realmPassword(t, user),
		issuer+"/protocol/openid-connect/token")
	if err != nil {
		t.Fatalf("token request for %s/%s (run make e2e-up first): %v\n%s", user, client, err, out)
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("token response for %s/%s: %v", user, client, err)
	}
	if resp.AccessToken == "" {
		t.Fatalf("no token for %s/%s: %s %s", user, client, resp.Error, resp.Description)
	}
	return resp.AccessToken
}

// tokenSub returns the sub claim of tok (unverified: the test only reads its
// own token).
func tokenSub(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode token payload: %v", err)
	}
	var c struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &c); err != nil || c.Sub == "" {
		t.Fatalf("token payload has no sub: %v", err)
	}
	return c.Sub
}

// freshUser returns a management token and the subject for user, after
// deleting user's owner record and status Secrets (what the store's Delete
// removes), so the test starts from an empty record as a new user would. The
// realm's users are fixed, so this replaces a fresh subject per test.
func freshUser(t *testing.T, user string) (tok, sub string) {
	t.Helper()
	tok = userToken(t, user, clientID)
	sub = tokenSub(t, tok)
	secrets := kube(t).CoreV1().Secrets(serviceNS)
	for _, name := range []string{model.SecretName(sub), model.StatusSecretName(sub)} {
		err := secrets.Delete(context.Background(), name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			t.Fatalf("delete %s/%s: %v", serviceNS, name, err)
		}
	}
	return tok, sub
}

// trustBundle returns a pool holding only ca-certificates.crt from
// nebari-trust-bundle in the landing namespace (never the system pool).
func trustBundle(t *testing.T) *x509.CertPool {
	t.Helper()
	cm, err := kube(t).CoreV1().ConfigMaps(landingNS).Get(context.Background(), bundleName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get %s/%s: %v", landingNS, bundleName, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cm.Data[bundleKey])) {
		t.Fatalf("%s/%s key %s holds no certificate", landingNS, bundleName, bundleKey)
	}
	return pool
}

// mgmtAPI calls the management API through a port-forward to the landing
// proxy pod, which the NetworkPolicy admits to 8444.
type mgmtAPI struct {
	base   string
	client *http.Client
}

var forwardRE = regexp.MustCompile(`Forwarding from 127\.0\.0\.1:(\d+)`)

// mgmtClient port-forwards to the landing proxy and returns a client that
// trusts only the cluster's trust bundle and checks the certificate for
// user-secrets.<ns>.svc, since the dial target is localhost.
func mgmtClient(t *testing.T) *mgmtAPI {
	t.Helper()
	return portForwardMgmt(t, landingNS, "pod/landing-proxy", false)
}

// portForwardMgmt port-forwards local to port 8444 of target in namespace ns
// and returns a management API client for it, trusting only the cluster's
// trust bundle and checking the certificate for user-secrets.<ns>.svc.
//
// keepAlive selects connection reuse. Pass true for a forward pinned to one
// pod and polled repeatedly: with a new TLS connection per poll, each client
// close_notify lands after the server closed, the pod sends a RST, and rarely
// that kills kubectl port-forward ("lost connection to pod"): containerd
// reports the reset as a forward error and client-go closes the whole forward.
// Pass false for the landing-proxy path so each request re-picks a backend.
func portForwardMgmt(t *testing.T, ns, target string, keepAlive bool) *mgmtAPI {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "kubectl", "-n", ns, "port-forward", target, ":8444")
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig())
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
	// portc gets the local port, or is closed if kubectl exits first.
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
	var port string
	select {
	case p, ok := <-portc:
		if !ok {
			_ = cmd.Wait()
			t.Fatalf("port-forward exited: %s", stderr.String())
		}
		port = p
	case <-time.After(30 * time.Second):
		t.Fatalf("port-forward did not start: %s", stderr.String())
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    trustBundle(t),
			ServerName: serviceHost,
		},
		DisableKeepAlives: !keepAlive,
	}
	return &mgmtAPI{base: "https://127.0.0.1:" + port, client: &http.Client{Transport: tr, Timeout: 10 * time.Second}}
}

// do sends a request with the bearer token and a JSON body (when body is
// non-nil) and returns the status and response body.
func (m *mgmtAPI) do(method, path, token string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, m.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

// mustDo is do that fails the test on a transport error.
func (m *mgmtAPI) mustDo(t *testing.T, method, path, token string, body any) (int, []byte) {
	t.Helper()
	status, b, err := m.do(method, path, token, body)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return status, b
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
