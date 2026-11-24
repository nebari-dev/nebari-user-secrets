//go:build e2e

// Package e2e drives the installed service on the kind cluster us-e2e that
// test/e2e/setup.sh (make e2e-up) builds.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Values shared with test/e2e/setup.sh and test/e2e/fixtures.
const (
	serviceNS   = "us-system"
	landingNS   = "nebari-system"
	workloadNS  = "e2e-workload"
	releaseName = "user-secrets"
	issuer      = "https://keycloak.nebari.local/realms/nebari"
	clientID    = "nebari-landing"
	signingKID  = "e2e-1"
	serviceHost = "user-secrets." + serviceNS + ".svc"
	chartDir    = "../../chart"
	bundleName  = "nebari-trust-bundle"
	bundleKey   = "ca-certificates.crt"
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

var signingKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(repoPath("test/e2e/.tmp/signing-key.pem"))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("signing key: no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key is %T, want RSA", k)
	}
	return rk, nil
})

// signToken returns an RS256 access token shaped like Keycloak's for sub,
// issued to client azp, signed with the key the JWKS server publishes.
func signToken(t *testing.T, sub, azp string) string {
	t.Helper()
	key, err := signingKey()
	if err != nil {
		t.Fatalf("signing key (run make e2e-up first): %v", err)
	}
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), signingKID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, opts)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	now := time.Now()
	claims := struct {
		jwt.Claims
		Typ               string   `json:"typ"`
		Azp               string   `json:"azp"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}{
		Claims: jwt.Claims{
			Issuer:    issuer,
			Subject:   sub,
			Audience:  jwt.Audience{"account"},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
			Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
		Typ:               "Bearer",
		Azp:               azp,
		PreferredUsername: sub,
		Groups:            []string{"users"},
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
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
	return portForwardMgmt(t, landingNS, "pod/landing-proxy")
}

// portForwardMgmt port-forwards local to port 8444 of target in namespace ns
// and returns a management API client for it, trusting only the cluster's
// trust bundle and checking the certificate for user-secrets.<ns>.svc.
func portForwardMgmt(t *testing.T, ns, target string) *mgmtAPI {
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
		DisableKeepAlives: true,
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

// uniqueSub returns a subject that no earlier run used, so reruns against the
// same cluster start from an empty record.
func uniqueSub(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
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
