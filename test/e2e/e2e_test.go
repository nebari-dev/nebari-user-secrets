//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"github.com/nebari-dev/nebari-user-secrets/internal/store"
)

// TestServiceReadyUnderPolicy: with the chart's NetworkPolicy in force (which
// admits only 8444 from the landing pods), every replica still passes the
// kubelet's readiness probe on 8080.
func TestServiceReadyUnderPolicy(t *testing.T) {
	ctx := context.Background()
	cs := kube(t)
	np, err := cs.NetworkingV1().NetworkPolicies(serviceNS).Get(ctx, "user-secrets", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("NetworkPolicy: %v", err)
	}
	in := np.Spec.Ingress
	if len(in) != 1 || len(in[0].Ports) != 1 {
		t.Fatalf("NetworkPolicy ingress = %+v, want one rule with one port", in)
	}
	if port := in[0].Ports[0].Port; port == nil || port.IntValue() != 8444 {
		t.Fatalf("NetworkPolicy ingress port = %v, want 8444 (a nil port admits every port)", port)
	}
	mustRun(t, 3*time.Minute, "kubectl", "-n", serviceNS, "rollout", "status", "deployment/user-secrets", "--timeout=150s")
	dep, err := cs.AppsV1().Deployments(serviceNS).Get(ctx, "user-secrets", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Deployment: %v", err)
	}
	probe := dep.Spec.Template.Spec.Containers[0].ReadinessProbe
	if probe == nil || probe.HTTPGet == nil || probe.HTTPGet.Port.IntValue() != 8080 {
		t.Fatalf("readiness probe = %+v, want httpGet on 8080", probe)
	}
	want := *dep.Spec.Replicas
	if dep.Status.ReadyReplicas != want {
		t.Fatalf("ready replicas = %d, want %d", dep.Status.ReadyReplicas, want)
	}
	sel := metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=user-secrets"}
	pods, err := cs.CoreV1().Pods(serviceNS).List(ctx, sel)
	if err != nil {
		t.Fatalf("pods: %v", err)
	}
	ready := 0
	for _, p := range pods.Items {
		for _, c := range p.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				ready++
			}
		}
	}
	if int32(ready) < want {
		t.Fatalf("%d pods Ready, want %d", ready, want)
	}
}

// TestServingCertChainsToNICRoot: the serving certificate verifies against
// the projected trust bundle for both Service names, and the root's name
// constraints are in force (a certificate the issuer signs for an outside
// name does not verify).
func TestServingCertChainsToNICRoot(t *testing.T) {
	ctx := context.Background()
	cs := kube(t)
	pool := trustBundle(t)

	sec, err := cs.CoreV1().Secrets(serviceNS).Get(ctx, "user-secrets-tls", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("user-secrets-tls: %v", err)
	}
	certs := parseCerts(t, sec.Data["tls.crt"])
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	for _, name := range []string{serviceHost, serviceHost + ".cluster.local"} {
		t.Run(name, func(t *testing.T) {
			if _, err := certs[0].Verify(x509.VerifyOptions{DNSName: name, Roots: pool, Intermediates: inter}); err != nil {
				t.Fatalf("verify serving certificate for %s: %v", name, err)
			}
		})
	}

	t.Run("root refuses probe.example.com", func(t *testing.T) {
		const probe = `apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: e2e-probe
  namespace: e2e-workload
spec:
  secretName: e2e-probe
  issuerRef:
    kind: ClusterIssuer
    name: nebari-ca-issuer
  dnsNames:
    - probe.example.com
`
		t.Cleanup(func() {
			_, _ = run(context.Background(), "kubectl", "-n", workloadNS, "delete", "certificate/e2e-probe",
				"secret/e2e-probe", "--ignore-not-found")
		})
		apply := mustRunStdin(t, probe, "kubectl", "apply", "-f", "-")
		t.Log(strings.TrimSpace(apply))
		mustRun(t, 2*time.Minute, "kubectl", "-n", workloadNS, "wait", "--for=condition=Ready",
			"certificate/e2e-probe", "--timeout=90s")
		ps, err := cs.CoreV1().Secrets(workloadNS).Get(ctx, "e2e-probe", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("e2e-probe secret: %v", err)
		}
		pc := parseCerts(t, ps.Data["tls.crt"])
		_, err = pc[0].Verify(x509.VerifyOptions{DNSName: "probe.example.com", Roots: pool})
		var inv x509.CertificateInvalidError
		if !errors.As(err, &inv) || inv.Reason != x509.CANotAuthorizedForThisName {
			t.Fatalf("verify probe.example.com: err = %v, want CertificateInvalidError CANotAuthorizedForThisName", err)
		}
	})
}

// mustRunStdin runs a command with stdin and fails the test on error.
func mustRunStdin(t *testing.T, stdin string, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := runStdin(ctx, stdin, name, args...)
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

type putBody struct {
	Description string          `json:"description"`
	ValueB64    string          `json:"value_b64"`
	Bindings    []model.Binding `json:"bindings"`
}

// TestManagementCreateList: journey 1, store a secret bound to an app and see
// it listed with its delivered name, never its value.
func TestManagementCreateList(t *testing.T) {
	api := mgmtClient(t)
	sub := uniqueSub("journey1")
	tok := signToken(t, sub, clientID)
	value := "vendor-" + rand.Text()

	status, body := api.mustDo(t, http.MethodPut, "/api/v1/secrets/vendor_key", tok, putBody{
		Description: "vendor API key",
		ValueB64:    base64.StdEncoding.EncodeToString([]byte(value)),
		Bindings:    []model.Binding{{App: "jupyter", Env: "VENDOR_KEY"}},
	})
	if status != http.StatusCreated {
		t.Fatalf("PUT status = %d, want 201; body %s", status, body)
	}
	if strings.Contains(string(body), value) {
		t.Fatal("PUT response contains the value")
	}

	status, body = api.mustDo(t, http.MethodGet, "/api/v1/secrets", tok, nil)
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
		App: "jupyter", Env: "VENDOR_KEY", Name: "NEBARI_SECRET_VENDOR_KEY",
		Path: "/var/run/nebari/secrets/NEBARI_SECRET_VENDOR_KEY",
	}
	if len(view.Secrets) != 1 || view.Secrets[0].Name != "vendor_key" ||
		len(view.Secrets[0].Bindings) != 1 || view.Secrets[0].Bindings[0] != want {
		t.Fatalf("secrets = %+v, want vendor_key bound as %+v", view.Secrets, want)
	}
	if view.Usage.Count != 1 {
		t.Fatalf("usage count = %d, want 1", view.Usage.Count)
	}
}

// TestManagementRejectsOtherClient: journey 8d, a token issued to any client
// other than the landing SPA is refused.
func TestManagementRejectsOtherClient(t *testing.T) {
	api := mgmtClient(t)
	tests := []struct {
		name       string
		azp        string
		wantStatus int
	}{
		{"landing client", clientID, http.StatusOK},
		{"other client", "other-client", http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := signToken(t, uniqueSub("journey8d"), tt.azp)
			status, body := api.mustDo(t, http.MethodGet, "/api/v1/secrets", tok, nil)
			if status != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", status, tt.wantStatus, body)
			}
			if tt.wantStatus == http.StatusUnauthorized && strings.TrimSpace(string(body)) != `{"error":"invalid_token"}` {
				t.Fatalf("body = %s, want invalid_token", body)
			}
		})
	}
}

// maxErrorStreak is how many List calls in a row (500 ms apart) may fail
// before the readiness observation counts as lost.
const maxErrorStreak = 10

// readyPoller counts the service's ready endpoints (replicas whose kubelet
// /readyz probe passes) every 500 ms and remembers the minimum over the
// successful observations. A failed List is counted, not fatal: a transient
// API-server error during the rollout says nothing about the replicas.
type readyPoller struct {
	mu   sync.Mutex
	st   pollStats
	stop chan struct{}
	done chan struct{}
}

// pollStats summarises a readiness poll.
type pollStats struct {
	samples   int   // successful observations
	minReady  int   // minimum ready endpoints seen; -1 before the first sample
	errors    int   // failed List calls
	maxStreak int   // longest run of consecutive failed List calls
	lastErr   error // most recent List error
}

func startReadyPoller(t *testing.T) *readyPoller {
	t.Helper()
	cs := kube(t)
	p := &readyPoller{st: pollStats{minReady: -1}, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		streak := 0
		for {
			n, err := readyEndpoints(cs.DiscoveryV1().EndpointSlices(serviceNS))
			p.mu.Lock()
			if err != nil {
				streak++
				p.st.errors++
				p.st.lastErr = err
				p.st.maxStreak = max(p.st.maxStreak, streak)
			} else {
				streak = 0
				p.st.samples++
				if p.st.minReady < 0 || n < p.st.minReady {
					p.st.minReady = n
				}
			}
			p.mu.Unlock()
			select {
			case <-p.stop:
				return
			case <-tick.C:
			}
		}
	}()
	return p
}

func (p *readyPoller) finish() pollStats {
	close(p.stop)
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.st
}

type sliceLister interface {
	List(ctx context.Context, opts metav1.ListOptions) (*discoveryv1.EndpointSliceList, error)
}

func readyEndpoints(l sliceLister) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	list, err := l.List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=user-secrets"})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range list.Items {
		for _, e := range s.Endpoints {
			if e.Conditions.Ready != nil && *e.Conditions.Ready {
				n++
			}
		}
	}
	return n, nil
}

type nopAuditor struct{}

func (nopAuditor) KeyEvent(context.Context, string, string, string, string) {}

// TestDurabilityAcrossRestart: journey 9, a stored value survives a rolling
// restart and a helm upgrade, and a replica stays ready throughout.
func TestDurabilityAcrossRestart(t *testing.T) {
	api := mgmtClient(t)
	sub := uniqueSub("journey9")
	tok := signToken(t, sub, clientID)
	value := "durable-" + rand.Text()

	status, body := api.mustDo(t, http.MethodPut, "/api/v1/secrets/durable_key", tok, putBody{
		ValueB64: base64.StdEncoding.EncodeToString([]byte(value)),
		Bindings: []model.Binding{{App: "jupyter", Env: "DURABLE_KEY"}},
	})
	if status != http.StatusCreated {
		t.Fatalf("PUT status = %d, want 201; body %s", status, body)
	}

	poller := startReadyPoller(t)
	mustRun(t, time.Minute, "kubectl", "-n", serviceNS, "rollout", "restart", "deployment/user-secrets")
	mustRun(t, 5*time.Minute, "kubectl", "-n", serviceNS, "rollout", "status", "deployment/user-secrets", "--timeout=280s")
	mustRun(t, 6*time.Minute, "helm", "upgrade", releaseName, chartDir, "--namespace", serviceNS,
		"--reuse-values", "--wait", "--timeout", "5m")
	ps := poller.finish()
	t.Logf("readiness: %d observations, minimum ready replicas %d, %d failed polls (longest streak %d, last error %v)",
		ps.samples, ps.minReady, ps.errors, ps.maxStreak, ps.lastErr)
	if ps.maxStreak >= maxErrorStreak {
		t.Fatalf("readiness unobserved for %d polls in a row: %v", ps.maxStreak, ps.lastErr)
	}
	if ps.samples < 2 || ps.minReady < 1 {
		t.Fatalf("readiness: %d observations, minimum %d ready replicas; want at least one ready throughout",
			ps.samples, ps.minReady)
	}

	status, body = api.mustDo(t, http.MethodGet, "/api/v1/secrets", tok, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"name":"durable_key"`) {
		t.Fatalf("GET after restart: status %d body %s", status, body)
	}

	// The value resolves through the store: read the owner record and open it
	// with the master key from user-secrets-kek, as a replica does.
	ctx := context.Background()
	cs := kube(t)
	st := store.NewKubernetesSecretStore(cs, serviceNS, time.Now)
	rec, _, err := st.Get(ctx, sub)
	if err != nil {
		t.Fatalf("store get: %v", err)
	}
	kek := crypto.NewKubernetesKEK(cs, serviceNS, st, nopAuditor{})
	if err := kek.Load(ctx); err != nil {
		t.Fatalf("load master key: %v", err)
	}
	sealer := crypto.NewSealer(kek, rand.Reader)
	var got []byte
	for _, e := range rec.Secrets {
		if e.Name == "durable_key" {
			if got, err = sealer.Open(ctx, rec, e); err != nil {
				t.Fatalf("open: %v", err)
			}
		}
	}
	if string(got) != value {
		t.Fatal("stored value did not survive the restart and upgrade")
	}
}

// TestNetworkExposure: journey 19, only the landing pods reach 8444. The
// control case pins the workload pod's timeout on the policy: the same pod
// reaches another in-cluster HTTPS Service.
func TestNetworkExposure(t *testing.T) {
	jwks := "jwks.e2e-keycloak.svc:443"
	mgmt := serviceHost + ":8444"
	tests := []struct {
		name        string
		namespace   string
		pod         string
		target      string
		wantConnect bool
	}{
		{"control: workload pod reaches the JWKS server", workloadNS, "workload-client", jwks, true},
		{"workload namespace is blocked", workloadNS, "workload-client", mgmt, false},
		{"landing pod connects", landingNS, "landing-proxy", mgmt, true},
		// Nothing listens on 8443 yet, so an admitted port would answer
		// "connection refused"; only a policy drop times out.
		{"landing pod is blocked from 8443", landingNS, "landing-proxy", serviceHost + ":8443", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			start := time.Now()
			out, err := run(ctx, "kubectl", "-n", tt.namespace, "exec", tt.pod, "--",
				"socat", "-u", "/dev/null", "TCP:"+tt.target+",connect-timeout=3")
			elapsed := time.Since(start)
			t.Logf("connect %s/%s -> %s: err=%v after %s: %s", tt.namespace, tt.pod, tt.target, err,
				elapsed.Round(time.Millisecond), strings.TrimSpace(out))
			if tt.wantConnect && err != nil {
				t.Fatalf("connect failed: %v: %s", err, out)
			}
			if !tt.wantConnect {
				if err == nil {
					t.Fatalf("connected to %s", tt.target)
				}
				if !strings.Contains(out, "timed out") {
					t.Fatalf("want a connect timeout (policy drop), got: %s", out)
				}
			}
		})
	}
}
