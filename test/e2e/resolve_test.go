//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

// Values shared with test/e2e/fixtures/consumer.yaml and values-consumer.yaml.
const (
	consumerNS  = "test-consumer"
	consumerApp = "test-consumer"
	otherApp    = "notebook"
	workloadSA  = "tc-workload"
	creatorUser = "system:serviceaccount:test-consumer:tc-creator"

	// curlImage is curlimages/curl 8.22.0 pinned by the digest of its
	// multi-arch manifest list (skopeo inspect --raw
	// docker://docker.io/curlimages/curl:8.22.0 | sha256sum, 2026-11-24).
	curlImage = "docker.io/curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777"

	tokenDir  = "/var/run/secrets/user-secrets"
	bundleDir = "/etc/nebari/trust"
	// podTimeout bounds a consumer pod's start (image pull on a fresh
	// cluster) and its one resolve call.
	podTimeout = 3 * time.Minute
)

// resolveScript calls the resolve API once over HTTP/1.1, trusting only the
// mounted trust bundle, and prints the body, then HTTP_STATUS:<code> and
// CURL_EXIT:<code>. With the argument "stdin" it sends the token read from
// stdin instead of the pod's projected token.
const resolveScript = `
if [ "${1:-}" = stdin ]; then tok=$(cat); else tok=$(cat ` + tokenDir + `/token); fi
curl -sS --http1.1 --max-time 20 --cacert ` + bundleDir + `/` + bundleKey + ` -X POST \
  -H "Authorization: Bearer $tok" -w '\nHTTP_STATUS:%{http_code}\n' \
  https://` + serviceHost + `:8443/api/v1/resolve
echo "CURL_EXIT:$?"
`

// podMode is how a consumer pod runs: once calls resolve at start and exits;
// wait sleeps so the test can call resolve with kubectl exec.
type podMode int

const (
	modeOnce podMode = iota
	modeWait
)

// consumerPod is a pod in the consumer namespace running as the registered
// workload ServiceAccount with a kubelet-minted token for audience
// user-secrets and the trust bundle mounted. labelled adds the label and both
// annotations for sub and app.
func consumerPod(sub, app string, labelled bool, mode podMode) *corev1.Pod {
	cmd := []string{"sh", "-c", resolveScript}
	if mode == modeWait {
		cmd = []string{"sh", "-c", "sleep 900"}
	}
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "tc-", Namespace: consumerNS},
		Spec: corev1.PodSpec{
			ServiceAccountName:            workloadSA,
			AutomountServiceAccountToken:  ptr.To(false),
			RestartPolicy:                 corev1.RestartPolicyNever,
			TerminationGracePeriodSeconds: ptr.To(int64(0)),
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   ptr.To(true),
				RunAsUser:      ptr.To(int64(65532)),
				RunAsGroup:     ptr.To(int64(65532)),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name:    "curl",
				Image:   curlImage,
				Command: cmd,
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: ptr.To(false),
					ReadOnlyRootFilesystem:   ptr.To(true),
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "token", MountPath: tokenDir, ReadOnly: true},
					{Name: "trust", MountPath: bundleDir, ReadOnly: true},
				},
			}},
			Volumes: []corev1.Volume{
				{Name: "token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
						Audience: "user-secrets", ExpirationSeconds: ptr.To(int64(600)), Path: "token",
					}}},
				}}},
				{Name: "trust", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: bundleName},
				}}},
			},
		},
	}
	if labelled {
		p.Labels = map[string]string{"nebari.dev/user-secrets": "true"}
		p.Annotations = map[string]string{"nebari.dev/user-secrets-sub": sub, "nebari.dev/user-secrets-app": app}
	}
	return p
}

// creatorKube returns a client that impersonates the registered creator, so
// policy B sees its username on the pod create.
func creatorKube(t *testing.T) *kubernetes.Clientset {
	t.Helper()
	rc, err := clientcmd.BuildConfigFromFlags("", kubeconfig())
	if err != nil {
		t.Fatalf("kube config: %v", err)
	}
	rc.Impersonate = rest.ImpersonationConfig{UserName: creatorUser}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		t.Fatalf("creator client: %v", err)
	}
	return cs
}

// startPod creates pod with cs and deletes it when the test ends. A labelled
// pod must be created with creatorKube.
func startPod(t *testing.T, cs *kubernetes.Clientset, pod *corev1.Pod) *corev1.Pod {
	t.Helper()
	p, err := cs.CoreV1().Pods(consumerNS).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create consumer pod: %v", err)
	}
	t.Cleanup(func() {
		_ = kube(t).CoreV1().Pods(consumerNS).Delete(context.Background(), p.Name,
			metav1.DeleteOptions{GracePeriodSeconds: ptr.To(int64(0))})
	})
	return p
}

// waitPod polls the pod until done reports true, failing after podTimeout.
func waitPod(t *testing.T, name string, done func(*corev1.Pod) bool) {
	t.Helper()
	deadline := time.Now().Add(podTimeout)
	var last *corev1.Pod
	for time.Now().Before(deadline) {
		p, err := kube(t).CoreV1().Pods(consumerNS).Get(context.Background(), name, metav1.GetOptions{})
		if err == nil {
			last = p
			if done(p) {
				return
			}
		}
		time.Sleep(time.Second)
	}
	if last != nil {
		t.Fatalf("pod %s: phase %s within %s; statuses %+v", name, last.Status.Phase, podTimeout,
			last.Status.ContainerStatuses)
	}
	t.Fatalf("pod %s not found within %s", name, podTimeout)
}

// resolveResult is one resolve call as the consumer pod saw it. body may hold
// values: tests compare it and never print it.
type resolveResult struct {
	status   int
	curlExit int
	body     []byte
}

// response decodes the body.
func (r resolveResult) response(t *testing.T) resolveBody {
	t.Helper()
	var b resolveBody
	if err := json.Unmarshal(r.body, &b); err != nil {
		t.Fatalf("decode resolve body (%d bytes, status %d): %v", len(r.body), r.status, err)
	}
	return b
}

type resolveBody struct {
	Secrets []struct {
		Env      string `json:"env"`
		ValueB64 string `json:"value_b64"`
	} `json:"secrets"`
	Error string `json:"error"`
}

// envs returns the delivered names, for messages (never the values).
func (b resolveBody) envs() []string {
	out := make([]string, 0, len(b.Secrets))
	for _, s := range b.Secrets {
		out = append(out, s.Env)
	}
	return out
}

// parseResolveOutput reads the output of resolveScript. Lines other than the
// body and the two markers (curl's own errors) are kept out of the body.
func parseResolveOutput(t *testing.T, out string) resolveResult {
	t.Helper()
	r := resolveResult{status: -1, curlExit: -1}
	var body []string
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "HTTP_STATUS:"):
			r.status, _ = strconv.Atoi(strings.TrimPrefix(line, "HTTP_STATUS:"))
		case strings.HasPrefix(line, "CURL_EXIT:"):
			r.curlExit, _ = strconv.Atoi(strings.TrimPrefix(line, "CURL_EXIT:"))
		case strings.HasPrefix(line, "{"):
			body = append(body, line)
		case strings.TrimSpace(line) != "":
			// curl's -S error text carries no value.
			t.Logf("curl: %s", line)
		}
	}
	r.body = []byte(strings.Join(body, "\n"))
	if r.curlExit != 0 || r.status < 0 {
		t.Fatalf("resolve call failed: curl exit %d, HTTP status %d", r.curlExit, r.status)
	}
	return r
}

// resolveOnce creates a modeOnce pod with cs, waits for it to finish and
// returns its call from the pod log.
func resolveOnce(t *testing.T, cs *kubernetes.Clientset, pod *corev1.Pod) (*corev1.Pod, resolveResult) {
	t.Helper()
	p := startPod(t, cs, pod)
	waitPod(t, p.Name, func(p *corev1.Pod) bool {
		return p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed
	})
	raw, err := kube(t).CoreV1().Pods(consumerNS).GetLogs(p.Name, &corev1.PodLogOptions{Container: "curl"}).
		DoRaw(context.Background())
	if err != nil {
		t.Fatalf("logs of %s: %v", p.Name, err)
	}
	return p, parseResolveOutput(t, string(raw))
}

// startWaitingPod creates a modeWait pod with cs and waits until it runs.
func startWaitingPod(t *testing.T, cs *kubernetes.Clientset, pod *corev1.Pod) *corev1.Pod {
	t.Helper()
	p := startPod(t, cs, pod)
	waitPod(t, p.Name, func(p *corev1.Pod) bool {
		for _, c := range p.Status.ContainerStatuses {
			if c.Ready {
				return true
			}
		}
		return p.Status.Phase == corev1.PodFailed
	})
	return p
}

// execResolve runs resolveScript in a waiting pod with kubectl exec. A
// non-empty token is sent on stdin in place of the pod's projected token.
func execResolve(t *testing.T, pod, token string) resolveResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	args := []string{"-n", consumerNS, "exec", pod, "-c", "curl", "--", "sh", "-c", resolveScript, "sh"}
	if token != "" {
		args = []string{"-n", consumerNS, "exec", "-i", pod, "-c", "curl", "--", "sh", "-c", resolveScript, "sh", "stdin"}
	}
	out, err := runStdin(ctx, token, "kubectl", args...)
	if err != nil {
		t.Fatalf("kubectl exec in %s: %v", pod, err)
	}
	return parseResolveOutput(t, out)
}

// readyForPods waits until every replica reports verified and the API-server
// clock has passed verifiedSince, so a pod created now is not refused as
// pod_predates_guard (verifiedSince carries a 30 s margin into the future
// when it moves). It returns the replicas and a management token for the
// status route.
func readyForPods(t *testing.T) ([]replica, string) {
	t.Helper()
	reps := guardReplicas(t)
	tok := signToken(t, uniqueSub("resolve"), clientID)
	waitGuard(t, reps, tok, stateVerified, baselineTimeout)
	waitPastVerifiedSince(t)
	return reps, tok
}

// waitPastVerifiedSince sleeps until the stored verifiedSince is more than a
// second in the past (creationTimestamp and verifiedSince are compared at
// whole seconds, and kind's API server shares this host's clock).
func waitPastVerifiedSince(t *testing.T) {
	t.Helper()
	vs := guardStateVerifiedSince(t)
	if vs.IsZero() {
		t.Fatalf("%s has no verifiedSince while verified", guardStateName)
	}
	wait := time.Until(vs.Add(1500 * time.Millisecond))
	if wait > time.Minute {
		t.Fatalf("verifiedSince %s is more than a minute ahead", vs.Format(time.RFC3339))
	}
	if wait > 0 {
		t.Logf("waiting %s for verifiedSince %s to pass", wait.Round(time.Second), vs.Format(time.RFC3339))
		time.Sleep(wait)
	}
}

// testSecret is a secret a test stores and expects (or does not expect) to
// resolve.
type testSecret struct {
	name     string
	value    string
	bindings []model.Binding
}

// newSecret returns a secret with a fresh random value.
func newSecret(name string, bindings ...model.Binding) testSecret {
	return testSecret{name: name, value: name + "-" + rand.Text(), bindings: bindings}
}

func bind(app, env string) model.Binding { return model.Binding{App: model.AppID(app), Env: env} }

// putSecrets stores the secrets for the token's user through the management
// API.
func putSecrets(t *testing.T, api *mgmtAPI, tok string, secrets ...testSecret) {
	t.Helper()
	for _, s := range secrets {
		status, body := api.mustDo(t, http.MethodPut, "/api/v1/secrets/"+s.name, tok, putBody{
			ValueB64: base64.StdEncoding.EncodeToString([]byte(s.value)),
			Bindings: s.bindings,
		})
		if status != http.StatusCreated {
			t.Fatalf("PUT %s: status %d, want 201; body %s", s.name, status, body)
		}
	}
}

// wantDelivered returns the env -> base64 value map a test-consumer pod
// should get from secrets.
func wantDelivered(secrets ...testSecret) map[string]string {
	out := map[string]string{}
	for _, s := range secrets {
		for _, b := range s.bindings {
			if string(b.App) == consumerApp {
				out[model.DeliveredName(b.Env)] = base64.StdEncoding.EncodeToString([]byte(s.value))
			}
		}
	}
	return out
}

// checkSecrets requires a 200 whose secrets are exactly want (names and
// values) and that carries none of the values in forbidden, in plain or
// base64 form. Messages name envs, never values.
func checkSecrets(t *testing.T, r resolveResult, want map[string]string, forbidden ...testSecret) {
	t.Helper()
	b := r.response(t)
	if r.status != http.StatusOK {
		t.Fatalf("resolve status %d (error %q), want 200", r.status, b.Error)
	}
	if b.Secrets == nil {
		t.Fatal("resolve body has no secrets array")
	}
	got := map[string]string{}
	for _, s := range b.Secrets {
		got[s.Env] = s.ValueB64
	}
	if len(got) != len(b.Secrets) {
		t.Errorf("duplicate env in %v", b.envs())
	}
	if !slices.Equal(slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want))) {
		t.Fatalf("delivered %v, want %v", b.envs(), slices.Sorted(maps.Keys(want)))
	}
	for env, v := range want {
		if got[env] != v {
			t.Errorf("%s: delivered value does not match the stored value", env)
		}
	}
	for _, f := range forbidden {
		if bytes.Contains(r.body, []byte(f.value)) ||
			bytes.Contains(r.body, []byte(base64.StdEncoding.EncodeToString([]byte(f.value)))) {
			t.Errorf("response carries the value of %s", f.name)
		}
	}
}

// checkError requires status and error code, and no secrets in the body.
func checkError(t *testing.T, r resolveResult, status int, code string) {
	t.Helper()
	b := r.response(t)
	if r.status != status || b.Error != code {
		t.Fatalf("resolve: status %d error %q, want %d %q", r.status, b.Error, status, code)
	}
	if b.Secrets != nil {
		t.Fatalf("error response carries secrets %v", b.envs())
	}
}

// TestResolveFromLabelledPod (journeys 8b and 17): a labelled pod created by
// the registered creator gets exactly its user's test-consumer secrets, none
// bound only to another app, and the management API then shows the delivery.
func TestResolveFromLabelledPod(t *testing.T) {
	readyForPods(t)
	api := mgmtClient(t)
	sub := uniqueSub("resolve-a")
	tok := signToken(t, sub, clientID)
	alpha := newSecret("alpha_key", bind(consumerApp, "ALPHA"))
	both := newSecret("both_key", bind(consumerApp, "BETA"), bind(otherApp, "BETA_NB"))
	nbOnly := newSecret("nb_key", bind(otherApp, "NB_ONLY"))
	putSecrets(t, api, tok, alpha, both, nbOnly)

	_, r := resolveOnce(t, creatorKube(t), consumerPod(sub, consumerApp, true, modeOnce))
	checkSecrets(t, r, wantDelivered(alpha, both, nbOnly), nbOnly)

	// The status write follows the response; poll for it.
	deadline := time.Now().Add(15 * time.Second)
	for {
		status, body := api.mustDo(t, http.MethodGet, "/api/v1/secrets", tok, nil)
		if status != http.StatusOK {
			t.Fatalf("GET /api/v1/secrets: status %d body %s", status, body)
		}
		var view model.OwnerView
		if err := json.Unmarshal(body, &view); err != nil {
			t.Fatalf("decode OwnerView: %v", err)
		}
		for _, d := range view.Deliveries {
			if d.App == consumerApp && !d.LastOK.IsZero() {
				if d.LastCount != 2 || d.LastReason != "" {
					t.Fatalf("delivery %+v, want lastCount 2 and no failure", d)
				}
				t.Logf("delivery status: %+v", d)
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s delivery in %+v", consumerApp, view.Deliveries)
		}
		time.Sleep(time.Second)
	}
}

// TestCrossUserIsolation (journey 7, service half; journey 8c): user B's pod
// gets B's secrets and none of A's; a pod with the projected token but
// without the label is refused not_annotated; a management (Keycloak-style)
// token is not a pod token.
func TestCrossUserIsolation(t *testing.T) {
	readyForPods(t)
	api := mgmtClient(t)
	subA, subB := uniqueSub("iso-a"), uniqueSub("iso-b")
	tokA := signToken(t, subA, clientID)
	aShared := newSecret("shared_key", bind(consumerApp, "SHARED"))
	aOnly := newSecret("a_only", bind(consumerApp, "A_ONLY"))
	bShared := newSecret("shared_key", bind(consumerApp, "SHARED"))
	putSecrets(t, api, tokA, aShared, aOnly)
	putSecrets(t, api, signToken(t, subB, clientID), bShared)

	t.Run("B's pod gets only B's secrets", func(t *testing.T) {
		_, r := resolveOnce(t, creatorKube(t), consumerPod(subB, consumerApp, true, modeOnce))
		checkSecrets(t, r, wantDelivered(bShared), aShared, aOnly)
	})

	// One unlabelled pod with the projected token serves both refusals.
	pod := startWaitingPod(t, kube(t), consumerPod("", "", false, modeWait))
	tests := []struct {
		name       string
		token      string // "" sends the pod's projected token
		wantStatus int
		wantCode   string
	}{
		{"unlabelled pod with its projected token", "", http.StatusForbidden, "not_annotated"},
		{"management token for user A", tokA, http.StatusUnauthorized, "not_pod_bound"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := execResolve(t, pod.Name, tt.token)
			checkError(t, r, tt.wantStatus, tt.wantCode)
		})
	}
}

// recordSecret is user-secrets' owner record Secret, read and replaced with
// kubectl.
type recordSecret map[string]any

func getRecordSecret(t *testing.T, sub string) recordSecret {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := run(ctx, "kubectl", "-n", serviceNS, "get", "secret", model.SecretName(sub), "-o", "json")
	if err != nil {
		t.Fatalf("kubectl get record of %s: %v", sub, err)
	}
	var s recordSecret
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatalf("decode record Secret: %v", err)
	}
	return s
}

// raw returns data["record.json"] as stored.
func (s recordSecret) raw(t *testing.T) []byte {
	t.Helper()
	data, _ := s["data"].(map[string]any)
	enc, _ := data["record.json"].(string)
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(raw) == 0 {
		t.Fatalf("record.json: %d bytes, %v", len(raw), err)
	}
	return raw
}

// record decodes data["record.json"].
func (s recordSecret) record(t *testing.T) model.OwnerRecord {
	t.Helper()
	raw := s.raw(t)
	var rec model.OwnerRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("decode record.json: %v", err)
	}
	return rec
}

// replaceRecord writes rec into data["record.json"] of the live Secret with
// kubectl replace (the live resourceVersion makes it a conditional update).
func replaceRecord(t *testing.T, sub string, rec []byte) {
	t.Helper()
	live := getRecordSecret(t, sub)
	data, _ := live["data"].(map[string]any)
	data["record.json"] = base64.StdEncoding.EncodeToString(rec)
	b, err := json.Marshal(live)
	if err != nil {
		t.Fatalf("encode record Secret: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if out, err := runStdin(ctx, string(b), "kubectl", "replace", "-f", "-"); err != nil {
		t.Fatalf("kubectl replace record of %s: %v\n%s", sub, err, out)
	}
}

// TestDecryptFailedOnKind (journey 20): A's sealed entry copied into B's
// record does not open under B's key; B's pod gets 500 decrypt_failed and
// nothing else, A's value included.
func TestDecryptFailedOnKind(t *testing.T) {
	readyForPods(t)
	api := mgmtClient(t)
	subA, subB := uniqueSub("dec-a"), uniqueSub("dec-b")
	aKey := newSecret("vendor_key", bind(consumerApp, "VENDOR_KEY"))
	bKey := newSecret("vendor_key", bind(consumerApp, "VENDOR_KEY"))
	putSecrets(t, api, signToken(t, subA, clientID), aKey)
	putSecrets(t, api, signToken(t, subB, clientID), bKey)

	recA := getRecordSecret(t, subA).record(t)
	secB := getRecordSecret(t, subB)
	recB, origB := secB.record(t), secB.raw(t)
	t.Cleanup(func() { replaceRecord(t, subB, origB) })
	if len(recA.Secrets) != 1 || len(recB.Secrets) != 1 {
		t.Fatalf("records hold %d and %d secrets, want 1 each", len(recA.Secrets), len(recB.Secrets))
	}
	recB.Secrets[0].Sealed = recA.Secrets[0].Sealed
	tampered, err := json.Marshal(recB)
	if err != nil {
		t.Fatalf("encode tampered record: %v", err)
	}
	replaceRecord(t, subB, tampered)

	_, r := resolveOnce(t, creatorKube(t), consumerPod(subB, consumerApp, true, modeOnce))
	checkError(t, r, http.StatusInternalServerError, "decrypt_failed")
	for _, s := range []testSecret{aKey, bKey} {
		if bytes.Contains(r.body, []byte(s.value)) ||
			bytes.Contains(r.body, []byte(base64.StdEncoding.EncodeToString([]byte(s.value)))) {
			t.Errorf("decrypt_failed body carries a value")
		}
	}
}

// TestResolveGuard (journey 12, delivery half): with binding B at [Warn]
// resolve answers 503 guard_not_verified; a pod created during [Warn] is
// refused pod_predates_guard after [Deny] is restored; a pod created after
// the restore resolves.
//
// The old pod sleeps, and the test runs the resolve call in it with kubectl
// exec before and after the restore: the same pod and the same projected
// token, so only the guard state differs between the two calls.
func TestResolveGuard(t *testing.T) {
	reps, tok := readyForPods(t)
	api := mgmtClient(t)
	sub := uniqueSub("guard-a")
	key := newSecret("guard_key", bind(consumerApp, "GUARD_KEY"))
	putSecrets(t, api, signToken(t, sub, clientID), key)
	creator := creatorKube(t)

	patchCreatorsBindingWarn(t, reps, tok)
	waitGuard(t, reps, tok, stateConfirmedBad, badTimeout)

	old := startWaitingPod(t, creator, consumerPod(sub, consumerApp, true, modeWait))
	checkError(t, execResolve(t, old.Name, ""), http.StatusServiceUnavailable, "guard_not_verified")

	restoreBundle(t)
	waitGuard(t, reps, tok, stateVerified, recoverTimeout)
	checkError(t, execResolve(t, old.Name, ""), http.StatusForbidden, "pod_predates_guard")

	waitPastVerifiedSince(t)
	_, r := resolveOnce(t, creator, consumerPod(sub, consumerApp, true, modeOnce))
	checkSecrets(t, r, wantDelivered(key))
}

// TestDurabilityThroughResolve (journey 9): after a rolling restart and a
// helm upgrade of the service, a new consumer pod still resolves the value.
func TestDurabilityThroughResolve(t *testing.T) {
	api := mgmtClient(t)
	sub := uniqueSub("durable-r")
	key := newSecret("durable_key", bind(consumerApp, "DURABLE_KEY"))
	putSecrets(t, api, signToken(t, sub, clientID), key)

	mustRun(t, time.Minute, "kubectl", "-n", serviceNS, "rollout", "restart", "deployment/"+releaseName)
	mustRun(t, 5*time.Minute, "kubectl", "-n", serviceNS, "rollout", "status", "deployment/"+releaseName, "--timeout=280s")
	mustRun(t, 6*time.Minute, "helm", "upgrade", releaseName, chartDir, "--namespace", serviceNS,
		"--reuse-values", "--wait", "--timeout", "5m")

	readyForPods(t)
	_, r := resolveOnce(t, creatorKube(t), consumerPod(sub, consumerApp, true, modeOnce))
	checkSecrets(t, r, wantDelivered(key))
}

// auditLine is the part of a service log line the audit checks read.
type auditLine struct {
	Audit     bool   `json:"audit"`
	Event     string `json:"event"`
	OwnerSub  string `json:"owner_sub"`
	ReaderSub string `json:"reader_sub"`
	Secret    string `json:"secret"`
	App       string `json:"app"`
	Pod       string `json:"pod"`
	PodUID    string `json:"pod_uid"`
	SA        string `json:"sa"`
	Guard     string `json:"guard"`
	Reason    string `json:"reason"`
}

// serviceLogs returns every service replica's log lines since start.
func serviceLogs(t *testing.T, since time.Time) []string {
	t.Helper()
	ctx := context.Background()
	pods, err := kube(t).CoreV1().Pods(serviceNS).List(ctx,
		metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=" + releaseName})
	if err != nil {
		t.Fatalf("service pods: %v", err)
	}
	st := metav1.NewTime(since)
	var lines []string
	for _, p := range pods.Items {
		raw, err := kube(t).CoreV1().Pods(serviceNS).GetLogs(p.Name,
			&corev1.PodLogOptions{Container: releaseName, SinceTime: &st}).DoRaw(ctx)
		if err != nil {
			t.Fatalf("logs of %s: %v", p.Name, err)
		}
		lines = append(lines, strings.Split(strings.TrimSpace(string(raw)), "\n")...)
	}
	return lines
}

// TestResolveDeniedAudit (journey 11): one secret_read line per returned
// secret with every field, one resolve_denied line with the reason for a
// refused call, and no value or token in any service log line.
func TestResolveDeniedAudit(t *testing.T) {
	readyForPods(t)
	start := time.Now().Add(-2 * time.Second)
	api := mgmtClient(t)
	sub := uniqueSub("audit-a")
	mgmtTok := signToken(t, sub, clientID)
	one := newSecret("audit_one", bind(consumerApp, "AUDIT_ONE"))
	two := newSecret("audit_two", bind(consumerApp, "AUDIT_TWO"))
	putSecrets(t, api, mgmtTok, one, two)

	// The labelled pod waits, so the test can read its projected token and
	// look for it in the logs.
	ok := startWaitingPod(t, creatorKube(t), consumerPod(sub, consumerApp, true, modeWait))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	podTok, err := run(ctx, "kubectl", "-n", consumerNS, "exec", ok.Name, "-c", "curl", "--", "cat", tokenDir+"/token")
	if err != nil || strings.Count(podTok, ".") != 2 {
		t.Fatalf("read the pod's projected token: %v", err)
	}
	checkSecrets(t, execResolve(t, ok.Name, ""), wantDelivered(one, two))
	denied, r := resolveOnce(t, kube(t), consumerPod("", "", false, modeOnce))
	checkError(t, r, http.StatusForbidden, "not_annotated")

	secrets := []testSecret{one, two}
	// A token's signature is its most specific part; any of the three parts
	// appearing would be a leak.
	forbidden := map[string]string{}
	for _, s := range secrets {
		forbidden[s.name+" value"] = s.value
		forbidden[s.name+" base64"] = base64.StdEncoding.EncodeToString([]byte(s.value))
	}
	for i, part := range strings.Split(strings.TrimSpace(podTok), ".") {
		forbidden[fmt.Sprintf("pod token part %d", i)] = part
	}
	for i, part := range strings.Split(mgmtTok, ".") {
		forbidden[fmt.Sprintf("management token part %d", i)] = part
	}

	wantRead := map[string]auditLine{}
	for _, s := range secrets {
		wantRead[s.name] = auditLine{
			Audit: true, Event: "secret_read", OwnerSub: sub, ReaderSub: sub, Secret: s.name,
			App: consumerApp, Pod: consumerNS + "/" + ok.Name, PodUID: string(ok.UID), SA: workloadSA,
			Guard: "enforced",
		}
	}
	wantDenied := auditLine{
		Audit: true, Event: "resolve_denied", Pod: consumerNS + "/" + denied.Name,
		PodUID: string(denied.UID), SA: workloadSA, Reason: "not_annotated",
	}

	// Lines reach the log at once; poll briefly for the log read only.
	deadline := time.Now().Add(15 * time.Second)
	for {
		lines := serviceLogs(t, start)
		gotRead := map[string][]auditLine{}
		var gotDenied []auditLine
		for _, l := range lines {
			for what, f := range forbidden {
				if strings.Contains(l, f) {
					t.Fatalf("a service log line contains the %s", what)
				}
			}
			var a auditLine
			if json.Unmarshal([]byte(l), &a) != nil || !a.Audit {
				continue
			}
			switch {
			case a.Event == "secret_read" && a.ReaderSub == sub:
				gotRead[a.Secret] = append(gotRead[a.Secret], a)
			case a.Event == "resolve_denied" && a.Pod == wantDenied.Pod:
				gotDenied = append(gotDenied, a)
			}
		}
		complete := len(gotDenied) > 0
		for name := range wantRead {
			complete = complete && len(gotRead[name]) > 0
		}
		if !complete && time.Now().Before(deadline) {
			time.Sleep(time.Second)
			continue
		}
		if len(gotRead) != len(wantRead) {
			t.Errorf("secret_read lines for secrets %v, want %v", slices.Sorted(maps.Keys(gotRead)),
				slices.Sorted(maps.Keys(wantRead)))
		}
		for name, want := range wantRead {
			if len(gotRead[name]) != 1 || gotRead[name][0] != want {
				t.Errorf("secret_read for %s: %+v, want exactly one %+v", name, gotRead[name], want)
			}
		}
		if len(gotDenied) != 1 || gotDenied[0] != wantDenied {
			t.Errorf("resolve_denied: %+v, want exactly one %+v", gotDenied, wantDenied)
		}
		if !t.Failed() {
			t.Logf("audit lines: %d secret_read for %s, resolve_denied %+v", len(wantRead), sub, gotDenied[0])
		}
		return
	}
}
