//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/nebari-dev/nebari-user-secrets/internal/guard"
)

// Names and timing for the guard tests.
const (
	creatorsName   = "user-secrets-creators"
	guardStateName = "user-secrets-guard-state"

	// stateVerified and stateConfirmedBad are the guard states the status
	// route reports.
	stateVerified     = "verified"
	stateConfirmedBad = "confirmed_bad"

	// baselineTimeout bounds the first wait for verified: a replica that just
	// started (or restarted in another test) needs its informers to sync and
	// one evaluation (three probes of at most 20 s each, a server-time read
	// and a guard-state write).
	baselineTimeout = 3 * time.Minute
	// badTimeout is the spec bound for a watched object change to show: the
	// watch event is applied at once, without probing.
	badTimeout = 10 * time.Second
	// recoverTimeout bounds verified after a restore: the watch event starts
	// one evaluation after the 2 s settle delay, whose worst case is three
	// probe timeouts (60 s) plus the server-time read and the guard-state
	// write; 90 s leaves about 28 s for those.
	recoverTimeout = 90 * time.Second
	// pollEvery is the pause between rounds; each round reads the status of
	// every service replica, through a port-forward to that pod, so a state
	// counts only when every replica reports it in the same round.
	pollEvery = 500 * time.Millisecond
)

// replica is one service pod's management API, reached by port-forward.
type replica struct {
	pod string
	api *mgmtAPI
}

// guardReplicas waits for the deployment's rollout, then port-forwards to each
// running service pod. It fails if fewer pods than the deployment's replicas
// are ready.
func guardReplicas(t *testing.T) []replica {
	t.Helper()
	mustRun(t, 5*time.Minute, "kubectl", "-n", serviceNS, "rollout", "status", "deployment/"+releaseName, "--timeout=280s")
	ctx := context.Background()
	dep, err := kube(t).AppsV1().Deployments(serviceNS).Get(ctx, releaseName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("deployment: %v", err)
	}
	pods, err := kube(t).CoreV1().Pods(serviceNS).List(ctx,
		metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=" + releaseName})
	if err != nil {
		t.Fatalf("pods: %v", err)
	}
	out := make([]replica, 0, len(pods.Items))
	for _, p := range pods.Items {
		if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning {
			continue
		}
		out = append(out, replica{pod: p.Name, api: portForwardMgmt(t, serviceNS, "pod/"+p.Name, true)})
	}
	if want := int(*dep.Spec.Replicas); len(out) != want {
		t.Fatalf("%d running service pods, want %d", len(out), want)
	}
	return out
}

type guardStatus struct {
	Guard struct {
		State  string `json:"state"`
		Mode   string `json:"mode"`
		Reason string `json:"reason"`
	} `json:"guard"`
}

// readGuard reads GET /api/v1/status once.
func readGuard(api *mgmtAPI, tok string) (guardStatus, error) {
	status, body, err := api.do(http.MethodGet, "/api/v1/status", tok, nil)
	if err != nil {
		return guardStatus{}, err
	}
	if status != http.StatusOK {
		return guardStatus{}, fmt.Errorf("status route: %d %s", status, body)
	}
	var gs guardStatus
	if err := json.Unmarshal(body, &gs); err != nil {
		return guardStatus{}, fmt.Errorf("status body %s: %w", body, err)
	}
	return gs, nil
}

// waitGuard polls every replica's status route until all of them report want
// in the same round, or fails after timeout. It returns the elapsed time and
// each replica's last status, in replica order.
func waitGuard(t *testing.T, reps []replica, tok, want string, timeout time.Duration) (time.Duration, []guardStatus) {
	t.Helper()
	start := time.Now()
	deadline := start.Add(timeout)
	last := make([]guardStatus, len(reps))
	lastErr := make([]error, len(reps))
	for time.Now().Before(deadline) {
		all := true
		for i, r := range reps {
			gs, err := readGuard(r.api, tok)
			lastErr[i] = err
			if err == nil {
				last[i] = gs
			}
			if err != nil || gs.Guard.State != want {
				all = false
			}
		}
		if all {
			return time.Since(start), last
		}
		time.Sleep(pollEvery)
	}
	for i, r := range reps {
		t.Errorf("replica %s: last %+v, last error %v", r.pod, last[i].Guard, lastErr[i])
	}
	t.Fatalf("not every replica reported %s within %s", want, timeout)
	return 0, last
}

// wantReason checks every replica's reason.
func wantReason(t *testing.T, reps []replica, got []guardStatus, want string) {
	t.Helper()
	for i, r := range reps {
		if got[i].Guard.Reason != want {
			t.Errorf("replica %s: reason %q, want %q", r.pod, got[i].Guard.Reason, want)
		}
	}
}

// applyBundle re-applies the rendered cluster bundle (serviceNS is the
// install-config default, so the directory is applied as is).
func applyBundle(t *testing.T) {
	t.Helper()
	mustRun(t, time.Minute, "kubectl", "apply", "-k", repoPath("cluster"))
}

// guardStateVerifiedSince reads verifiedSince from the guard-state ConfigMap;
// zero when absent.
func guardStateVerifiedSince(t *testing.T) time.Time {
	t.Helper()
	cm, err := kube(t).CoreV1().ConfigMaps(serviceNS).Get(context.Background(), guardStateName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return time.Time{}
	}
	if err != nil {
		t.Fatalf("get %s: %v", guardStateName, err)
	}
	v, err := time.Parse(time.RFC3339, cm.Data["verifiedSince"])
	if err != nil {
		return time.Time{}
	}
	return v
}

// managerTime returns the managedFields time of manager on obj (zero if none).
func managerTime(obj metav1.Object, manager string) time.Time {
	var out time.Time
	for _, mf := range obj.GetManagedFields() {
		if mf.Manager == manager && mf.Time != nil && mf.Time.After(out) {
			out = mf.Time.UTC()
		}
	}
	return out
}

// patchCreatorsBindingWarn switches binding B to [Warn] under a field manager
// used by this call only, so that manager's managedFields time is the
// API-server time of the patch. It registers a cleanup that re-applies the
// bundle and waits for verified.
func patchCreatorsBindingWarn(t *testing.T, reps []replica, tok string) time.Time {
	t.Helper()
	t.Cleanup(func() {
		applyBundle(t)
		waitGuard(t, reps, tok, stateVerified, recoverTimeout)
	})
	mgr := fmt.Sprintf("e2e-guard-%d", time.Now().UnixNano())
	b, err := kube(t).AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Patch(context.Background(),
		creatorsName, types.MergePatchType, []byte(`{"spec":{"validationActions":["Warn"]}}`),
		metav1.PatchOptions{FieldManager: mgr})
	if err != nil {
		t.Fatalf("patch binding %s: %v", creatorsName, err)
	}
	if got := b.Spec.ValidationActions; len(got) != 1 || got[0] != admissionregistrationv1.Warn {
		t.Fatalf("binding validationActions after patch = %v", got)
	}
	pt := managerTime(b, mgr)
	if pt.IsZero() {
		t.Fatalf("binding has no managedFields entry for %s", mgr)
	}
	return pt
}

// restoreBundle re-applies the bundle and returns the API-server time of that
// apply (the client-side-apply manager takes validationActions back, so its
// managedFields time advances).
func restoreBundle(t *testing.T) time.Time {
	t.Helper()
	applyBundle(t)
	b, err := kube(t).AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(context.Background(),
		creatorsName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get binding %s: %v", creatorsName, err)
	}
	if got := b.Spec.ValidationActions; len(got) != 1 || got[0] != admissionregistrationv1.Deny {
		t.Fatalf("binding validationActions after restore = %v", got)
	}
	return managerTime(b, "kubectl-client-side-apply")
}

// TestGuardFailClosed (journey 12): with the bundle at [Deny] the guard is
// verified; binding B switched to [Warn] makes it confirmed_bad within 10 s
// (watch path); re-applying the bundle makes it verified again.
func TestGuardFailClosed(t *testing.T) {
	reps := guardReplicas(t)
	tok := userToken(t, "alice", clientID)

	_, gs := waitGuard(t, reps, tok, stateVerified, baselineTimeout)
	for i, r := range reps {
		if gs[i].Guard.Mode != "enforced" {
			t.Fatalf("replica %s: mode = %q, want enforced", r.pod, gs[i].Guard.Mode)
		}
	}

	patchCreatorsBindingWarn(t, reps, tok)
	took, gs := waitGuard(t, reps, tok, stateConfirmedBad, badTimeout)
	t.Logf("confirmed_bad on all %d replicas %s after the patch", len(reps), took)
	wantReason(t, reps, gs, "binding "+creatorsName+": validationActions lacks Deny")

	restoreBundle(t)
	took, _ = waitGuard(t, reps, tok, stateVerified, recoverTimeout)
	t.Logf("verified on all %d replicas %s after the restore", len(reps), took)
}

// TestGuardVerifiedSinceMoves: recovering from the [Warn] patch moves
// verifiedSince forward, to an API-server time taken after the restore plus
// the 30 s margin.
func TestGuardVerifiedSinceMoves(t *testing.T) {
	reps := guardReplicas(t)
	tok := userToken(t, "alice", clientID)

	waitGuard(t, reps, tok, stateVerified, baselineTimeout)
	before := guardStateVerifiedSince(t)
	if before.IsZero() {
		t.Fatalf("%s has no verifiedSince while verified", guardStateName)
	}

	patchTime := patchCreatorsBindingWarn(t, reps, tok)
	waitGuard(t, reps, tok, stateConfirmedBad, badTimeout)
	restoreTime := restoreBundle(t)
	waitGuard(t, reps, tok, stateVerified, recoverTimeout)

	// The guard-state write happens before verified is applied, so the new
	// value is already stored; poll briefly for the read only.
	var after time.Time
	deadline := time.Now().Add(10 * time.Second)
	for {
		after = guardStateVerifiedSince(t)
		if after.After(before) || time.Now().After(deadline) {
			break
		}
		time.Sleep(pollEvery)
	}
	t.Logf("verifiedSince before %s, patch at %s (server), restore at %s (server), verifiedSince after %s",
		before.Format(time.RFC3339), patchTime.Format(time.RFC3339),
		restoreTime.Format(time.RFC3339), after.Format(time.RFC3339))

	if !after.After(before) {
		t.Fatalf("verifiedSince did not move: before %s, after %s", before, after)
	}
	margin := 30 * time.Second
	if !after.After(patchTime.Add(margin)) {
		t.Errorf("verifiedSince %s is not after the patch time %s + 30 s", after, patchTime)
	}
	if restoreTime.IsZero() {
		t.Fatalf("binding has no kubectl-client-side-apply managedFields time")
	}
	// The server time is read after the probes pass, which is after the
	// restore; both are whole seconds. The upper bound is the recovery bound.
	if after.Before(restoreTime.Add(margin)) {
		t.Errorf("verifiedSince %s is earlier than the restore %s + 30 s", after, restoreTime)
	}
	if after.After(restoreTime.Add(margin + recoverTimeout)) {
		t.Errorf("verifiedSince %s is later than the restore %s + 30 s + %s", after, restoreTime, recoverTimeout)
	}
}

// restoreCreatorsConfigMap re-creates user-secrets-creators as the release
// owns it: helm upgrade with the release's own values re-creates a missing
// object with helm's metadata, so the next helm upgrade (in another test or
// run) finds nothing to change and does not move verifiedSince.
func restoreCreatorsConfigMap(t *testing.T) {
	t.Helper()
	mustRun(t, 6*time.Minute, "helm", "upgrade", releaseName, chartDir, "--namespace", serviceNS,
		"--reuse-values", "--wait", "--timeout", "5m")
	if _, err := kube(t).CoreV1().ConfigMaps(serviceNS).Get(context.Background(), creatorsName,
		metav1.GetOptions{}); err != nil {
		t.Fatalf("%s after helm upgrade: %v", creatorsName, err)
	}
}

func plainPod(labelled bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "e2e-guard-", Namespace: "default"},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: ptr.To(false),
			Containers: []corev1.Container{{
				Name:  "pause",
				Image: guard.PauseImage,
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("10m"),
						corev1.ResourceMemory: resource.MustParse("16Mi"),
					},
				},
			}},
		},
	}
	if labelled {
		p.Labels = map[string]string{"nebari.dev/user-secrets": "true"}
		p.Annotations = map[string]string{"nebari.dev/user-secrets-sub": "e2e", "nebari.dev/user-secrets-app": "jupyter"}
	}
	return p
}

// TestMissingConfigMapLeavesClusterWorking (journey 15, service side): with
// user-secrets-creators deleted the guard is confirmed_bad, labelled pods are
// denied, and an unlabelled pod in default is created as usual.
func TestMissingConfigMapLeavesClusterWorking(t *testing.T) {
	ctx := context.Background()
	cs := kube(t)
	reps := guardReplicas(t)
	tok := userToken(t, "alice", clientID)

	waitGuard(t, reps, tok, stateVerified, baselineTimeout)
	t.Cleanup(func() {
		_, err := cs.CoreV1().ConfigMaps(serviceNS).Get(ctx, creatorsName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			restoreCreatorsConfigMap(t)
		}
		waitGuard(t, reps, tok, stateVerified, recoverTimeout)
	})

	if err := cs.CoreV1().ConfigMaps(serviceNS).Delete(ctx, creatorsName, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete %s: %v", creatorsName, err)
	}
	took, gs := waitGuard(t, reps, tok, stateConfirmedBad, badTimeout)
	t.Logf("confirmed_bad on all %d replicas %s after the delete", len(reps), took)
	wantReason(t, reps, gs, "configmap "+creatorsName+": missing")

	pod, err := cs.CoreV1().Pods("default").Create(ctx, plainPod(false), metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("unlabelled pod in default was refused: %v", err)
	}
	t.Cleanup(func() {
		_ = cs.CoreV1().Pods("default").Delete(context.Background(), pod.Name,
			metav1.DeleteOptions{GracePeriodSeconds: ptr.To(int64(0))})
	})

	_, err = cs.CoreV1().Pods("default").Create(ctx, plainPod(true),
		metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	if err == nil {
		t.Fatal("labelled pod was admitted while the creators ConfigMap is missing")
	}
	if !strings.Contains(err.Error(), creatorsName) {
		t.Errorf("labelled pod denied, but not by %s: %v", creatorsName, err)
	}
}
