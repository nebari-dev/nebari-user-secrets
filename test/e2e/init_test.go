//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

// The delivery pod shape the injector will produce (spec "The injector"):
// the files emptyDir (memory, 1Mi) and the bin emptyDir, both read-only in
// the workload container.
const (
	filesDir   = "/var/run/nebari/secrets"
	binDir     = "/var/run/nebari/user-secrets-bin"
	resolveURL = "https://" + serviceHost + ":8443/api/v1/resolve"
	initName   = "user-secrets-init"
	mainName   = "main"
	// The init container runs as the image's user; the workload as another
	// user and group, as a notebook (jovyan, UID 1000) does, so it can read
	// the files and run the wrapper only through the fsGroup bits.
	initUID    = int64(65532)
	mainUID    = int64(1000)
	mainGID    = int64(1000)
	podFSGroup = int64(2000)
	// blockedPrefix names the namespaces the blocked case creates: never a
	// registered workload namespace.
	blockedPrefix = "e2e-blocked-"
	// blockedLabel marks those namespaces, so a run deletes the ones an
	// aborted run left behind.
	blockedLabel = "user-secrets-e2e/blocked"
	initTimeout  = 4 * time.Minute
)

// mainScript runs under user-secrets-env and prints, without any value, the
// .status line and for each secret file its mode, group and SHA-256, and the
// SHA-256 of the environment variable of the same name (or unset).
const mainScript = `
cd ` + filesDir + `
echo "ID:$(id -u):$(id -g)"
echo "BIN:$(stat -c '%a:%g' ` + binDir + `/user-secrets-env)"
echo "STATUS:$(cat .status 2>/dev/null || echo absent)"
for f in NEBARI_SECRET_*; do
  [ -e "$f" ] || continue
  echo "FILE:$f:$(stat -c '%a:%g' "$f"):$(sha256sum < "$f" | cut -d' ' -f1)"
done
for n in $(env | sed -n 's/^\(NEBARI_SECRET_[A-Z0-9_]*\)=.*/\1/p' | sort -u); do
  echo "ENV:$n:$(eval "printf %s \"\${$n}\"" | sha256sum | cut -d' ' -f1)"
done
`

// initImage is the service image, which also holds /user-secrets-init: the
// image and pull policy of the installed Deployment.
func initImage(t *testing.T) (string, corev1.PullPolicy) {
	t.Helper()
	d, err := kube(t).AppsV1().Deployments(serviceNS).Get(context.Background(), releaseName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("deployment %s: %v", releaseName, err)
	}
	c := d.Spec.Template.Spec.Containers[0]
	return c.Image, c.ImagePullPolicy
}

// restricted is a container security context that Pod Security "restricted"
// admits, running as uid:gid.
func restricted(uid, gid int64) *corev1.SecurityContext {
	return &corev1.SecurityContext{
		RunAsUser:                ptr.To(uid),
		RunAsGroup:               ptr.To(gid),
		AllowPrivilegeEscalation: ptr.To(false),
		ReadOnlyRootFilesystem:   ptr.To(true),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
}

// deliveryPod is consumerPod with the delivery pieces: the init container
// from the service image in failure mode mode, the files and bin volumes,
// and the main container wrapped by user-secrets-env running mainScript.
func deliveryPod(t *testing.T, ns, sa, sub, mode string, labelled bool, env ...corev1.EnvVar) *corev1.Pod {
	t.Helper()
	p := consumerPod(sub, consumerApp, labelled, modeOnce)
	p.Namespace = ns
	p.Spec.ServiceAccountName = sa
	p.Spec.SecurityContext.FSGroup = ptr.To(podFSGroup)
	img, pull := initImage(t)
	p.Spec.InitContainers = []corev1.Container{{
		Name:            initName,
		Image:           img,
		ImagePullPolicy: pull,
		Command: []string{"/user-secrets-init", "fetch", "--url", resolveURL, "--ca", bundleDir + "/" + bundleKey,
			"--token", tokenDir + "/token", "--dir", filesDir, "--bin-dir", binDir, "--mode", mode},
		SecurityContext: restricted(initUID, initUID),
		VolumeMounts: []corev1.VolumeMount{
			{Name: "token", MountPath: tokenDir, ReadOnly: true},
			{Name: "trust", MountPath: bundleDir, ReadOnly: true},
			{Name: "user-secrets-files", MountPath: filesDir},
			{Name: "user-secrets-bin", MountPath: binDir},
		},
	}}
	p.Spec.Containers = []corev1.Container{{
		Name:            mainName,
		Image:           pin("CURL_IMAGE"),
		Command:         []string{binDir + "/user-secrets-env", "--", "sh", "-c", mainScript},
		Env:             env,
		SecurityContext: restricted(mainUID, mainGID),
		VolumeMounts: []corev1.VolumeMount{
			{Name: "user-secrets-files", MountPath: filesDir, ReadOnly: true},
			{Name: "user-secrets-bin", MountPath: binDir, ReadOnly: true},
		},
	}}
	p.Spec.Volumes = append(p.Spec.Volumes,
		corev1.Volume{Name: "user-secrets-files", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{
			Medium: corev1.StorageMediumMemory, SizeLimit: ptr.To(resource.MustParse("1Mi")),
		}}},
		corev1.Volume{Name: "user-secrets-bin", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	)
	return p
}

// createPodIn creates pod in its namespace with cs and deletes it when the
// test ends.
func createPodIn(t *testing.T, cs *kubernetes.Clientset, pod *corev1.Pod) *corev1.Pod {
	t.Helper()
	p, err := cs.CoreV1().Pods(pod.Namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create pod in %s: %v", pod.Namespace, err)
	}
	t.Cleanup(func() {
		_ = kube(t).CoreV1().Pods(p.Namespace).Delete(context.Background(), p.Name,
			metav1.DeleteOptions{GracePeriodSeconds: ptr.To(int64(0))})
	})
	return p
}

// waitPodDone polls the pod until it has succeeded or failed and returns it.
func waitPodDone(t *testing.T, ns, name string) *corev1.Pod {
	t.Helper()
	deadline := time.Now().Add(initTimeout)
	var last *corev1.Pod
	for time.Now().Before(deadline) {
		p, err := kube(t).CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{})
		if err == nil {
			last = p
			if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
				return p
			}
		}
		time.Sleep(time.Second)
	}
	if last != nil {
		t.Fatalf("pod %s/%s: phase %s within %s; init %+v; main %+v", ns, name, last.Status.Phase, initTimeout,
			last.Status.InitContainerStatuses, last.Status.ContainerStatuses)
	}
	t.Fatalf("pod %s/%s not found within %s", ns, name, initTimeout)
	return nil
}

// podLog returns one container's log.
func podLog(t *testing.T, ns, pod, container string) string {
	t.Helper()
	raw, err := kube(t).CoreV1().Pods(ns).GetLogs(pod, &corev1.PodLogOptions{Container: container}).
		DoRaw(context.Background())
	if err != nil {
		t.Fatalf("logs of %s/%s: %v", pod, container, err)
	}
	return string(raw)
}

// deliveryReport is mainScript's output and the wrapper's stderr lines.
type deliveryReport struct {
	id      string // uid:gid of the main container
	bin     string // mode:gid of user-secrets-env
	status  string
	files   map[string]string // name -> "mode:gid:sha256"
	env     map[string]string // name -> sha256
	wrapper []string          // user-secrets-env lines
}

func parseDelivery(log string) deliveryReport {
	r := deliveryReport{files: map[string]string{}, env: map[string]string{}}
	sc := bufio.NewScanner(strings.NewReader(log))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "ID:"):
			r.id = strings.TrimPrefix(line, "ID:")
		case strings.HasPrefix(line, "BIN:"):
			r.bin = strings.TrimPrefix(line, "BIN:")
		case strings.HasPrefix(line, "STATUS:"):
			r.status = strings.TrimPrefix(line, "STATUS:")
		case strings.HasPrefix(line, "FILE:"):
			name, rest, _ := strings.Cut(strings.TrimPrefix(line, "FILE:"), ":")
			r.files[name] = rest
		case strings.HasPrefix(line, "ENV:"):
			name, sum, _ := strings.Cut(strings.TrimPrefix(line, "ENV:"), ":")
			r.env[name] = sum
		case strings.HasPrefix(line, "user-secrets-env:"):
			r.wrapper = append(r.wrapper, line)
		}
	}
	return r
}

func sha(b string) string {
	s := sha256.Sum256([]byte(b))
	return hex.EncodeToString(s[:])
}

// TestInitDeliversFiles (journeys 13 and 17): the real init container in a
// hand-built delivery pod writes each secret as a file with the exact stored
// bytes (journey 13's escape test value, with a newline and a non-UTF-8
// byte), mode 0440 and the pod's fsGroup, and user-secrets-env exports the
// same bytes without replacing a variable the container already sets. In a
// namespace the service's NetworkPolicy does not admit, a soft pod starts
// with .status "error unreachable", no secret files and the wrapper's one
// warning line, and a strict pod's init container fails so the main
// container never starts.
func TestInitDeliversFiles(t *testing.T) {
	t.Run("delivers exact bytes as files and env", func(t *testing.T) {
		readyForPods(t)
		api := mgmtClient(t)
		tok, sub := freshUser(t, "alice")
		escape := testSecret{
			name:     "escape_test",
			value:    `{"k":"a$$b$(HOME){username}"}` + "\n" + "\xff",
			bindings: []model.Binding{bind(consumerApp, "ESCAPE_TEST")},
		}
		plain := newSecret("plain_key", bind(consumerApp, "PLAIN"))
		preset := newSecret("preset_key", bind(consumerApp, "PRESET"))
		putSecrets(t, api, tok, escape, plain, preset)

		const presetValue = "set-by-the-container"
		p := createPodIn(t, creatorKube(t), deliveryPod(t, consumerNS, workloadSA, sub, "soft", true,
			corev1.EnvVar{Name: "NEBARI_SECRET_PRESET", Value: presetValue}))
		done := waitPodDone(t, consumerNS, p.Name)
		initLog := podLog(t, consumerNS, p.Name, initName)
		t.Logf("init container: %s", strings.TrimSpace(initLog))
		r := parseDelivery(podLog(t, consumerNS, p.Name, mainName))
		t.Logf("main uid:gid %q, user-secrets-env mode:gid %q, status %q, files %v, wrapper %q",
			r.id, r.bin, r.status, keys(r.files), r.wrapper)
		// The main container's command is the wrapper: Succeeded means UID
		// 1000 exec'd it.
		if done.Status.Phase != corev1.PodSucceeded {
			t.Fatalf("pod phase %s, want Succeeded", done.Status.Phase)
		}
		if r.id != "1000:1000" {
			t.Fatalf("main container runs as %q, want 1000:1000", r.id)
		}
		if r.bin != "550:2000" {
			t.Errorf("user-secrets-env mode:gid = %q, want 550:2000", r.bin)
		}
		if r.status != "ok 3" {
			t.Fatalf(".status = %q, want ok 3", r.status)
		}
		if len(r.wrapper) != 0 {
			t.Errorf("wrapper printed %q, want nothing", r.wrapper)
		}
		want := map[string]string{
			"NEBARI_SECRET_ESCAPE_TEST": escape.value,
			"NEBARI_SECRET_PLAIN":       plain.value,
			"NEBARI_SECRET_PRESET":      preset.value,
		}
		if len(r.files) != len(want) {
			t.Fatalf("files %v, want %v", keys(r.files), keys(want))
		}
		for name, v := range want {
			if got, wantFile := r.files[name], "440:2000:"+sha(v); got != wantFile {
				t.Errorf("%s: file mode:gid:sha256 = %q, want 440:2000 and the stored bytes' hash", name, got)
			}
		}
		for name, v := range map[string]string{
			"NEBARI_SECRET_ESCAPE_TEST": escape.value,
			"NEBARI_SECRET_PLAIN":       plain.value,
			// The container's own variable wins over the file.
			"NEBARI_SECRET_PRESET": presetValue,
		} {
			if r.env[name] != sha(v) {
				t.Errorf("%s: env var does not hold the expected bytes (present %v)", name, r.env[name] != "")
			}
		}
	})

	t.Run("a blocked namespace gets error unreachable; strict never starts", func(t *testing.T) {
		blockedNS := createBlockedNamespace(t)
		soft := createPodIn(t, kube(t), deliveryPod(t, blockedNS, "default", "", "soft", false))
		strict := createPodIn(t, kube(t), deliveryPod(t, blockedNS, "default", "", "strict", false))

		ps := waitPodDone(t, blockedNS, soft.Name)
		t.Logf("soft init container: %s", strings.TrimSpace(podLog(t, blockedNS, soft.Name, initName)))
		if ps.Status.Phase != corev1.PodSucceeded {
			t.Fatalf("soft pod phase %s, want Succeeded (the workload starts)", ps.Status.Phase)
		}
		r := parseDelivery(podLog(t, blockedNS, soft.Name, mainName))
		t.Logf("soft main: status %q, wrapper %q", r.status, r.wrapper)
		// More than one attempt: a dropped connection must fail within the
		// client's dial timeout and be retried, not use the whole budget.
		m := regexp.MustCompile(`^error unreachable .* after (\d+) attempts$`).FindStringSubmatch(r.status)
		if m == nil {
			t.Errorf(".status = %q, want error unreachable ... after N attempts", r.status)
		} else if n, _ := strconv.Atoi(m[1]); n < 2 {
			t.Errorf(".status = %q: %d attempt(s), want more than one", r.status, n)
		}
		if len(r.files) != 0 || len(r.env) != 0 {
			t.Errorf("files %v env %v, want none", keys(r.files), keys(r.env))
		}
		if len(r.wrapper) != 1 || !strings.Contains(r.wrapper[0], "warning") ||
			!strings.Contains(r.wrapper[0], "error unreachable") {
			t.Errorf("wrapper lines %q, want one warning naming error unreachable", r.wrapper)
		}

		pf := waitPodDone(t, blockedNS, strict.Name)
		initLog := podLog(t, blockedNS, strict.Name, initName)
		t.Logf("strict init container: %s", strings.TrimSpace(initLog))
		if pf.Status.Phase != corev1.PodFailed {
			t.Fatalf("strict pod phase %s, want Failed", pf.Status.Phase)
		}
		if !strings.Contains(initLog, "error unreachable") {
			t.Errorf("strict init log lacks error unreachable")
		}
		for _, s := range pf.Status.InitContainerStatuses {
			if s.Name == initName && (s.State.Terminated == nil || s.State.Terminated.ExitCode != 1) {
				t.Errorf("strict init container state %+v, want terminated with exit code 1", s.State)
			}
		}
		for _, s := range pf.Status.ContainerStatuses {
			if s.Name == mainName && (s.State.Running != nil || s.State.Terminated != nil || s.ContainerID != "") {
				t.Errorf("strict main container started: %+v", s.State)
			}
		}
	})
}

// createBlockedNamespace deletes the namespaces earlier runs left with
// blockedLabel, then creates one named blockedPrefix plus a random suffix
// (Pod Security restricted, as the consumer namespace), deletes it when the
// test ends, waits for trust-manager to project the trust bundle into it and
// for its default ServiceAccount, and returns its name. The service's
// NetworkPolicy admits port 8443 only from registered workload namespaces,
// and this is not one.
func createBlockedNamespace(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	// t.Cleanup does not run when go test's -timeout panics; sweep leftovers.
	old, err := kube(t).CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: blockedLabel + "=true"})
	if err != nil {
		t.Fatalf("list leftover %s* namespaces: %v", blockedPrefix, err)
	}
	for _, n := range old.Items {
		if err := kube(t).CoreV1().Namespaces().Delete(ctx, n.Name, metav1.DeleteOptions{}); err != nil &&
			!apierrors.IsNotFound(err) {
			t.Fatalf("delete leftover namespace %s: %v", n.Name, err)
		}
		t.Logf("deleted leftover namespace %s", n.Name)
	}
	ns, err := kube(t).CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		GenerateName: blockedPrefix,
		Labels:       map[string]string{"pod-security.kubernetes.io/enforce": "restricted", blockedLabel: "true"},
	}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create namespace %s*: %v", blockedPrefix, err)
	}
	blockedNS := ns.Name
	t.Cleanup(func() {
		_ = kube(t).CoreV1().Namespaces().Delete(context.Background(), blockedNS, metav1.DeleteOptions{})
	})
	deadline := time.Now().Add(2 * time.Minute)
	for {
		_, err := kube(t).CoreV1().ConfigMaps(blockedNS).Get(ctx, bundleName, metav1.GetOptions{})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not projected into %s: %v", bundleName, blockedNS, err)
		}
		time.Sleep(time.Second)
	}
	// The ServiceAccount controller creates default shortly after the
	// namespace; a pod create before that is refused.
	for {
		_, err := kube(t).CoreV1().ServiceAccounts(blockedNS).Get(ctx, "default", metav1.GetOptions{})
		if err == nil {
			return blockedNS
		}
		if time.Now().After(deadline) {
			t.Fatalf("no default ServiceAccount in %s: %v", blockedNS, err)
		}
		time.Sleep(time.Second)
	}
}

// keys returns the sorted names of m, for messages that must not print
// values.
func keys(m map[string]string) []string {
	return slices.Sorted(maps.Keys(m))
}
