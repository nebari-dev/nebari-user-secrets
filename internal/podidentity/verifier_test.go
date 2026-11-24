package podidentity

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

type fakeReviewer struct {
	st   authenticationv1.TokenReviewStatus
	err  error
	tok  string
	auds []string
}

func (f *fakeReviewer) Review(_ context.Context, token string, auds []string) (authenticationv1.TokenReviewStatus, error) {
	f.tok, f.auds = token, auds
	return f.st, f.err
}

type fakePods struct {
	pod *corev1.Pod
	err error
}

func (f fakePods) GetPod(context.Context, string, string) (*corev1.Pod, error) { return f.pod, f.err }

type fakeReg struct{ ok bool }

func (f fakeReg) WorkloadAllowed(model.AppID, string, string) bool { return f.ok }

var created = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func goodStatus() authenticationv1.TokenReviewStatus {
	return authenticationv1.TokenReviewStatus{
		Authenticated: true,
		Audiences:     []string{"user-secrets"},
		User: authenticationv1.UserInfo{
			Username: "system:serviceaccount:ns1:nb",
			Extra: map[string]authenticationv1.ExtraValue{
				"authentication.kubernetes.io/pod-name": {"jupyter-alice"},
				"authentication.kubernetes.io/pod-uid":  {"uid-1"},
			},
		},
	}
}

func goodPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "jupyter-alice", Namespace: "ns1", UID: "uid-1",
			CreationTimestamp: metav1.NewTime(created),
			Labels:            map[string]string{"nebari.dev/user-secrets": "true"},
			Annotations:       map[string]string{"nebari.dev/user-secrets-sub": "sub-alice", "nebari.dev/user-secrets-app": "jupyterhub"},
		},
		Spec: corev1.PodSpec{ServiceAccountName: "nb"},
	}
}

func TestPodVerifier(t *testing.T) {
	mutStatus := func(f func(*authenticationv1.TokenReviewStatus)) authenticationv1.TokenReviewStatus {
		s := goodStatus()
		f(&s)
		return s
	}
	mutPod := func(f func(*corev1.Pod)) *corev1.Pod { p := goodPod(); f(p); return p }
	notFound := apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "x")
	wantClaim := model.PodClaim{
		Pod:       model.PodIdentity{Namespace: "ns1", Name: "jupyter-alice", UID: "uid-1", ServiceAccount: "nb"},
		App:       "jupyterhub",
		Principal: model.Principal{Kind: "user", Sub: "sub-alice"},
		Created:   created,
	}
	// What a denial after TokenReview carries for the audit line: the
	// token's namespace, pod name and ServiceAccount; the UID only once it
	// was checked against the pod; never a sub or app.
	seen := model.PodClaim{Pod: model.PodIdentity{Namespace: "ns1", Name: "jupyter-alice", ServiceAccount: "nb"}}
	seenUID := model.PodClaim{Pod: wantClaim.Pod}
	tests := []struct {
		name       string
		bearer     string
		st         authenticationv1.TokenReviewStatus
		revErr     error
		pod        *corev1.Pod
		podErr     error
		registered bool
		wantReason string
		wantStatus int
		wantClaim  model.PodClaim
	}{
		{name: "happy", bearer: "t", st: goodStatus(), pod: goodPod(), registered: true, wantClaim: wantClaim},
		{name: "empty bearer", bearer: "", st: goodStatus(), pod: goodPod(), registered: true, wantReason: "not_pod_bound", wantStatus: 401},
		{name: "unauthenticated", bearer: "t", st: mutStatus(func(s *authenticationv1.TokenReviewStatus) { s.Authenticated = false }), pod: goodPod(), registered: true, wantReason: "not_pod_bound", wantStatus: 401},
		{name: "audience not echoed", bearer: "t", st: mutStatus(func(s *authenticationv1.TokenReviewStatus) { s.Audiences = []string{"other"} }), pod: goodPod(), registered: true, wantReason: "not_pod_bound", wantStatus: 401},
		{name: "no pod extra", bearer: "t", st: mutStatus(func(s *authenticationv1.TokenReviewStatus) { s.User.Extra = nil }), pod: goodPod(), registered: true, wantReason: "not_pod_bound", wantStatus: 401},
		{name: "non SA username", bearer: "t", st: mutStatus(func(s *authenticationv1.TokenReviewStatus) { s.User.Username = "alice" }), pod: goodPod(), registered: true, wantReason: "not_pod_bound", wantStatus: 401},
		{name: "review api error", bearer: "t", revErr: errors.New("boom"), pod: goodPod(), registered: true, wantReason: "kubernetes_unavailable", wantStatus: 503},
		{name: "pod missing", bearer: "t", st: goodStatus(), podErr: notFound, registered: true, wantReason: "pod_missing", wantStatus: 403, wantClaim: seen},
		{name: "get pod api error", bearer: "t", st: goodStatus(), podErr: errors.New("boom"), registered: true, wantReason: "kubernetes_unavailable", wantStatus: 503},
		{name: "uid differs", bearer: "t", st: goodStatus(), pod: mutPod(func(p *corev1.Pod) { p.UID = "other" }), registered: true, wantReason: "uid_mismatch", wantStatus: 403, wantClaim: seen},
		{name: "SA mismatch", bearer: "t", st: goodStatus(), pod: mutPod(func(p *corev1.Pod) { p.Spec.ServiceAccountName = "evil" }), registered: true, wantReason: "uid_mismatch", wantStatus: 403, wantClaim: seen},
		{name: "unlabelled", bearer: "t", st: goodStatus(), pod: mutPod(func(p *corev1.Pod) { p.Labels = nil }), registered: true, wantReason: "not_annotated", wantStatus: 403, wantClaim: seenUID},
		{name: "label not true", bearer: "t", st: goodStatus(), pod: mutPod(func(p *corev1.Pod) { p.Labels["nebari.dev/user-secrets"] = "True" }), registered: true, wantReason: "not_annotated", wantStatus: 403, wantClaim: seenUID},
		{name: "label without annotations", bearer: "t", st: goodStatus(), pod: mutPod(func(p *corev1.Pod) { p.Annotations = nil }), registered: true, wantReason: "not_annotated", wantStatus: 403, wantClaim: seenUID},
		{name: "empty sub annotation", bearer: "t", st: goodStatus(), pod: mutPod(func(p *corev1.Pod) { p.Annotations["nebari.dev/user-secrets-sub"] = "" }), registered: true, wantReason: "not_annotated", wantStatus: 403, wantClaim: seenUID},
		{name: "status error set", bearer: "t", st: mutStatus(func(s *authenticationv1.TokenReviewStatus) { s.Error = "x" }), pod: goodPod(), registered: true, wantReason: "not_pod_bound", wantStatus: 401},
		{name: "pod-uid missing", bearer: "t", st: mutStatus(func(s *authenticationv1.TokenReviewStatus) {
			delete(s.User.Extra, "authentication.kubernetes.io/pod-uid")
		}), pod: goodPod(), registered: true, wantReason: "not_pod_bound", wantStatus: 401},
		{name: "pod-name multi-valued", bearer: "t", st: mutStatus(func(s *authenticationv1.TokenReviewStatus) {
			s.User.Extra["authentication.kubernetes.io/pod-name"] = authenticationv1.ExtraValue{"a", "b"}
		}), pod: goodPod(), registered: true, wantReason: "not_pod_bound", wantStatus: 401},
		{name: "pod-uid multi-valued", bearer: "t", st: mutStatus(func(s *authenticationv1.TokenReviewStatus) {
			s.User.Extra["authentication.kubernetes.io/pod-uid"] = authenticationv1.ExtraValue{"uid-1", "uid-2"}
		}), pod: goodPod(), registered: true, wantReason: "not_pod_bound", wantStatus: 401},
		{name: "empty app annotation", bearer: "t", st: goodStatus(), pod: mutPod(func(p *corev1.Pod) { p.Annotations["nebari.dev/user-secrets-app"] = "" }), registered: true, wantReason: "not_annotated", wantStatus: 403, wantClaim: seenUID},
		{name: "not registered returns claim", bearer: "t", st: goodStatus(), pod: mutPod(func(p *corev1.Pod) { p.Annotations["nebari.dev/user-secrets-app"] = "dask" }), registered: false, wantReason: "not_registered", wantStatus: 403,
			wantClaim: model.PodClaim{Pod: wantClaim.Pod, App: "dask", Principal: wantClaim.Principal, Created: created}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rev := &fakeReviewer{st: tt.st, err: tt.revErr}
			v := NewPodVerifier(rev, fakePods{pod: tt.pod, err: tt.podErr}, fakeReg{ok: tt.registered})
			got, err := v.Verify(context.Background(), tt.bearer)
			if tt.bearer != "" && !reflect.DeepEqual(rev.auds, []string{"user-secrets"}) {
				t.Errorf("review audiences = %v", rev.auds)
			}
			if tt.wantReason == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				var de *DenyError
				if !errors.As(err, &de) || de.Reason != tt.wantReason || de.Status != tt.wantStatus {
					t.Fatalf("err = %v, want reason %s status %d", err, tt.wantReason, tt.wantStatus)
				}
			}
			if !reflect.DeepEqual(got, tt.wantClaim) {
				t.Errorf("claim = %+v, want %+v", got, tt.wantClaim)
			}
		})
	}
}

func TestKubeAdapters(t *testing.T) {
	tests := []struct {
		name     string
		reviewE  error
		podName  string
		wantErr  bool
		notFound bool
	}{
		{name: "ok", podName: "jupyter-alice"},
		{name: "pod not found", podName: "nope", wantErr: true, notFound: true},
		{name: "review api error", podName: "jupyter-alice", reviewE: errors.New("down")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fake.NewClientset(goodPod())
			var gotSpec authenticationv1.TokenReviewSpec
			c.PrependReactor("create", "tokenreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
				if tt.reviewE != nil {
					return true, nil, tt.reviewE
				}
				tr := a.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
				gotSpec = tr.Spec
				tr.Status = goodStatus()
				return true, tr, nil
			})
			st, rerr := NewKubeTokenReviewer(c).Review(context.Background(), "tok", []string{"user-secrets"})
			if (rerr != nil) != (tt.reviewE != nil) {
				t.Fatalf("review err = %v", rerr)
			}
			if rerr == nil && (!st.Authenticated || gotSpec.Token != "tok" || !reflect.DeepEqual(gotSpec.Audiences, []string{"user-secrets"})) {
				t.Fatalf("review: st=%+v spec=%+v", st, gotSpec)
			}
			p, gerr := NewKubePodGetter(c).GetPod(context.Background(), "ns1", tt.podName)
			if (gerr != nil) != tt.wantErr || apierrors.IsNotFound(gerr) != tt.notFound {
				t.Fatalf("getpod err = %v", gerr)
			}
			if gerr == nil && p.UID != "uid-1" {
				t.Fatalf("pod = %v", p)
			}
		})
	}
}
