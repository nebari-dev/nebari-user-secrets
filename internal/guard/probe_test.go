package guard

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	psapi "k8s.io/pod-security-admission/api"
	pspolicy "k8s.io/pod-security-admission/policy"
)

// These literals are copied from cluster/policies.yaml on purpose: the prober
// reads the messages from the embedded YAML, so this test fails if the YAML
// changes and the prober's expectations do not follow.
const (
	msgA = "user-secrets: annotated pods must carry the label nebari.dev/user-secrets=true"
	msgB = "user-secrets: requester is not a registered creator for this namespace and app"
)

func denied(reason metav1.StatusReason, code int32, msg string) error {
	return &apierrors.StatusError{ErrStatus: metav1.Status{
		Status: metav1.StatusFailure, Code: code, Reason: reason, Message: msg,
	}}
}

// vapDeniedBy builds the error the API server returns for a VAP denial
// (dispatcher.go:289-306 at apiserver v0.35.0): the formatted message is also
// recorded as a status cause.
func vapDeniedBy(policy, msg string) error {
	m := "ValidatingAdmissionPolicy '" + policy + "' with binding '" + policy + "' denied request: " + msg
	err := denied(metav1.StatusReasonInvalid, 422, "pods \"x\" is invalid: "+m).(*apierrors.StatusError)
	err.ErrStatus.Details = &metav1.StatusDetails{Causes: []metav1.StatusCause{{Message: m}}}
	return err
}

// vapDenied is a denial by the real policy a message belongs to.
func vapDenied(msg string) error {
	if msg == msgB {
		return vapDeniedBy(creatorsName, msg)
	}
	return vapDeniedBy(guardName, msg)
}

var errTransport = &net.OpError{Op: "dial", Err: errors.New("connection refused")}

func TestProbeKinds(t *testing.T) {
	cases := []struct {
		name            string
		kind            probeKind
		wantLabel       bool
		wantAnnotations bool
	}{
		{"labelled", probeLabelled, true, true},
		{"unlabelled annotated", probeUnlabelled, false, true},
		{"canary", probeCanary, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := probePod("ns1", tc.kind, "img")
			if p.Namespace != "ns1" || p.GenerateName != "user-secrets-probe-" || p.Name != "" {
				t.Errorf("metadata: ns=%q generateName=%q name=%q", p.Namespace, p.GenerateName, p.Name)
			}
			if p.Spec.AutomountServiceAccountToken == nil || *p.Spec.AutomountServiceAccountToken {
				t.Error("automountServiceAccountToken must be false")
			}
			if p.Spec.ServiceAccountName != "" {
				t.Error("probe must use the default ServiceAccount")
			}
			_, hasLabel := p.Labels["nebari.dev/user-secrets"]
			if hasLabel != tc.wantLabel {
				t.Errorf("label present = %v, want %v", hasLabel, tc.wantLabel)
			}
			if tc.wantLabel && p.Labels["nebari.dev/user-secrets"] != "true" {
				t.Error("label value must be true")
			}
			_, hasSub := p.Annotations["nebari.dev/user-secrets-sub"]
			_, hasApp := p.Annotations["nebari.dev/user-secrets-app"]
			if hasSub != tc.wantAnnotations || hasApp != tc.wantAnnotations {
				t.Errorf("annotations sub=%v app=%v, want %v", hasSub, hasApp, tc.wantAnnotations)
			}
		})
	}
}

func TestProbePodsRestricted(t *testing.T) {
	ev, err := pspolicy.NewEvaluator(pspolicy.DefaultChecks(), nil)
	if err != nil {
		t.Fatal(err)
	}
	lv := psapi.LevelVersion{Level: psapi.LevelRestricted, Version: psapi.LatestVersion()}
	for _, kind := range []probeKind{probeLabelled, probeUnlabelled, probeCanary} {
		p := probePod("ns1", kind, PauseImage)
		for _, r := range ev.EvaluatePod(lv, &p.ObjectMeta, &p.Spec) {
			if !r.Allowed {
				t.Errorf("probe kind %d violates restricted: %s", kind, r.ForbiddenReason)
			}
		}
	}
}

func TestPauseImagePinnedByDigest(t *testing.T) {
	if !strings.HasPrefix(PauseImage, "registry.k8s.io/pause:3.10@sha256:") || len(PauseImage) != len("registry.k8s.io/pause:3.10@sha256:")+64 {
		t.Errorf("pause image not pinned by digest: %s", PauseImage)
	}
}

func TestProberMessagesFollowPolicies(t *testing.T) {
	p := NewDryRunProber(fake.NewClientset(), testNS, PauseImage)
	if p.msgGuard != msgA || p.msgCreators != msgB {
		t.Errorf("messages = %q / %q", p.msgGuard, p.msgCreators)
	}
}

func TestProbe(t *testing.T) {
	webhookWith := func(msg string) error {
		return denied(metav1.StatusReasonForbidden, 403, `admission webhook "x" denied the request: `+msg)
	}
	timeoutErr := apierrors.NewTimeoutError("slow", 1)
	pss := denied(metav1.StatusReasonForbidden, 403, `pods "x" is forbidden: violates PodSecurity "restricted:latest": privileged`)
	rbacForbidden := denied(metav1.StatusReasonForbidden, 403, `pods is forbidden: User "system:serviceaccount:us-system:svc" cannot create resource "pods" in API group "" in the namespace "us-system"`)
	webhookForbidden := denied(metav1.StatusReasonForbidden, 403, `admission webhook "x.example" denied the request: nope`)

	asDesigned := ProbeOutcome{Outcome: OutcomeDeniedAsExpected}
	admitted := ProbeOutcome{Outcome: OutcomeAdmitted}
	canaryDenied := ProbeOutcome{Outcome: OutcomeDenied}
	inc := func(class string) ProbeOutcome { return ProbeOutcome{Outcome: OutcomeInconclusive, Detail: class} }
	allGood := func(r ProbeResult) ProbeResult {
		if r.Labelled == (ProbeOutcome{}) {
			r.Labelled = asDesigned
		}
		if r.Unlabelled == (ProbeOutcome{}) {
			r.Unlabelled = asDesigned
		}
		if r.Canary == (ProbeOutcome{}) {
			r.Canary = admitted
		}
		return r
	}

	cases := []struct {
		name                      string
		labelled, unlabelled, can error
		want                      ProbeResult // zero outcomes are filled with the as-designed ones
		detailHas                 []string
	}{
		{name: "all as designed", labelled: vapDenied(msgB), unlabelled: vapDenied(msgA),
			want: ProbeResult{}},
		{name: "labelled: webhook carrying B's message is inconclusive", labelled: webhookWith(msgB), unlabelled: vapDenied(msgA),
			want:      ProbeResult{Labelled: inc("other_denial")},
			detailHas: []string{"labelled", "other_denial"}},
		{name: "unlabelled: webhook carrying A's message is inconclusive", labelled: vapDenied(msgB), unlabelled: webhookWith(msgA),
			want:      ProbeResult{Unlabelled: inc("other_denial")},
			detailHas: []string{"unlabelled", "other_denial"}},
		{name: "labelled: other-named VAP with B's message is inconclusive", labelled: vapDeniedBy("lookalike", msgB), unlabelled: vapDenied(msgA),
			want:      ProbeResult{Labelled: inc("other_denial")},
			detailHas: []string{"labelled", "other_denial"}},
		{name: "unlabelled: other-named VAP with A's message is inconclusive", labelled: vapDenied(msgB), unlabelled: vapDeniedBy("lookalike", msgA),
			want:      ProbeResult{Unlabelled: inc("other_denial")},
			detailHas: []string{"unlabelled", "other_denial"}},
		{name: "labelled: client-side deadline is inconclusive", labelled: context.DeadlineExceeded, unlabelled: vapDenied(msgA),
			want:      ProbeResult{Labelled: inc("timeout")},
			detailHas: []string{"labelled", "timeout"}},
		{name: "labelled admitted is confirmed bad", labelled: nil, unlabelled: vapDenied(msgA),
			want: ProbeResult{Labelled: admitted}},
		{name: "unlabelled admitted is confirmed bad", labelled: vapDenied(msgB), unlabelled: nil,
			want: ProbeResult{Unlabelled: admitted}},
		{name: "labelled admitted while the canary is inconclusive stays a concluded admission", labelled: nil, unlabelled: vapDenied(msgA),
			can:       errTransport,
			want:      ProbeResult{Labelled: admitted, Canary: inc("transport")},
			detailHas: []string{"canary", "transport"}},
		{name: "unlabelled admitted while the labelled probe is inconclusive stays a concluded admission", labelled: pss, unlabelled: nil,
			want:      ProbeResult{Labelled: inc("pod_security"), Unlabelled: admitted},
			detailHas: []string{"labelled", "pod_security"}},
		{name: "labelled denied by A's message is inconclusive", labelled: vapDenied(msgA), unlabelled: vapDenied(msgA),
			want:      ProbeResult{Labelled: inc("other_denial")},
			detailHas: []string{"labelled", "other_denial"}},
		{name: "unlabelled denied by B's message is inconclusive", labelled: vapDenied(msgB), unlabelled: vapDenied(msgB),
			want:      ProbeResult{Unlabelled: inc("other_denial")},
			detailHas: []string{"unlabelled", "other_denial"}},
		{name: "labelled denied by Pod Security is inconclusive", labelled: pss, unlabelled: vapDenied(msgA),
			want:      ProbeResult{Labelled: inc("pod_security")},
			detailHas: []string{"labelled", "pod_security"}},
		{name: "unlabelled transport error is inconclusive", labelled: vapDenied(msgB), unlabelled: errTransport,
			want:      ProbeResult{Unlabelled: inc("transport")},
			detailHas: []string{"unlabelled", "transport"}},
		{name: "labelled timeout is inconclusive", labelled: timeoutErr, unlabelled: vapDenied(msgA),
			want:      ProbeResult{Labelled: inc("server_error")},
			detailHas: []string{"labelled", "server_error"}},
		{name: "labelled 5xx is inconclusive", labelled: apierrors.NewInternalError(errors.New("boom")), unlabelled: vapDenied(msgA),
			want:      ProbeResult{Labelled: inc("server_error")},
			detailHas: []string{"labelled", "server_error"}},
		{name: "labelled RBAC forbidden is inconclusive", labelled: rbacForbidden, unlabelled: vapDenied(msgA),
			want:      ProbeResult{Labelled: inc("rbac")},
			detailHas: []string{"labelled", "rbac"}},
		{name: "canary denied by admission is confirmed bad", labelled: vapDenied(msgB), unlabelled: vapDenied(msgA),
			can:  webhookForbidden,
			want: ProbeResult{Canary: canaryDenied}},
		{name: "canary denied by a policy is confirmed bad", labelled: vapDenied(msgB), unlabelled: vapDenied(msgA),
			can:  vapDenied("user-secrets: something"),
			want: ProbeResult{Canary: canaryDenied}},
		{name: "canary denied by Pod Security is inconclusive", labelled: vapDenied(msgB), unlabelled: vapDenied(msgA),
			can:       pss,
			want:      ProbeResult{Canary: inc("pod_security")},
			detailHas: []string{"canary", "pod_security"}},
		{name: "canary transport error is inconclusive", labelled: vapDenied(msgB), unlabelled: vapDenied(msgA),
			can:       errTransport,
			want:      ProbeResult{Canary: inc("transport")},
			detailHas: []string{"canary", "transport"}},
		{name: "canary 5xx is inconclusive", labelled: vapDenied(msgB), unlabelled: vapDenied(msgA),
			can:       apierrors.NewServiceUnavailable("down"),
			want:      ProbeResult{Canary: inc("server_error")},
			detailHas: []string{"canary", "server_error"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewClientset()
			cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
				p := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
				var err error
				switch {
				case p.Labels["nebari.dev/user-secrets"] != "":
					err = tc.labelled
				case p.Annotations["nebari.dev/user-secrets-sub"] != "":
					err = tc.unlabelled
				default:
					err = tc.can
				}
				return true, p, err
			})
			got, err := NewDryRunProber(cs, testNS, PauseImage).Probe(context.Background())
			if err != nil {
				t.Fatalf("Probe error: %v", err)
			}
			want := allGood(tc.want)
			if got != want {
				t.Errorf("result = %+v, want %+v", got, want)
			}
			detail := got.Detail()
			for _, s := range tc.detailHas {
				if !strings.Contains(detail, s) {
					t.Errorf("detail %q lacks %q", detail, s)
				}
			}
			if !want.Inconclusive() && detail != "" {
				t.Errorf("unexpected detail %q", detail)
			}
		})
	}
}

func TestProbeEveryCreateIsDryRun(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		return true, a.(k8stesting.CreateAction).GetObject(), nil
	})
	if _, err := NewDryRunProber(cs, testNS, PauseImage).Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	var n int
	for _, a := range cs.Actions() {
		c, ok := a.(k8stesting.CreateActionImpl)
		if !ok {
			t.Fatalf("unexpected action %v", a)
		}
		n++
		if len(c.CreateOptions.DryRun) != 1 || c.CreateOptions.DryRun[0] != metav1.DryRunAll {
			t.Errorf("create %d dryRun = %v", n, c.CreateOptions.DryRun)
		}
		if c.GetNamespace() != testNS {
			t.Errorf("create %d namespace = %q", n, c.GetNamespace())
		}
	}
	if n != 3 {
		t.Errorf("creates = %d, want 3", n)
	}
}

func TestProbeContextCancelled(t *testing.T) {
	cs := fake.NewClientset()
	ctx, cancel := context.WithCancel(context.Background())
	cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		cancel()
		return true, nil, context.Canceled
	})
	_, err := NewDryRunProber(cs, testNS, PauseImage).Probe(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}
