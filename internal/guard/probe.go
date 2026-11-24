package guard

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

// PauseImage is the probe pods' image, pinned by the multi-arch index digest.
// Read with: docker buildx imagetools inspect registry.k8s.io/pause:3.10
const PauseImage = "registry.k8s.io/pause:3.10@sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a"

const (
	probeGenerateName = "user-secrets-probe-"
	probeTimeout      = 20 * time.Second
	labelKey          = "nebari.dev/user-secrets"
	annotationSub     = "nebari.dev/user-secrets-sub"
	annotationApp     = "nebari.dev/user-secrets-app"
)

// Outcome is one probe's result. The zero value is OutcomeInconclusive, so an
// unset outcome never reads as a pass.
type Outcome int

const (
	// OutcomeInconclusive: the probe could not be interpreted (another
	// denial, Pod Security, RBAC, a server error, a timeout, a transport
	// failure).
	OutcomeInconclusive Outcome = iota
	// OutcomeDeniedAsExpected: a guarded probe was denied by its policy's
	// status cause (labelled by B, unlabelled by A).
	OutcomeDeniedAsExpected
	// OutcomeAdmitted: the dry-run create succeeded. As designed for the
	// canary; confirmed bad for a guarded probe.
	OutcomeAdmitted
	// OutcomeDenied: the canary was refused by admission (confirmed bad).
	// Guarded probes never report it.
	OutcomeDenied
)

// ProbeOutcome is one probe's outcome with a fixed-text detail (an error
// class, never error text). Detail is empty unless the outcome is
// inconclusive.
type ProbeOutcome struct {
	Outcome Outcome
	Detail  string
}

// ProbeResult is what the three dry-run creates showed, per probe, so a
// concluded admission or canary denial is never hidden by another probe being
// inconclusive. As designed: Labelled and Unlabelled OutcomeDeniedAsExpected,
// Canary OutcomeAdmitted.
type ProbeResult struct {
	Labelled, Unlabelled, Canary ProbeOutcome
}

// Inconclusive reports whether any probe is inconclusive.
func (r ProbeResult) Inconclusive() bool {
	return r.Labelled.Outcome == OutcomeInconclusive || r.Unlabelled.Outcome == OutcomeInconclusive ||
		r.Canary.Outcome == OutcomeInconclusive
}

// Detail lists the inconclusive probes as "<probe> probe: <class>", joined by
// "; ". It is empty when every probe concluded.
func (r ProbeResult) Detail() string {
	var details []string
	for _, x := range []struct {
		kind probeKind
		o    ProbeOutcome
	}{{probeLabelled, r.Labelled}, {probeUnlabelled, r.Unlabelled}, {probeCanary, r.Canary}} {
		if x.o.Outcome == OutcomeInconclusive {
			details = append(details, fmt.Sprintf("%s probe: %s", x.kind, x.o.Detail))
		}
	}
	return strings.Join(details, "; ")
}

// Prober runs the three probes.
type Prober interface {
	Probe(ctx context.Context) (ProbeResult, error)
}

type probeKind int

const (
	probeLabelled probeKind = iota
	probeUnlabelled
	probeCanary
)

func (k probeKind) String() string {
	switch k {
	case probeLabelled:
		return "labelled"
	case probeUnlabelled:
		return "unlabelled"
	default:
		return "canary"
	}
}

// DryRunProber creates probe pods with a server-side dry run in the service
// namespace, as whatever identity the client carries.
type DryRunProber struct {
	pods       kubernetes.Interface
	namespace  string
	pauseImage string
	// The exact denial messages, read from the embedded cluster/policies.yaml.
	msgGuard, msgCreators string
	initErr               error
}

// NewDryRunProber returns a prober. The expected denial messages come from the
// embedded policies; if they cannot be read, every Probe is inconclusive.
func NewDryRunProber(c kubernetes.Interface, namespace, pauseImage string) *DryRunProber {
	p := &DryRunProber{pods: c, namespace: namespace, pauseImage: pauseImage}
	e, err := NewExpectation(namespace)
	if err != nil {
		p.initErr = err
		return p
	}
	// Validation 0 of each policy is the rule the matching probe trips.
	if len(e.guardPolicy.Spec.Validations) == 0 || len(e.creatorsPolicy.Spec.Validations) == 0 {
		p.initErr = errors.New("embedded policies have no validations")
		return p
	}
	p.msgGuard = e.guardPolicy.Spec.Validations[0].Message
	p.msgCreators = e.creatorsPolicy.Spec.Validations[0].Message
	return p
}

// probePod builds a restricted-compliant pod. The labelled probe carries the
// label and both annotations, so policy A admits it and only B can deny it. The
// unlabelled probe carries the annotations only, so B does not match it and
// only A can deny it. The canary carries no user-secrets metadata.
func probePod(namespace string, kind probeKind, image string) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{GenerateName: probeGenerateName, Namespace: namespace},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: ptr.To(false),
			RestartPolicy:                corev1.RestartPolicyNever,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   ptr.To(true),
				RunAsUser:      ptr.To(int64(65532)),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name:  "pause",
				Image: image,
				// Small requests and limits so a namespace ResourceQuota or
				// LimitRange does not deny the canary.
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("16Mi")},
					Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("16Mi")},
				},
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: ptr.To(false),
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
			}},
		},
	}
	if kind != probeCanary {
		p.Annotations = map[string]string{annotationSub: "probe", annotationApp: "probe"}
	}
	if kind == probeLabelled {
		p.Labels = map[string]string{labelKey: "true"}
	}
	return p
}

// Probe runs the three probes in order. It returns an error only when ctx ends
// before they complete; every API failure goes into the result.
func (p *DryRunProber) Probe(ctx context.Context) (ProbeResult, error) {
	ctx, span := otel.Tracer("nebari-user-secrets").Start(ctx, "guard.Probe")
	defer span.End()

	// Every outcome starts inconclusive (the zero value) and is set once its
	// probe concludes.
	var res ProbeResult
	if p.initErr != nil {
		span.RecordError(p.initErr)
		d := ProbeOutcome{Outcome: OutcomeInconclusive, Detail: "messages_unavailable"}
		return ProbeResult{Labelled: d, Unlabelled: d, Canary: d}, nil
	}
	inconclusive := func(k probeKind, class string) ProbeOutcome {
		// Fixed text only: the probe and the class, never the error's text.
		span.AddEvent("guard.probe_inconclusive", trace.WithAttributes(
			attribute.String("probe", k.String()), attribute.String("class", class)))
		return ProbeOutcome{Outcome: OutcomeInconclusive, Detail: class}
	}

	for _, kind := range []probeKind{probeLabelled, probeUnlabelled, probeCanary} {
		err := p.create(ctx, kind)
		if ctx.Err() != nil {
			span.RecordError(ctx.Err())
			return res, ctx.Err()
		}
		class := classify(err)
		switch kind {
		case probeLabelled:
			switch {
			case err == nil: // admitted: confirmed bad
				res.Labelled = ProbeOutcome{Outcome: OutcomeAdmitted}
			case class == classDenied && deniedBy(err, creatorsName, p.msgCreators):
				res.Labelled = ProbeOutcome{Outcome: OutcomeDeniedAsExpected}
			default:
				res.Labelled = inconclusive(kind, deniedClass(class))
			}
		case probeUnlabelled:
			switch {
			case err == nil:
				res.Unlabelled = ProbeOutcome{Outcome: OutcomeAdmitted}
			case class == classDenied && deniedBy(err, guardName, p.msgGuard):
				res.Unlabelled = ProbeOutcome{Outcome: OutcomeDeniedAsExpected}
			default:
				res.Unlabelled = inconclusive(kind, deniedClass(class))
			}
		case probeCanary:
			switch {
			case err == nil:
				res.Canary = ProbeOutcome{Outcome: OutcomeAdmitted}
			case class == classDenied:
				// Confirmed bad: admission refused a plain restricted pod.
				res.Canary = ProbeOutcome{Outcome: OutcomeDenied}
			default:
				res.Canary = inconclusive(kind, class)
			}
		}
	}
	return res, nil
}

func (p *DryRunProber) create(ctx context.Context, kind probeKind) error {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	_, err := p.pods.CoreV1().Pods(p.namespace).Create(ctx,
		probePod(p.namespace, kind, p.pauseImage),
		metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	return err
}

// deniedBy reports whether err is the API server's denial by the named policy
// (its binding shares the name) with exactly this message. The VAP dispatcher
// records "ValidatingAdmissionPolicy '<policy>' with binding '<binding>' denied
// request: <message>" as a status cause (k8s.io/apiserver v0.35.0
// pkg/admission/plugin/policy/validating/dispatcher.go:289-306); a webhook or a
// differently named policy cannot produce that cause for these names. The
// reason must be Forbidden or Invalid.
func deniedBy(err error, policy, message string) bool {
	var status apierrors.APIStatus
	if !errors.As(err, &status) {
		return false
	}
	st := status.Status()
	if st.Reason != metav1.StatusReasonForbidden && st.Reason != metav1.StatusReasonInvalid {
		return false
	}
	want := fmt.Sprintf("ValidatingAdmissionPolicy '%s' with binding '%s' denied request: %s", policy, policy, message)
	if st.Details == nil {
		return false
	}
	for _, c := range st.Details.Causes {
		if c.Message == want {
			return true
		}
	}
	return false
}

// Error classes for Detail. classDenied is an admission denial (a policy or
// webhook) that is not Pod Security and not an RBAC refusal.
const (
	classDenied      = "denied"
	classPodSecurity = "pod_security"
	classRBAC        = "rbac"
	classServer      = "server_error"
	classAPI         = "api_error"
	classTimeout     = "timeout"
	classTransport   = "transport"
)

// deniedClass names a denial that was not the one expected for a probe.
func deniedClass(class string) string {
	if class == classDenied {
		return "other_denial"
	}
	return class
}

// classify buckets an error without including any of its text. nil is not a
// valid input.
func classify(err error) string {
	if err == nil {
		return ""
	}
	var status apierrors.APIStatus
	if !errors.As(err, &status) {
		if errors.Is(err, context.DeadlineExceeded) {
			return classTimeout
		}
		return classTransport
	}
	switch {
	case apierrors.IsTimeout(err), apierrors.IsServerTimeout(err), apierrors.IsInternalError(err),
		apierrors.IsServiceUnavailable(err), apierrors.IsTooManyRequests(err),
		status.Status().Code >= 500:
		return classServer
	case apierrors.IsForbidden(err) || apierrors.IsInvalid(err):
		msg := err.Error()
		switch {
		case strings.Contains(msg, "violates PodSecurity"):
			return classPodSecurity
		case apierrors.IsForbidden(err) && strings.Contains(msg, "cannot create resource"):
			return classRBAC
		}
		return classDenied
	}
	return classAPI
}
