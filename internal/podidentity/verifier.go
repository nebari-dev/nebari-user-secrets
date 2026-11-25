// Package podidentity turns a projected ServiceAccount token into a trusted
// model.PodClaim.
package podidentity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

const (
	Audience       = "user-secrets"
	LabelKey       = "nebari.dev/user-secrets"
	AnnotationSub  = "nebari.dev/user-secrets-sub"
	AnnotationApp  = "nebari.dev/user-secrets-app"
	extraPodName   = "authentication.kubernetes.io/pod-name"
	extraPodUID    = "authentication.kubernetes.io/pod-uid"
	ReasonNotBound = "not_pod_bound"
	ReasonUID      = "uid_mismatch"
	ReasonNotAnn   = "not_annotated"
	ReasonNotReg   = "not_registered"
	ReasonPodGone  = "pod_missing"
	ReasonKubeDown = "kubernetes_unavailable"
)

// DenyError is a verification denial carrying the spec's reason and the HTTP
// status the resolve handler should return.
type DenyError struct {
	Reason string
	Status int
}

func (e *DenyError) Error() string { return "pod verification denied: " + e.Reason }

func deny(reason string, status int) error { return &DenyError{Reason: reason, Status: status} }

type TokenReviewer interface {
	Review(ctx context.Context, token string, audiences []string) (authenticationv1.TokenReviewStatus, error)
}

type PodGetter interface {
	GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error)
}

type Registry interface {
	WorkloadAllowed(app model.AppID, namespace, serviceAccount string) bool
}

type PodVerifier struct {
	reviewer TokenReviewer
	pods     PodGetter
	reg      Registry
}

func NewPodVerifier(r TokenReviewer, p PodGetter, reg Registry) *PodVerifier {
	return &PodVerifier{reviewer: r, pods: p, reg: reg}
}

// Verify validates a pod-bound ServiceAccount token. On not_registered it
// returns the claim built so far with the error. On pod_missing, uid_mismatch
// and not_annotated it returns a claim holding only the pod identity for the
// audit line: namespace, pod name and ServiceAccount from the TokenReview, and
// the UID only once it matched the pod; sub and app stay empty, and callers
// must not resolve or record status with it. On every other failure the claim
// is zero.
func (v *PodVerifier) Verify(ctx context.Context, bearer string) (_ model.PodClaim, err error) {
	ctx, sp := otel.Tracer("nebari-user-secrets").Start(ctx, "podidentity.Verify")
	defer sp.End()
	defer func() { recordErr(sp, err) }()

	if bearer == "" {
		return model.PodClaim{}, deny(ReasonNotBound, http.StatusUnauthorized)
	}
	st, rerr := v.reviewer.Review(ctx, bearer, []string{Audience})
	if rerr != nil {
		return model.PodClaim{}, deny(ReasonKubeDown, http.StatusServiceUnavailable)
	}
	if !st.Authenticated || st.Error != "" || !slices.Contains(st.Audiences, Audience) {
		return model.PodClaim{}, deny(ReasonNotBound, http.StatusUnauthorized)
	}
	ns, sa, ok := splitSA(st.User.Username)
	if !ok {
		return model.PodClaim{}, deny(ReasonNotBound, http.StatusUnauthorized)
	}
	nameV, uidV := st.User.Extra[extraPodName], st.User.Extra[extraPodUID]
	if len(nameV) != 1 || len(uidV) != 1 || nameV[0] == "" || uidV[0] == "" {
		return model.PodClaim{}, deny(ReasonNotBound, http.StatusUnauthorized)
	}

	name, uid := nameV[0], uidV[0]
	seen := model.PodClaim{Pod: model.PodIdentity{Namespace: ns, Name: name, ServiceAccount: sa}}
	pod, gerr := v.pods.GetPod(ctx, ns, name)
	switch {
	case apierrors.IsNotFound(gerr):
		return seen, deny(ReasonPodGone, http.StatusForbidden)
	case gerr != nil:
		return model.PodClaim{}, deny(ReasonKubeDown, http.StatusServiceUnavailable)
	}
	if string(pod.UID) != uid || pod.Spec.ServiceAccountName != sa {
		return seen, deny(ReasonUID, http.StatusForbidden)
	}
	seen.Pod.UID = uid
	sub, app := pod.Annotations[AnnotationSub], pod.Annotations[AnnotationApp]
	if pod.Labels[LabelKey] != "true" || sub == "" || app == "" {
		return seen, deny(ReasonNotAnn, http.StatusForbidden)
	}

	claim := model.PodClaim{
		Pod:       model.PodIdentity{Namespace: ns, Name: pod.Name, UID: uid, ServiceAccount: sa},
		App:       model.AppID(app),
		Principal: model.Principal{Kind: "user", Sub: sub},
		Created:   pod.CreationTimestamp.Time,
	}
	if !v.reg.WorkloadAllowed(claim.App, ns, sa) {
		return claim, deny(ReasonNotReg, http.StatusForbidden)
	}
	return claim, nil
}

func recordErr(sp trace.Span, err error) {
	if err != nil {
		sp.RecordError(errors.New(fmt.Sprint(err)))
	}
}

func splitSA(u string) (ns, name string, ok bool) {
	parts := strings.Split(u, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" || parts[2] == "" || parts[3] == "" {
		return "", "", false
	}
	return parts[2], parts[3], true
}
