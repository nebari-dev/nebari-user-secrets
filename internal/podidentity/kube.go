package podidentity

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// KubeTokenReviewer implements TokenReviewer with the Kubernetes TokenReview API.
type KubeTokenReviewer struct{ c kubernetes.Interface }

func NewKubeTokenReviewer(c kubernetes.Interface) *KubeTokenReviewer {
	return &KubeTokenReviewer{c: c}
}

func (k *KubeTokenReviewer) Review(ctx context.Context, token string, audiences []string) (authenticationv1.TokenReviewStatus, error) {
	ctx, sp := otel.Tracer("nebari-user-secrets").Start(ctx, "podidentity.KubeTokenReviewer.Review")
	defer sp.End()
	tr := &authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: token, Audiences: audiences}}
	out, err := k.c.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		sp.RecordError(errors.New("token review failed"))
		return authenticationv1.TokenReviewStatus{}, err
	}
	return out.Status, nil
}

// KubePodGetter implements PodGetter with a direct API read.
type KubePodGetter struct{ c kubernetes.Interface }

func NewKubePodGetter(c kubernetes.Interface) *KubePodGetter { return &KubePodGetter{c: c} }

func (k *KubePodGetter) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	ctx, sp := otel.Tracer("nebari-user-secrets").Start(ctx, "podidentity.KubePodGetter.GetPod")
	defer sp.End()
	pod, err := k.c.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		sp.RecordError(errors.New("get pod failed"))
	}
	return pod, err
}
