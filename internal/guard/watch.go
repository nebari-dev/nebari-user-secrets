package guard

import (
	"context"

	"go.opentelemetry.io/otel"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// AdmissionWatcher exposes the watched guard objects. Every accessor returns
// ok == false when either object of a pair (or the ConfigMap) is missing.
type AdmissionWatcher interface {
	Policies() (guard, creators *admissionregistrationv1.ValidatingAdmissionPolicy, ok bool)
	Bindings() (guard, creators *admissionregistrationv1.ValidatingAdmissionPolicyBinding, ok bool)
	Creators() (*corev1.ConfigMap, bool)
	Synced() bool
}

// InformerWatcher watches the two policies, the two bindings and the
// user-secrets-creators ConfigMap with one informer each. Every informer uses a
// metadata.name field selector, so a reader role can grant list and watch by
// resourceNames.
type InformerWatcher struct {
	namespace string
	changed   chan struct{}

	policyGuard, policyCreators   cache.SharedIndexInformer
	bindingGuard, bindingCreators cache.SharedIndexInformer
	configMap                     cache.SharedIndexInformer
}

// NewInformerWatcher builds the informers; call Start to run them.
func NewInformerWatcher(c kubernetes.Interface, namespace string) *InformerWatcher {
	w := &InformerWatcher{namespace: namespace, changed: make(chan struct{}, 1)}
	policies := c.AdmissionregistrationV1().ValidatingAdmissionPolicies()
	bindings := c.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings()
	cms := c.CoreV1().ConfigMaps(namespace)

	w.policyGuard = w.informer(c, &admissionregistrationv1.ValidatingAdmissionPolicy{}, guardName,
		func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) { return policies.List(ctx, o) },
		func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
			return policies.Watch(ctx, o)
		})
	w.policyCreators = w.informer(c, &admissionregistrationv1.ValidatingAdmissionPolicy{}, creatorsName,
		func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) { return policies.List(ctx, o) },
		func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
			return policies.Watch(ctx, o)
		})
	w.bindingGuard = w.informer(c, &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}, guardName,
		func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) { return bindings.List(ctx, o) },
		func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
			return bindings.Watch(ctx, o)
		})
	w.bindingCreators = w.informer(c, &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}, creatorsName,
		func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) { return bindings.List(ctx, o) },
		func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
			return bindings.Watch(ctx, o)
		})
	w.configMap = w.informer(c, &corev1.ConfigMap{}, creatorsName,
		func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) { return cms.List(ctx, o) },
		func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) { return cms.Watch(ctx, o) })
	return w
}

func (w *InformerWatcher) informer(c kubernetes.Interface, example runtime.Object, name string,
	list func(context.Context, metav1.ListOptions) (runtime.Object, error),
	watchFn func(context.Context, metav1.ListOptions) (watch.Interface, error),
) cache.SharedIndexInformer {
	sel := fields.OneTermEqualSelector("metadata.name", name).String()
	lw := &cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) {
			o.FieldSelector = sel
			return list(ctx, o)
		},
		WatchFuncWithContext: func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
			o.FieldSelector = sel
			return watchFn(ctx, o)
		},
	}
	// The wrapper tells the reflector when the client (the fake in tests) cannot
	// stream an initial list, so it falls back to list-then-watch.
	inf := cache.NewSharedIndexInformer(cache.ToListWatcherWithWatchListSemantics(lw, c), example, 0, cache.Indexers{})
	notify := func() {
		select {
		case w.changed <- struct{}{}:
		default:
		}
	}
	// AddEventHandler fails only on a stopped informer, which these are not yet.
	_, _ = inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { notify() },
		UpdateFunc: func(_, _ any) { notify() },
		DeleteFunc: func(any) { notify() },
	})
	return inf
}

// Start runs the informers until ctx is done. It returns once they are started,
// not once they are synced; use Synced.
func (w *InformerWatcher) Start(ctx context.Context) {
	_, span := otel.Tracer("nebari-user-secrets").Start(ctx, "guard.Start")
	defer span.End()
	for _, inf := range w.all() {
		go inf.Run(ctx.Done())
	}
}

// Changed signals that a watched object was added, updated or deleted. The
// channel is buffered with capacity 1 and sent to without blocking, so events
// coalesce.
func (w *InformerWatcher) Changed() <-chan struct{} { return w.changed }

// Synced reports whether every informer has completed its initial list.
func (w *InformerWatcher) Synced() bool {
	for _, inf := range w.all() {
		if !inf.HasSynced() {
			return false
		}
	}
	return true
}

func (w *InformerWatcher) all() []cache.SharedIndexInformer {
	return []cache.SharedIndexInformer{w.policyGuard, w.policyCreators, w.bindingGuard, w.bindingCreators, w.configMap}
}

// Policies returns deep copies of the two policies.
func (w *InformerWatcher) Policies() (guard, creators *admissionregistrationv1.ValidatingAdmissionPolicy, ok bool) {
	g, gok := get[*admissionregistrationv1.ValidatingAdmissionPolicy](w.policyGuard, guardName)
	c, cok := get[*admissionregistrationv1.ValidatingAdmissionPolicy](w.policyCreators, creatorsName)
	if !gok || !cok {
		return nil, nil, false
	}
	return g.DeepCopy(), c.DeepCopy(), true
}

// Bindings returns deep copies of the two bindings.
func (w *InformerWatcher) Bindings() (guard, creators *admissionregistrationv1.ValidatingAdmissionPolicyBinding, ok bool) {
	g, gok := get[*admissionregistrationv1.ValidatingAdmissionPolicyBinding](w.bindingGuard, guardName)
	c, cok := get[*admissionregistrationv1.ValidatingAdmissionPolicyBinding](w.bindingCreators, creatorsName)
	if !gok || !cok {
		return nil, nil, false
	}
	return g.DeepCopy(), c.DeepCopy(), true
}

// Creators returns a deep copy of the user-secrets-creators ConfigMap.
func (w *InformerWatcher) Creators() (*corev1.ConfigMap, bool) {
	cm, ok := get[*corev1.ConfigMap](w.configMap, w.namespace+"/"+creatorsName)
	if !ok {
		return nil, false
	}
	return cm.DeepCopy(), true
}

func get[T any](inf cache.SharedIndexInformer, key string) (T, bool) {
	var zero T
	obj, exists, err := inf.GetStore().GetByKey(key)
	if err != nil || !exists {
		return zero, false
	}
	t, ok := obj.(T)
	return t, ok
}
