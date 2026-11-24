// Package guard verifies that the admission policies protecting user-secrets
// pods are in force, and keeps the replica's verdict.
package guard

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

// GuardState is the guard's current verification state, as reported by the
// management API's status route.
type GuardState struct {
	State  string // "verified" | "confirmed_bad" | "unknown" | "overridden"
	Mode   model.GuardMode
	Reason string
}

const (
	guardStateName       = "user-secrets-guard-state"
	keyFingerprint       = "fingerprint"
	keyVerifiedSince     = "verifiedSince"
	keyBadMarker         = "badMarker"
	clockGenerateName    = "user-secrets-guard-clock-"
	maxAdvanceAttempts   = 5
	verifiedSinceLayout  = time.RFC3339
	errNoCreationTimeMsg = "dry-run create returned no creationTimestamp"
)

// StoredState is the content of the user-secrets-guard-state ConfigMap.
// VerifiedSince is zero when the stored value is absent or unparseable.
// BadMarker is empty when no marker is stored. A replica that sees
// confirmed_bad stores a fresh marker value; the next verifiedSince move clears
// it only if it is the value that replica observed before reading the server
// time, so a probe-only bad state (no fingerprint change) still moves
// verifiedSince after a restart or on another replica, and a marking made after
// a move's observation survives that move.
type StoredState struct {
	Fingerprint   string
	VerifiedSince time.Time
	BadMarker     string
}

// StateStore persists the fingerprint and verifiedSince shared by all
// replicas.
type StateStore interface {
	// Synced reports whether the stored state has been listed once.
	Synced() bool
	// Stored returns the last stored state seen through the watch; ok is false
	// when there is none.
	Stored() (StoredState, bool)
	// ServerNow returns a time set by the API server, comparable to a pod's
	// creationTimestamp. It never falls back to the local clock.
	ServerNow(ctx context.Context) (time.Time, error)
	// Advance stores fingerprint and max(stored verifiedSince, verifiedSince)
	// with resourceVersion concurrency and returns what was stored. It clears
	// the bad-seen marker only if the stored marker (on every re-read) equals
	// observedMarker, "" meaning absent; otherwise the marker is kept and
	// returned in StoredState.BadMarker.
	Advance(ctx context.Context, fingerprint string, verifiedSince time.Time, observedMarker string) (StoredState, error)
	// MarkBad stores a fresh bad-seen marker value, replacing any marker and
	// keeping the other keys, with resourceVersion concurrency.
	MarkBad(ctx context.Context) error
}

// ConfigMapStateStore keeps the state in the user-secrets-guard-state
// ConfigMap and watches it with one informer (metadata.name field selector), so
// another replica's write is observed on the watch event.
type ConfigMapStateStore struct {
	c         kubernetes.Interface
	namespace string
	inf       cache.SharedIndexInformer
}

// NewConfigMapStateStore builds the store; call Start to run its informer.
func NewConfigMapStateStore(c kubernetes.Interface, namespace string) *ConfigMapStateStore {
	cms := c.CoreV1().ConfigMaps(namespace)
	sel := fields.OneTermEqualSelector("metadata.name", guardStateName).String()
	lw := &cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) {
			o.FieldSelector = sel
			return cms.List(ctx, o)
		},
		WatchFuncWithContext: func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
			o.FieldSelector = sel
			return cms.Watch(ctx, o)
		},
	}
	inf := cache.NewSharedIndexInformer(cache.ToListWatcherWithWatchListSemantics(lw, c), &corev1.ConfigMap{}, 0, cache.Indexers{})
	return &ConfigMapStateStore{c: c, namespace: namespace, inf: inf}
}

// Start runs the informer until ctx is done. It returns once it is started, not
// once it is synced; use Synced.
func (s *ConfigMapStateStore) Start(ctx context.Context) {
	_, span := otel.Tracer("nebari-user-secrets").Start(ctx, "guard.Start")
	defer span.End()
	go s.inf.Run(ctx.Done())
}

// Synced reports whether the informer has completed its initial list.
func (s *ConfigMapStateStore) Synced() bool { return s.inf.HasSynced() }

// Stored returns the state in the informer's cache.
func (s *ConfigMapStateStore) Stored() (StoredState, bool) {
	cm, ok := get[*corev1.ConfigMap](s.inf, s.namespace+"/"+guardStateName)
	if !ok {
		return StoredState{}, false
	}
	return parseState(cm), true
}

func parseState(cm *corev1.ConfigMap) StoredState {
	st := StoredState{Fingerprint: cm.Data[keyFingerprint], BadMarker: cm.Data[keyBadMarker]}
	if t, err := time.Parse(verifiedSinceLayout, cm.Data[keyVerifiedSince]); err == nil {
		st.VerifiedSince = t.UTC()
	}
	return st
}

// ServerNow reads the API server's clock as the creationTimestamp of a
// server-side dry-run create of a ConfigMap with a generated name. Nothing is
// persisted.
//
// Why this timestamp: the generic registry store sets creationTimestamp from
// the API server's clock on every create, before the dry-run branch, and the
// dry-run storage returns that object as the response:
//   - k8s.io/apiserver@v0.35.0 pkg/registry/generic/registry/store.go:484
//     (Store.create calls rest.FillObjectMetaSystemFields, then generates the
//     name), and :526 (e.Storage.Create with the dry-run flag);
//   - pkg/registry/rest/meta.go:39-41 (FillObjectMetaSystemFields sets
//     CreationTimestamp to metav1Now(), the server's clock);
//   - pkg/registry/generic/registry/dryrun.go:39-44 (DryRunnableStorage.Create
//     copies the object, timestamp included, into the response without
//     writing it).
//
// Pods are created through the same Store.create, so this is the same clock and
// the same second precision as the pod creationTimestamp that resolve compares
// against verifiedSince. The managedFields time of the guard-state update was
// not used: the time is only known after the write, so storing time + 30 s
// needs a second write, and that time advances only when the operation changes
// some field (k8s.io/apimachinery@v0.35.0
// pkg/util/managedfields/internal/managedfieldsupdater.go:52-63), which a
// rewrite of an unchanged fingerprint would not.
//
// The read is taken after the probes passed and before the guard-state write,
// so it is an API-server time at which the guard was verified; the 30 s margin
// is added by the caller.
func (s *ConfigMapStateStore) ServerNow(ctx context.Context) (time.Time, error) {
	ctx, span := otel.Tracer("nebari-user-secrets").Start(ctx, "guard.ServerNow")
	defer span.End()
	clock := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{GenerateName: clockGenerateName, Namespace: s.namespace}}
	out, err := s.c.CoreV1().ConfigMaps(s.namespace).Create(ctx, clock, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	if err != nil {
		err = fmt.Errorf("read server time: %w", err)
		span.RecordError(err)
		return time.Time{}, err
	}
	if out == nil || out.CreationTimestamp.IsZero() {
		err := errors.New(errNoCreationTimeMsg)
		span.RecordError(err)
		return time.Time{}, err
	}
	return out.CreationTimestamp.UTC(), nil
}

// Advance stores fingerprint and the later of the stored verifiedSince and
// verifiedSince. It creates the ConfigMap when absent and otherwise updates it
// with the resourceVersion it read; on a conflict (or a create that lost a
// race) it re-reads and re-applies the max rule.
func (s *ConfigMapStateStore) Advance(ctx context.Context, fingerprint string, verifiedSince time.Time, observedMarker string) (StoredState, error) {
	ctx, span := otel.Tracer("nebari-user-secrets").Start(ctx, "guard.Advance")
	defer span.End()
	st, err := s.advance(ctx, fingerprint, verifiedSince.UTC().Truncate(time.Second), observedMarker)
	if err != nil {
		span.RecordError(err)
	}
	return st, err
}

func (s *ConfigMapStateStore) advance(ctx context.Context, fingerprint string, verifiedSince time.Time, observed string) (StoredState, error) {
	cms := s.c.CoreV1().ConfigMaps(s.namespace)
	for range maxAdvanceAttempts {
		cm, err := cms.Get(ctx, guardStateName, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			want := StoredState{Fingerprint: fingerprint, VerifiedSince: verifiedSince}
			cm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: guardStateName, Namespace: s.namespace}}
			setState(cm, want)
			_, err = cms.Create(ctx, cm, metav1.CreateOptions{})
			if apierrors.IsAlreadyExists(err) {
				continue
			}
			if err != nil {
				return StoredState{}, fmt.Errorf("create guard state: %w", err)
			}
			return want, nil
		case err != nil:
			return StoredState{}, fmt.Errorf("read guard state: %w", err)
		}
		want := StoredState{Fingerprint: fingerprint, VerifiedSince: verifiedSince}
		prev := parseState(cm)
		if prev.VerifiedSince.After(want.VerifiedSince) {
			want.VerifiedSince = prev.VerifiedSince
		}
		if prev.BadMarker != observed {
			want.BadMarker = prev.BadMarker // a marking this move did not observe
		}
		cm = cm.DeepCopy()
		setState(cm, want) // keeps cm.ResourceVersion: the update is conditional on it
		_, err = cms.Update(ctx, cm, metav1.UpdateOptions{})
		if apierrors.IsConflict(err) {
			continue
		}
		if err != nil {
			return StoredState{}, fmt.Errorf("update guard state: %w", err)
		}
		return want, nil
	}
	return StoredState{}, fmt.Errorf("update guard state: %d conflicting attempts", maxAdvanceAttempts)
}

func setState(cm *corev1.ConfigMap, st StoredState) {
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[keyFingerprint] = st.Fingerprint
	cm.Data[keyVerifiedSince] = st.VerifiedSince.UTC().Format(verifiedSinceLayout)
	if st.BadMarker == "" {
		delete(cm.Data, keyBadMarker)
	} else {
		cm.Data[keyBadMarker] = st.BadMarker
	}
}

// MarkBad stores a fresh marker value (rand.Text, so each marking is
// distinguishable). It creates the ConfigMap with only the marker when absent
// (no fingerprint and no verifiedSince, both of which also make the next
// verified a move) and otherwise updates it with the resourceVersion it read,
// re-reading on a conflict. An existing marker is replaced: a move that
// observed the old value must not clear this marking.
func (s *ConfigMapStateStore) MarkBad(ctx context.Context) error {
	ctx, span := otel.Tracer("nebari-user-secrets").Start(ctx, "guard.MarkBad")
	defer span.End()
	err := s.markBad(ctx)
	if err != nil {
		span.RecordError(err)
	}
	return err
}

func (s *ConfigMapStateStore) markBad(ctx context.Context) error {
	cms := s.c.CoreV1().ConfigMaps(s.namespace)
	marker := rand.Text()
	for range maxAdvanceAttempts {
		cm, err := cms.Get(ctx, guardStateName, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			cm = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: guardStateName, Namespace: s.namespace},
				Data:       map[string]string{keyBadMarker: marker},
			}
			_, err = cms.Create(ctx, cm, metav1.CreateOptions{})
			if apierrors.IsAlreadyExists(err) {
				continue
			}
			if err != nil {
				return fmt.Errorf("create guard state: %w", err)
			}
			return nil
		case err != nil:
			return fmt.Errorf("read guard state: %w", err)
		}
		cm = cm.DeepCopy()
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		cm.Data[keyBadMarker] = marker
		_, err = cms.Update(ctx, cm, metav1.UpdateOptions{})
		if apierrors.IsConflict(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("update guard state: %w", err)
		}
		return nil
	}
	return fmt.Errorf("update guard state: %d conflicting attempts", maxAdvanceAttempts)
}
