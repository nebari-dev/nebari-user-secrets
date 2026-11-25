package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	recordLabel = "nebari.dev/user-secrets-record"
	recordKey   = "record.json"
	statusKey   = "status.json"

	deliveryInterval = time.Minute
)

type deliveryKey struct{ sub, app string }

// KubernetesSecretStore stores one Secret per owner plus a -status Secret.
type KubernetesSecretStore struct {
	c         kubernetes.Interface
	namespace string
	clock     func() time.Time

	mu       sync.Mutex
	lastSent map[deliveryKey]time.Time
}

var _ SecretStore = (*KubernetesSecretStore)(nil)

// NewKubernetesSecretStore returns a store in namespace. clock drives the
// per-app delivery rate limit.
func NewKubernetesSecretStore(c kubernetes.Interface, namespace string, clock func() time.Time) *KubernetesSecretStore {
	return &KubernetesSecretStore{c: c, namespace: namespace, clock: clock, lastSent: map[deliveryKey]time.Time{}}
}

func span(ctx context.Context, name string) (context.Context, trace.Span) {
	return otel.Tracer("nebari-user-secrets").Start(ctx, "store."+name)
}

func (s *KubernetesSecretStore) secrets() interface {
	Get(context.Context, string, metav1.GetOptions) (*corev1.Secret, error)
	Create(context.Context, *corev1.Secret, metav1.CreateOptions) (*corev1.Secret, error)
	Update(context.Context, *corev1.Secret, metav1.UpdateOptions) (*corev1.Secret, error)
	Delete(context.Context, string, metav1.DeleteOptions) error
	List(context.Context, metav1.ListOptions) (*corev1.SecretList, error)
} {
	return s.c.CoreV1().Secrets(s.namespace)
}

// Get returns the owner's record and the Secret's resourceVersion.
func (s *KubernetesSecretStore) Get(ctx context.Context, ownerSub string) (*model.OwnerRecord, string, error) {
	ctx, sp := span(ctx, "Get")
	defer sp.End()
	sec, err := s.secrets().Get(ctx, model.SecretName(ownerSub), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		sp.RecordError(err)
		return nil, "", fmt.Errorf("get record: %w", err)
	}
	rec, err := decodeRecord(sec)
	if err != nil {
		sp.RecordError(err)
		return nil, "", err
	}
	if rec.OwnerSub != ownerSub {
		sp.RecordError(ErrOwnerMismatch)
		return nil, "", ErrOwnerMismatch
	}
	return rec, sec.ResourceVersion, nil
}

func decodeRecord(sec *corev1.Secret) (*model.OwnerRecord, error) {
	var rec model.OwnerRecord
	if err := json.Unmarshal(sec.Data[recordKey], &rec); err != nil {
		return nil, fmt.Errorf("decode record: invalid %s", recordKey)
	}
	if rec.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported record schemaVersion %d", rec.SchemaVersion)
	}
	return &rec, nil
}

// Put writes rec. An empty expectedVersion creates; otherwise it updates only
// if the Secret is still at expectedVersion.
func (s *KubernetesSecretStore) Put(ctx context.Context, rec *model.OwnerRecord, expectedVersion string) (string, error) {
	ctx, sp := span(ctx, "Put")
	defer sp.End()
	b, err := json.Marshal(rec)
	if err != nil {
		sp.RecordError(err)
		return "", fmt.Errorf("encode record: %w", err)
	}
	if len(b) > MaxRecordBytes {
		sp.RecordError(ErrRecordTooLarge)
		return "", ErrRecordTooLarge
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            model.SecretName(rec.OwnerSub),
			Namespace:       s.namespace,
			Labels:          map[string]string{recordLabel: "owner"},
			ResourceVersion: expectedVersion,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{recordKey: b},
	}
	var out *corev1.Secret
	if expectedVersion == "" {
		out, err = s.secrets().Create(ctx, sec, metav1.CreateOptions{})
	} else {
		out, err = s.secrets().Update(ctx, sec, metav1.UpdateOptions{})
	}
	switch {
	case apierrors.IsConflict(err), apierrors.IsAlreadyExists(err):
		return "", ErrConflict
	case apierrors.IsNotFound(err) && expectedVersion != "":
		// The record was deleted since the caller read it; callers retry
		// conflicts by re-reading, which then sees NotFound. On create, NotFound
		// means misconfiguration (such as a missing namespace) and falls through.
		return "", ErrConflict
	case err != nil:
		sp.RecordError(err)
		return "", fmt.Errorf("write record: %w", err)
	}
	return out.ResourceVersion, nil
}

// Delete removes the owner and status Secrets; missing ones are not an error.
func (s *KubernetesSecretStore) Delete(ctx context.Context, ownerSub string) error {
	ctx, sp := span(ctx, "Delete")
	defer sp.End()
	for _, name := range []string{model.SecretName(ownerSub), model.StatusSecretName(ownerSub)} {
		if err := s.secrets().Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			sp.RecordError(err)
			return fmt.Errorf("delete %s: %w", name, err)
		}
	}
	return nil
}

// allow reports whether a delivery write for (sub, app) may go now, and if so
// records the attempt. A failed write is not retried within the interval.
func (s *KubernetesSecretStore) allow(sub, app string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	k := deliveryKey{sub, app}
	if last, ok := s.lastSent[k]; ok && now.Sub(last) < deliveryInterval {
		return false
	}
	s.lastSent[k] = now
	return true
}

// RecordDelivery stores d in the owner's status Secret. It is rate-limited to
// once a minute per (owner, app) per store: a call inside the window writes
// nothing and returns nil. A failed write is not retried within the window and
// its error is returned for the caller to log; status is advisory and a caller
// must never fail a resolve on it. A d with a zero LastOK keeps the stored
// success, and one with a zero LastFailure keeps the stored failure.
func (s *KubernetesSecretStore) RecordDelivery(ctx context.Context, ownerSub string, d model.DeliveryStatus) error {
	ctx, sp := span(ctx, "RecordDelivery")
	defer sp.End()
	if !s.allow(ownerSub, string(d.App)) {
		return nil
	}
	if err := s.writeStatus(ctx, ownerSub, d); err != nil {
		sp.RecordError(err)
		return fmt.Errorf("record delivery: %w", err)
	}
	return nil
}

// mergeStatus overlays the outcome in d onto cur: a success replaces the
// stored success, a failure the stored failure.
func mergeStatus(cur, d model.DeliveryStatus) model.DeliveryStatus {
	if !d.LastOK.IsZero() {
		cur.LastOK, cur.LastCount = d.LastOK, d.LastCount
	}
	if !d.LastFailure.IsZero() {
		cur.LastFailure, cur.LastReason = d.LastFailure, d.LastReason
	}
	cur.App = d.App
	return cur
}

func (s *KubernetesSecretStore) writeStatus(ctx context.Context, ownerSub string, d model.DeliveryStatus) error {
	name := model.StatusSecretName(ownerSub)
	sec, err := s.secrets().Get(ctx, name, metav1.GetOptions{})
	create := apierrors.IsNotFound(err)
	if err != nil && !create {
		return err
	}
	if create {
		sec = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.namespace, Labels: map[string]string{recordLabel: "status"}},
			Type:       corev1.SecretTypeOpaque,
		}
	}
	var list []model.DeliveryStatus
	if raw := sec.Data[statusKey]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &list); err != nil {
			list = nil // unreadable status is replaced; it is advisory only
		}
	}
	replaced := false
	for i := range list {
		if list[i].App == d.App {
			list[i], replaced = mergeStatus(list[i], d), true
		}
	}
	if !replaced {
		list = append(list, d)
	}
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	sec.Data = map[string][]byte{statusKey: b}
	if create {
		_, err = s.secrets().Create(ctx, sec, metav1.CreateOptions{})
	} else {
		_, err = s.secrets().Update(ctx, sec, metav1.UpdateOptions{})
	}
	return err
}

// Deliveries returns the owner's per-app delivery status, empty if none.
func (s *KubernetesSecretStore) Deliveries(ctx context.Context, ownerSub string) ([]model.DeliveryStatus, error) {
	ctx, sp := span(ctx, "Deliveries")
	defer sp.End()
	sec, err := s.secrets().Get(ctx, model.StatusSecretName(ownerSub), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		sp.RecordError(err)
		return nil, fmt.Errorf("get status: %w", err)
	}
	var list []model.DeliveryStatus
	if err := json.Unmarshal(sec.Data[statusKey], &list); err != nil {
		sp.RecordError(err)
		return nil, fmt.Errorf("decode status: invalid %s", statusKey)
	}
	return list, nil
}

// AnyRecords reports whether at least one owner record exists.
func (s *KubernetesSecretStore) AnyRecords(ctx context.Context) (bool, error) {
	ctx, sp := span(ctx, "AnyRecords")
	defer sp.End()
	l, err := s.secrets().List(ctx, metav1.ListOptions{LabelSelector: recordLabel + "=owner", Limit: 1})
	if err != nil {
		sp.RecordError(err)
		return false, fmt.Errorf("list records: %w", err)
	}
	return len(l.Items) > 0, nil
}

// ListOwners returns the ownerSub read from every owner record, sorted.
func (s *KubernetesSecretStore) ListOwners(ctx context.Context) ([]string, error) {
	ctx, sp := span(ctx, "ListOwners")
	defer sp.End()
	var subs []string
	opts := metav1.ListOptions{LabelSelector: recordLabel + "=owner", Limit: 100}
	for {
		l, err := s.secrets().List(ctx, opts)
		if err != nil {
			sp.RecordError(err)
			return nil, fmt.Errorf("list records: %w", err)
		}
		for i := range l.Items {
			rec, err := decodeRecord(&l.Items[i])
			if err != nil {
				sp.RecordError(err)
				return nil, err
			}
			subs = append(subs, rec.OwnerSub)
		}
		if l.Continue == "" {
			break
		}
		opts.Continue = l.Continue
	}
	sort.Strings(subs)
	return subs, nil
}
