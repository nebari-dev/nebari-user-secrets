package crypto

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
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
	kekSecretName  = "user-secrets-kek"
	kekPrimaryKey  = "primary"
	kekRecordLabel = "nebari.dev/user-secrets-record"
	kekIDFormat    = "20060102T150405Z"
	kekConflictTry = 5
)

// ErrKEKUnavailable is returned when the master key cannot be loaded or a
// required key id is not held. The service fails closed on it (503
// kek_unavailable); it never generates a replacement key.
var ErrKEKUnavailable = errors.New("kek_unavailable")

// RecordLister reports whether any owner record exists.
type RecordLister interface {
	AnyRecords(ctx context.Context) (bool, error)
}

// KeyAuditor receives master-key lifecycle events. Details never carry key
// material.
type KeyAuditor interface {
	KeyEvent(ctx context.Context, event, ownerSub, actor, detail string)
}

// KubernetesKEK keeps master keys in the Secret user-secrets-kek and caches
// them in memory after Bootstrap.
type KubernetesKEK struct {
	c         kubernetes.Interface
	namespace string
	records   RecordLister
	audit     KeyAuditor

	mu      sync.RWMutex
	keys    map[string][]byte
	primary string
}

var _ KeyEncryptionKey = (*KubernetesKEK)(nil)

// NewKubernetesKEK returns a KubernetesKEK. Call Bootstrap before use.
func NewKubernetesKEK(c kubernetes.Interface, namespace string, records RecordLister, audit KeyAuditor) *KubernetesKEK {
	return &KubernetesKEK{c: c, namespace: namespace, records: records, audit: audit}
}

func kekSpan(ctx context.Context, method string) (context.Context, trace.Span) {
	return otel.Tracer("nebari-user-secrets").Start(ctx, "crypto.KubernetesKEK."+method)
}

func unavailable(reason string) error {
	return fmt.Errorf("%w: %s", ErrKEKUnavailable, reason)
}

// parseKEKSecret validates a Secret and returns its keys and primary id.
func parseKEKSecret(s *corev1.Secret) (map[string][]byte, string, error) {
	primary := string(s.Data[kekPrimaryKey])
	keys := make(map[string][]byte, len(s.Data))
	for id, v := range s.Data {
		if id == kekPrimaryKey {
			continue
		}
		if len(v) != 32 {
			return nil, "", unavailable("invalid_key_entry")
		}
		keys[id] = append([]byte(nil), v...)
	}
	if _, ok := keys[primary]; !ok {
		return nil, "", unavailable("primary_missing")
	}
	return keys, primary, nil
}

// install parses s, replaces the cache and returns the parsed values.
func (k *KubernetesKEK) install(s *corev1.Secret) (map[string][]byte, string, error) {
	keys, primary, err := parseKEKSecret(s)
	if err != nil {
		return nil, "", err
	}
	k.mu.Lock()
	k.keys, k.primary = keys, primary
	k.mu.Unlock()
	return keys, primary, nil
}

// load reads the Secret and replaces the cache. It never writes.
func (k *KubernetesKEK) load(ctx context.Context) (map[string][]byte, string, error) {
	s, err := k.c.CoreV1().Secrets(k.namespace).Get(ctx, kekSecretName, metav1.GetOptions{})
	if err != nil {
		return nil, "", unavailable("read_failed")
	}
	return k.install(s)
}

func newKEKKey() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// freshID returns an id for now that is not in taken: "k" + UTC timestamp,
// with -2, -3 ... appended on a same-second collision.
func freshID(taken map[string][]byte) string {
	base := "k" + time.Now().UTC().Format(kekIDFormat)
	id := base
	for n := 2; ; n++ {
		if _, ok := taken[id]; !ok && id != kekPrimaryKey {
			return id
		}
		id = base + "-" + strconv.Itoa(n)
	}
}

// Load reads and validates the existing master-key Secret and installs it. It
// never creates a Secret: a missing or invalid one returns ErrKEKUnavailable.
// Admin commands use it so they cannot start a fresh key history.
func (k *KubernetesKEK) Load(ctx context.Context) error {
	ctx, span := kekSpan(ctx, "Load")
	defer span.End()
	if _, _, err := k.load(ctx); err != nil {
		span.RecordError(err)
		return err
	}
	return nil
}

// Bootstrap loads the master keys, creating the Secret only when it is absent
// and a successful list shows no owner record. Any other state fails closed.
func (k *KubernetesKEK) Bootstrap(ctx context.Context) error {
	ctx, span := kekSpan(ctx, "Bootstrap")
	defer span.End()
	secrets := k.c.CoreV1().Secrets(k.namespace)
	s, err := secrets.Get(ctx, kekSecretName, metav1.GetOptions{})
	switch {
	case err == nil:
		if _, _, err := k.install(s); err != nil {
			span.RecordError(err)
			return err
		}
		return nil
	case !apierrors.IsNotFound(err):
		err = unavailable("read_failed")
		span.RecordError(err)
		return err
	}

	any, lerr := k.records.AnyRecords(ctx)
	if lerr != nil || any {
		reason := "records_exist"
		if lerr != nil {
			reason = "record_list_failed"
		}
		k.audit.KeyEvent(ctx, "kek_unavailable", "", "", reason)
		err := unavailable(reason)
		span.RecordError(err)
		return err
	}

	key, err := newKEKKey()
	if err != nil {
		err = unavailable("rand_failed")
		span.RecordError(err)
		return err
	}
	id := freshID(nil)
	_, err = secrets.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kekSecretName,
			Namespace: k.namespace,
			Labels:    map[string]string{kekRecordLabel: "kek"},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{id: key, kekPrimaryKey: []byte(id)},
	}, metav1.CreateOptions{})
	switch {
	case err == nil:
		k.mu.Lock()
		k.keys, k.primary = map[string][]byte{id: key}, id
		k.mu.Unlock()
		k.audit.KeyEvent(ctx, "kek_created", "", "", id)
		return nil
	case apierrors.IsAlreadyExists(err):
		if _, _, err := k.load(ctx); err != nil {
			span.RecordError(err)
			return err
		}
		return nil
	default:
		err = unavailable("create_failed")
		span.RecordError(err)
		return err
	}
}

// bootstrapped reports whether a successful Bootstrap has loaded keys.
func (k *KubernetesKEK) bootstrapped() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.primary != ""
}

// livePrimary re-reads the Secret, refreshes the cache and returns the live
// primary id and its key. It never falls back to the cache on failure.
func (k *KubernetesKEK) livePrimary(ctx context.Context) (string, []byte, error) {
	if !k.bootstrapped() {
		return "", nil, ErrKEKUnavailable
	}
	keys, primary, err := k.load(ctx)
	if err != nil {
		return "", nil, err
	}
	key, ok := keys[primary]
	if !ok {
		return "", nil, ErrKEKUnavailable
	}
	return primary, key, nil
}

// PrimaryID returns the live primary id, read from the Secret so rewrap
// decisions see rotations made by other processes.
func (k *KubernetesKEK) PrimaryID(ctx context.Context) (string, error) {
	ctx, span := kekSpan(ctx, "PrimaryID")
	defer span.End()
	id, _, err := k.livePrimary(ctx)
	if err != nil {
		span.RecordError(err)
		return "", err
	}
	return id, nil
}

// Wrap wraps dek under the live primary key, read from the Secret on every
// call. It returns ErrKEKUnavailable if the Secret cannot be read or is invalid.
func (k *KubernetesKEK) Wrap(ctx context.Context, dek []byte, ownerSub string) (model.WrappedKey, error) {
	ctx, span := kekSpan(ctx, "Wrap")
	defer span.End()
	id, key, err := k.livePrimary(ctx)
	if err != nil {
		span.RecordError(err)
		return model.WrappedKey{}, err
	}
	ct, err := WrapWithKey(key, dek, ownerSub)
	if err != nil {
		span.RecordError(err)
		return model.WrappedKey{}, err
	}
	return model.WrappedKey{KEKID: id, Ciphertext: ct}, nil
}

func (k *KubernetesKEK) lookup(id string) ([]byte, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	key, ok := k.keys[id]
	return key, ok
}

// Unwrap unwraps w under the key named by w.KEKID. An id not held triggers one
// re-read of the Secret; if still absent it returns ErrKEKUnavailable.
func (k *KubernetesKEK) Unwrap(ctx context.Context, w model.WrappedKey, ownerSub string) ([]byte, error) {
	ctx, span := kekSpan(ctx, "Unwrap")
	defer span.End()
	key, ok := k.lookup(w.KEKID)
	if !ok {
		if keys, _, err := k.load(ctx); err == nil {
			key, ok = keys[w.KEKID]
		}
		if !ok {
			span.RecordError(ErrKEKUnavailable)
			return nil, ErrKEKUnavailable
		}
	}
	dek, err := UnwrapWithKey(key, w.Ciphertext, ownerSub)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	return dek, nil
}

// update applies mutate to the current Secret with resourceVersion
// concurrency, retrying on Conflict, then refreshes the cache.
func (k *KubernetesKEK) update(ctx context.Context, mutate func(s *corev1.Secret) error) error {
	secrets := k.c.CoreV1().Secrets(k.namespace)
	for range kekConflictTry {
		s, err := secrets.Get(ctx, kekSecretName, metav1.GetOptions{})
		if err != nil {
			return unavailable("read_failed")
		}
		if _, _, err := parseKEKSecret(s); err != nil {
			return err
		}
		if err := mutate(s); err != nil {
			return err
		}
		updated, err := secrets.Update(ctx, s, metav1.UpdateOptions{})
		if apierrors.IsConflict(err) {
			continue
		}
		if err != nil {
			return unavailable("update_failed")
		}
		_, _, err = k.install(updated)
		return err
	}
	return unavailable("update_conflict")
}

// AddKey adds a new master key, makes it primary and returns its id. It emits
// no audit event; the admin command does.
func (k *KubernetesKEK) AddKey(ctx context.Context) (string, error) {
	ctx, span := kekSpan(ctx, "AddKey")
	defer span.End()
	key, err := newKEKKey()
	if err != nil {
		span.RecordError(err)
		return "", unavailable("rand_failed")
	}
	var id string
	err = k.update(ctx, func(s *corev1.Secret) error {
		taken := make(map[string][]byte, len(s.Data))
		for n := range s.Data {
			taken[n] = nil
		}
		id = freshID(taken)
		s.Data[id] = key
		s.Data[kekPrimaryKey] = []byte(id)
		return nil
	})
	if err != nil {
		span.RecordError(err)
		return "", err
	}
	return id, nil
}

// Retire removes master key id. It refuses the primary and any id that
// inUse reports records for.
func (k *KubernetesKEK) Retire(ctx context.Context, id string, inUse func(ctx context.Context) (map[string]int, error)) error {
	ctx, span := kekSpan(ctx, "Retire")
	defer span.End()
	counts, err := inUse(ctx)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("count key usage: %w", err)
	}
	if counts[id] > 0 {
		err := fmt.Errorf("master key %s is still used by %d records", id, counts[id])
		span.RecordError(err)
		return err
	}
	err = k.update(ctx, func(s *corev1.Secret) error {
		if id == kekPrimaryKey || string(s.Data[kekPrimaryKey]) == id {
			return fmt.Errorf("master key %s is primary", id)
		}
		if _, ok := s.Data[id]; !ok {
			return fmt.Errorf("master key %s not found", id)
		}
		delete(s.Data, id)
		return nil
	})
	if err != nil {
		span.RecordError(err)
		return err
	}
	k.audit.KeyEvent(ctx, "kek_retired", "", "", id)
	return nil
}
