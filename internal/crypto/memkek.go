package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"go.opentelemetry.io/otel"
)

const (
	nonceSize = 12
	valueTag  = "nebari-user-secrets/v1"
	wrapTag   = "nebari-user-secrets/kek/v1"
)

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// WrapWithKey seals dek under key with AES-256-GCM, binding ownerSub as
// associated data. The result is nonce || ciphertext || tag, with the nonce
// from crypto/rand.
func WrapWithKey(key, dek []byte, ownerSub string) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(key))
	}
	if len(dek) != 32 {
		return nil, fmt.Errorf("data key must be 32 bytes, got %d", len(dek))
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, dek, wrapAAD(ownerSub)), nil
}

// UnwrapWithKey reverses WrapWithKey. Every failure returns ErrDecrypt.
func UnwrapWithKey(key, ct []byte, ownerSub string) ([]byte, error) {
	return openGCM(key, ct, wrapAAD(ownerSub))
}

func openGCM(key, ct, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrDecrypt
	}
	gcm, err := newGCM(key)
	if err != nil || len(ct) < nonceSize+gcm.Overhead() {
		return nil, ErrDecrypt
	}
	pt, err := gcm.Open(nil, ct[:nonceSize], ct[nonceSize:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// MemoryKEK is an in-memory KeyEncryptionKey for tests and as the wrap
// primitive for other implementations.
type MemoryKEK struct {
	mu      sync.RWMutex
	keys    map[string][]byte
	primary string
}

// NewMemoryKEK returns a MemoryKEK holding keys (id to 32-byte key) with
// primary naming the id used for new wraps. The map is copied.
func NewMemoryKEK(keys map[string][]byte, primary string) *MemoryKEK {
	m := make(map[string][]byte, len(keys))
	for id, k := range keys {
		m[id] = append([]byte(nil), k...)
	}
	return &MemoryKEK{keys: m, primary: primary}
}

// SetPrimary changes the id used for new wraps; it need not already be held.
func (m *MemoryKEK) SetPrimary(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.primary = id
}

// PrimaryID returns the id used for new wraps.
func (m *MemoryKEK) PrimaryID(ctx context.Context) (string, error) {
	_, span := otel.Tracer("nebari-user-secrets").Start(ctx, "crypto.MemoryKEK.PrimaryID")
	defer span.End()
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.primary, nil
}

func (m *MemoryKEK) key(id string) ([]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	k, ok := m.keys[id]
	return k, ok
}

// Wrap wraps dek under the primary key, or returns ErrUnknownKEK if the
// primary id has no key.
func (m *MemoryKEK) Wrap(ctx context.Context, dek []byte, ownerSub string) (model.WrappedKey, error) {
	_, span := otel.Tracer("nebari-user-secrets").Start(ctx, "crypto.MemoryKEK.Wrap")
	defer span.End()
	m.mu.RLock()
	id := m.primary
	m.mu.RUnlock()
	k, ok := m.key(id)
	if !ok {
		span.RecordError(ErrUnknownKEK)
		return model.WrappedKey{}, ErrUnknownKEK
	}
	ct, err := WrapWithKey(k, dek, ownerSub)
	if err != nil {
		span.RecordError(err)
		return model.WrappedKey{}, err
	}
	return model.WrappedKey{KEKID: id, Ciphertext: ct}, nil
}

// Unwrap unwraps w under the key named by w.KEKID. It returns ErrUnknownKEK
// for an id it does not hold and ErrDecrypt for any other failure.
func (m *MemoryKEK) Unwrap(ctx context.Context, w model.WrappedKey, ownerSub string) ([]byte, error) {
	_, span := otel.Tracer("nebari-user-secrets").Start(ctx, "crypto.MemoryKEK.Unwrap")
	defer span.End()
	k, ok := m.key(w.KEKID)
	if !ok {
		span.RecordError(ErrUnknownKEK)
		return nil, ErrUnknownKEK
	}
	dek, err := UnwrapWithKey(k, w.Ciphertext, ownerSub)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	return dek, nil
}
