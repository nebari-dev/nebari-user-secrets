// Package crypto implements envelope encryption for owner records: a random
// data key per user seals that user's values, and a master key (the KEK) wraps
// the data key.
package crypto

import (
	"context"
	"errors"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

// ErrDecrypt is returned for every failure to unwrap or open ciphertext: wrong
// key, wrong associated data, tampering or short input. It carries no detail.
var ErrDecrypt = errors.New("decrypt_failed")

// ErrUnknownKEK is returned when a record names a master key id the
// KeyEncryptionKey does not hold. It is distinct from ErrDecrypt so callers can
// tell "key gone" from "data bad".
var ErrUnknownKEK = errors.New("unknown_kek")

// KeyEncryptionKey wraps and unwraps data keys under a master key.
type KeyEncryptionKey interface {
	PrimaryID(ctx context.Context) (string, error)
	// Wrap wraps dek under the primary master key.
	Wrap(ctx context.Context, dek []byte, ownerSub string) (model.WrappedKey, error)
	// Unwrap unwraps w under the master key named by w.KEKID.
	Unwrap(ctx context.Context, w model.WrappedKey, ownerSub string) ([]byte, error)
}
