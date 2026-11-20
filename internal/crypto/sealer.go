package crypto

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"go.opentelemetry.io/otel"
)

// Sealer seals and opens secret values under per-owner data keys.
type Sealer struct {
	kek  KeyEncryptionKey
	rand io.Reader
}

// NewSealer returns a Sealer that wraps data keys with k and draws data keys
// and nonces from rand (crypto/rand.Reader in production).
func NewSealer(k KeyEncryptionKey, rand io.Reader) *Sealer {
	return &Sealer{kek: k, rand: rand}
}

// lengthPrefixed encodes parts as uint32 big-endian length followed by bytes,
// so no two distinct part lists encode to the same bytes.
func lengthPrefixed(parts ...string) []byte {
	var out []byte
	for _, p := range parts {
		out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
		out = append(out, p...)
	}
	return out
}

func valueAAD(sub, name string) []byte { return lengthPrefixed(valueTag, sub, name) }
func wrapAAD(sub string) []byte        { return lengthPrefixed(wrapTag, sub) }

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// NewDataKey creates a random 256-bit data key wrapped under the primary
// master key.
func (s *Sealer) NewDataKey(ctx context.Context, ownerSub string) (model.WrappedKey, error) {
	ctx, span := otel.Tracer("nebari-user-secrets").Start(ctx, "crypto.NewDataKey")
	defer span.End()
	dek := make([]byte, 32)
	defer zero(dek)
	if _, err := io.ReadFull(s.rand, dek); err != nil {
		err = fmt.Errorf("generate data key: %w", err)
		span.RecordError(err)
		return model.WrappedKey{}, err
	}
	w, err := s.kek.Wrap(ctx, dek, ownerSub)
	if err != nil {
		span.RecordError(err)
		return model.WrappedKey{}, err
	}
	return w, nil
}

// Seal encrypts value for rec's owner under name. The result is
// nonce || ciphertext || tag.
func (s *Sealer) Seal(ctx context.Context, rec *model.OwnerRecord, name string, value []byte) ([]byte, error) {
	ctx, span := otel.Tracer("nebari-user-secrets").Start(ctx, "crypto.Seal")
	defer span.End()
	dek, err := s.kek.Unwrap(ctx, rec.DataKey, rec.OwnerSub)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	defer zero(dek)
	if len(dek) != 32 {
		err := fmt.Errorf("data key must be 32 bytes, got %d", len(dek))
		span.RecordError(err)
		return nil, err
	}
	gcm, err := newGCM(dek)
	if err != nil {
		span.RecordError(ErrDecrypt)
		return nil, ErrDecrypt
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(s.rand, nonce); err != nil {
		err = fmt.Errorf("generate nonce: %w", err)
		span.RecordError(err)
		return nil, err
	}
	return gcm.Seal(nonce, nonce, value, valueAAD(rec.OwnerSub, name)), nil
}

// Open decrypts e, which must have been sealed for rec's owner under e.Name.
// Every failure to decrypt returns ErrDecrypt.
func (s *Sealer) Open(ctx context.Context, rec *model.OwnerRecord, e model.SecretEntry) ([]byte, error) {
	ctx, span := otel.Tracer("nebari-user-secrets").Start(ctx, "crypto.Open")
	defer span.End()
	dek, err := s.kek.Unwrap(ctx, rec.DataKey, rec.OwnerSub)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	defer zero(dek)
	pt, err := openGCM(dek, e.Sealed, valueAAD(rec.OwnerSub, e.Name))
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	return pt, nil
}

// Rewrap moves rec's data key under the primary master key. It returns false
// and changes nothing when the key is already under the primary. Values are
// not touched.
func (s *Sealer) Rewrap(ctx context.Context, rec *model.OwnerRecord) (changed bool, err error) {
	ctx, span := otel.Tracer("nebari-user-secrets").Start(ctx, "crypto.Rewrap")
	defer span.End()
	primary, err := s.kek.PrimaryID(ctx)
	if err != nil {
		span.RecordError(err)
		return false, err
	}
	if rec.DataKey.KEKID == primary {
		return false, nil
	}
	dek, err := s.kek.Unwrap(ctx, rec.DataKey, rec.OwnerSub)
	if err != nil {
		span.RecordError(err)
		return false, err
	}
	defer zero(dek)
	w, err := s.kek.Wrap(ctx, dek, rec.OwnerSub)
	if err != nil {
		span.RecordError(err)
		return false, err
	}
	rec.DataKey = w
	return true, nil
}
