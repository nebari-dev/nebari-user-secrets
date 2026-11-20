package crypto

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func newTestSealer(t *testing.T) *Sealer {
	t.Helper()
	kek := NewMemoryKEK(map[string][]byte{"k1": testKey(1), "k2": testKey(2)}, "k1")
	return NewSealer(kek, crand.Reader)
}

func newRecord(t *testing.T, s *Sealer, sub string) *model.OwnerRecord {
	t.Helper()
	dk, err := s.NewDataKey(context.Background(), sub)
	if err != nil {
		t.Fatalf("NewDataKey: %v", err)
	}
	return &model.OwnerRecord{SchemaVersion: 1, OwnerSub: sub, DataKey: dk}
}

func seal(t *testing.T, s *Sealer, rec *model.OwnerRecord, name string, v []byte) model.SecretEntry {
	t.Helper()
	sealed, err := s.Seal(context.Background(), rec, name, v)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return model.SecretEntry{Name: name, Sealed: sealed}
}

func TestSealOpenRoundTrip(t *testing.T) {
	big := make([]byte, 32768)
	if _, err := io.ReadFull(crand.Reader, big); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		value []byte
	}{
		{"empty", []byte("")},
		{"binary", []byte("\x00\xff\n")},
		{"max size", big},
	}
	s := newTestSealer(t)
	rec := newRecord(t, s, "sub-a")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := seal(t, s, rec, "api_key", tt.value)
			got, err := s.Open(context.Background(), rec, e)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(got, tt.value) {
				t.Fatalf("round trip mismatch")
			}
		})
	}
}

func TestSealedBoundToOwnerAndName(t *testing.T) {
	s := newTestSealer(t)
	a := newRecord(t, s, "sub-a")
	b := newRecord(t, s, "sub-b")
	e := seal(t, s, a, "k1", []byte("secret"))

	tests := []struct {
		name string
		rec  *model.OwnerRecord
		e    model.SecretEntry
	}{
		{"other owner", b, e},
		{"other name", a, model.SecretEntry{Name: "k2", Sealed: e.Sealed}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.Open(context.Background(), tt.rec, tt.e); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("got %v, want ErrDecrypt", err)
			}
		})
	}
}

func TestWrappedKeyBoundToOwner(t *testing.T) {
	s := newTestSealer(t)
	a := newRecord(t, s, "sub-a")
	b := newRecord(t, s, "sub-b")
	e := seal(t, s, a, "k1", []byte("secret"))
	b.DataKey = a.DataKey
	if _, err := s.Open(context.Background(), b, e); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v, want ErrDecrypt", err)
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	s := newTestSealer(t)
	rec := newRecord(t, s, "sub-a")
	e := seal(t, s, rec, "k1", []byte("secret"))
	tests := []struct {
		name   string
		mutate func(m *model.SecretEntry)
	}{
		{"flip nonce byte", func(m *model.SecretEntry) { m.Sealed[0] ^= 1 }},
		{"flip body byte", func(m *model.SecretEntry) { m.Sealed[len(m.Sealed)-1] ^= 1 }},
		{"truncated below nonce", func(m *model.SecretEntry) { m.Sealed = m.Sealed[:5] }},
		{"empty", func(m *model.SecretEntry) { m.Sealed = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := e
			m.Sealed = append([]byte(nil), e.Sealed...)
			tt.mutate(&m)
			if _, err := s.Open(context.Background(), rec, m); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("got %v, want ErrDecrypt", err)
			}
		})
	}
}

func TestTamperedWrappedKeyFails(t *testing.T) {
	s := newTestSealer(t)
	rec := newRecord(t, s, "sub-a")
	e := seal(t, s, rec, "k1", []byte("secret"))
	rec.DataKey.Ciphertext[0] ^= 1
	if _, err := s.Open(context.Background(), rec, e); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v, want ErrDecrypt", err)
	}
	if _, err := s.Seal(context.Background(), rec, "k1", []byte("x")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Seal got %v, want ErrDecrypt", err)
	}
}

func TestUnknownKEKDistinctFromDecrypt(t *testing.T) {
	s := newTestSealer(t)
	rec := newRecord(t, s, "sub-a")
	rec.DataKey.KEKID = "gone"
	_, err := s.Open(context.Background(), rec, model.SecretEntry{Name: "n", Sealed: make([]byte, 40)})
	if !errors.Is(err, ErrUnknownKEK) || errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v, want ErrUnknownKEK only", err)
	}
	if _, err := s.Rewrap(context.Background(), rec); !errors.Is(err, ErrUnknownKEK) {
		t.Fatalf("Rewrap got %v, want ErrUnknownKEK", err)
	}
}

func TestRewrapUnderNewPrimary(t *testing.T) {
	ctx := context.Background()
	kek := NewMemoryKEK(map[string][]byte{"k1": testKey(1), "k2": testKey(2)}, "k1")
	s := NewSealer(kek, crand.Reader)
	rec := newRecord(t, s, "sub-a")
	e := seal(t, s, rec, "k1", []byte("secret"))
	rec.Secrets = []model.SecretEntry{e}
	if rec.DataKey.KEKID != "k1" {
		t.Fatalf("kek id %q", rec.DataKey.KEKID)
	}

	kek.SetPrimary("k2")
	changed, err := s.Rewrap(ctx, rec)
	if err != nil || !changed {
		t.Fatalf("Rewrap = %v, %v", changed, err)
	}
	if rec.DataKey.KEKID != "k2" {
		t.Fatalf("kek id %q, want k2", rec.DataKey.KEKID)
	}
	got, err := s.Open(ctx, rec, rec.Secrets[0])
	if err != nil || string(got) != "secret" {
		t.Fatalf("Open after rewrap = %q, %v", got, err)
	}
	changed, err = s.Rewrap(ctx, rec)
	if err != nil || changed {
		t.Fatalf("second Rewrap = %v, %v", changed, err)
	}
}

func TestSealOpenNonUUIDSub(t *testing.T) {
	s := newTestSealer(t)
	rec := newRecord(t, s, "f:ldap-id:alice")
	e := seal(t, s, rec, "k1", []byte("v"))
	got, err := s.Open(context.Background(), rec, e)
	if err != nil || string(got) != "v" {
		t.Fatalf("Open = %q, %v", got, err)
	}
}

func TestAADUnambiguous(t *testing.T) {
	tests := []struct {
		name        string
		subA, nameA string
		subB, nameB string
	}{
		{"shifted boundary", "ab", "c", "a", "bc"},
		{"empty vs shifted", "", "abc", "abc", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if bytes.Equal(valueAAD(tt.subA, tt.nameA), valueAAD(tt.subB, tt.nameB)) {
				t.Fatal("value AAD collides")
			}
		})
	}
	if bytes.Equal(valueAAD("a", ""), wrapAAD("a")) {
		t.Fatal("value and wrap AAD must differ")
	}
}

func TestNonceFromRandReader(t *testing.T) {
	kek := NewMemoryKEK(map[string][]byte{"k1": testKey(1)}, "k1")
	fixed := bytes.NewReader(bytes.Repeat([]byte{7}, 32+12))
	s := NewSealer(kek, fixed)
	rec := newRecord(t, &Sealer{kek: kek, rand: crand.Reader}, "a")
	sealed, err := s.Seal(context.Background(), rec, "n", []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sealed[:12], bytes.Repeat([]byte{7}, 12)) {
		t.Fatalf("nonce not from reader: %x", sealed[:12])
	}
}

func TestRandFailure(t *testing.T) {
	kek := NewMemoryKEK(map[string][]byte{"k1": testKey(1)}, "k1")
	s := NewSealer(kek, bytes.NewReader(nil))
	if _, err := s.NewDataKey(context.Background(), "a"); err == nil {
		t.Fatal("NewDataKey: want error")
	}
	rec := newRecord(t, NewSealer(kek, crand.Reader), "a")
	if _, err := s.Seal(context.Background(), rec, "n", []byte("v")); err == nil {
		t.Fatal("Seal: want error")
	}
}

type errKEK struct{}

func (errKEK) PrimaryID(context.Context) (string, error) { return "", errors.New("boom") }
func (errKEK) Wrap(context.Context, []byte, string) (model.WrappedKey, error) {
	return model.WrappedKey{}, errors.New("boom")
}
func (errKEK) Unwrap(context.Context, model.WrappedKey, string) ([]byte, error) {
	return nil, errors.New("boom")
}

func TestKEKErrorsPropagate(t *testing.T) {
	s := NewSealer(errKEK{}, crand.Reader)
	ctx := context.Background()
	rec := &model.OwnerRecord{OwnerSub: "a"}
	if _, err := s.NewDataKey(ctx, "a"); err == nil {
		t.Error("NewDataKey: want error")
	}
	if _, err := s.Seal(ctx, rec, "n", nil); err == nil {
		t.Error("Seal: want error")
	}
	if _, err := s.Open(ctx, rec, model.SecretEntry{}); err == nil {
		t.Error("Open: want error")
	}
	if _, err := s.Rewrap(ctx, rec); err == nil {
		t.Error("Rewrap: want error")
	}
}

type shortDEKKEK struct{ n int }

func (shortDEKKEK) PrimaryID(context.Context) (string, error) { return "k1", nil }
func (shortDEKKEK) Wrap(context.Context, []byte, string) (model.WrappedKey, error) {
	return model.WrappedKey{}, nil
}
func (k shortDEKKEK) Unwrap(context.Context, model.WrappedKey, string) ([]byte, error) {
	return make([]byte, k.n), nil
}

func TestDataKeyLengthEnforced(t *testing.T) {
	ctx := context.Background()
	rec := &model.OwnerRecord{OwnerSub: "a"}
	for _, n := range []int{0, 16, 24, 31, 33} {
		if _, err := WrapWithKey(testKey(1), make([]byte, n), "a"); err == nil {
			t.Errorf("WrapWithKey dek len %d: want error", n)
		}
		s := NewSealer(shortDEKKEK{n}, crand.Reader)
		if _, err := s.Seal(ctx, rec, "n", []byte("v")); err == nil {
			t.Errorf("Seal dek len %d: want error", n)
		}
		if _, err := s.Open(ctx, rec, model.SecretEntry{Name: "n", Sealed: make([]byte, 40)}); !errors.Is(err, ErrDecrypt) {
			t.Errorf("Open dek len %d: got %v, want ErrDecrypt", n, err)
		}
	}
}

func TestWrapWithKeyBadKey(t *testing.T) {
	if _, err := WrapWithKey([]byte("short"), testKey(9), "a"); err == nil {
		t.Error("WrapWithKey: want error for short key")
	}
	if _, err := UnwrapWithKey([]byte("short"), make([]byte, 60), "a"); !errors.Is(err, ErrDecrypt) {
		t.Errorf("UnwrapWithKey short key: got %v", err)
	}
	if _, err := UnwrapWithKey(testKey(1), []byte{1, 2}, "a"); !errors.Is(err, ErrDecrypt) {
		t.Errorf("UnwrapWithKey short ct: got %v", err)
	}
}

func TestMemoryKEKPrimaryAndWrap(t *testing.T) {
	ctx := context.Background()
	kek := NewMemoryKEK(map[string][]byte{"k1": testKey(1)}, "missing")
	if _, err := kek.PrimaryID(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := kek.Wrap(ctx, testKey(5), "a"); !errors.Is(err, ErrUnknownKEK) {
		t.Fatalf("Wrap with unknown primary: %v", err)
	}
}
