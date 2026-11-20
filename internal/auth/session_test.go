package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

const (
	issPublic   = "https://nebari.example.com/auth/realms/nebari"
	issInternal = "http://keycloak.keycloak.svc/auth/realms/nebari"
	spaClient   = "nebari-landing-spa"
)

var fixedNow = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func baseClaims() map[string]any {
	return map[string]any{
		"iss":                issPublic,
		"typ":                "Bearer",
		"azp":                spaClient,
		"sub":                "sub-123",
		"preferred_username": "alice",
		"groups":             []string{"admins", "dev"},
		"aud":                []string{"account"},
		"iat":                fixedNow.Add(-time.Minute).Unix(),
		"exp":                fixedNow.Add(5 * time.Minute).Unix(),
	}
}

func sign(t *testing.T, alg jose.SignatureAlgorithm, key any, kid string, claims map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(s).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func rawClaims(t *testing.T, m map[string]any) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func mutate(f func(m map[string]any)) map[string]any {
	m := baseClaims()
	f(m)
	return m
}

func TestVerify(t *testing.T) {
	key := newKey(t)
	other := newKey(t)
	keys := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}
	v := NewSessionVerifier(keys, []string{issPublic, issInternal}, spaClient, func() time.Time { return fixedNow })

	// A none-algorithm token: header {"alg":"none"}, no signature.
	noneTok := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + rawClaims(t, baseClaims()) + "."

	otherV := NewSessionVerifier(&oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&other.PublicKey}},
		[]string{issPublic}, spaClient, func() time.Time { return fixedNow })
	hs := sign(t, jose.HS256, []byte("0123456789abcdef0123456789abcdef"), "k1", baseClaims())

	tests := []struct {
		name    string
		token   string
		want    model.Principal
		wantErr bool
		v       *SessionVerifier // overrides the default verifier when set
	}{
		{"valid", sign(t, jose.RS256, key, "k1", baseClaims()),
			model.Principal{Kind: "user", Sub: "sub-123", Username: "alice", Groups: []string{"admins", "dev"}}, false, nil},
		{"second issuer accepted", sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { m["iss"] = issInternal })),
			model.Principal{Kind: "user", Sub: "sub-123", Username: "alice", Groups: []string{"admins", "dev"}}, false, nil},
		{"wrong azp", sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { m["azp"] = "other-client" })), model.Principal{}, true, nil},
		{"missing azp", sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { delete(m, "azp") })), model.Principal{}, true, nil},
		{"user-secrets aud but wrong azp", sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) {
			m["azp"] = "other-client"
			m["aud"] = []string{"user-secrets"}
		})), model.Principal{}, true, nil},
		{"typ ID", sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { m["typ"] = "ID" })), model.Principal{}, true, nil},
		{"typ missing", sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { delete(m, "typ") })), model.Principal{}, true, nil},
		{"expired", sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { m["exp"] = fixedNow.Add(-time.Minute).Unix() })), model.Principal{}, true, nil},
		{"issuer not listed", sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { m["iss"] = "https://evil.example.com/realms/nebari" })), model.Principal{}, true, nil},
		{"issuer prefix of listed", sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { m["iss"] = issPublic + "/" })), model.Principal{}, true, nil},
		{"alg HS256", hs, model.Principal{}, true, nil},
		{"alg none", noneTok, model.Principal{}, true, nil},
		{"missing sub", sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { delete(m, "sub") })), model.Principal{}, true, nil},
		{"empty sub", sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { m["sub"] = "" })), model.Principal{}, true, nil},
		{"signed by unknown key", sign(t, jose.RS256, other, "k1", baseClaims()), model.Principal{}, true, nil},
		{"no exp", sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { delete(m, "exp") })), model.Principal{}, true, nil},
		{"nbf in future", sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { m["nbf"] = fixedNow.Add(10 * time.Minute).Unix() })), model.Principal{}, true, nil},
		{"groups as string", sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { m["groups"] = "admins" })), model.Principal{}, true, nil},
		{"groups as numbers", sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { m["groups"] = []int{1, 2} })), model.Principal{}, true, nil},
		{"no kid, different static key", sign(t, jose.RS256, key, "", baseClaims()), model.Principal{}, true, otherV},
		{"no kid, signing static key", sign(t, jose.RS256, key, "", baseClaims()),
			model.Principal{Kind: "user", Sub: "sub-123", Username: "alice", Groups: []string{"admins", "dev"}}, false, v},
		{"garbage", "not-a-jwt", model.Principal{}, true, nil},
		{"empty", "", model.Principal{}, true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vv := v
			if tt.v != nil {
				vv = tt.v
			}
			got, err := vv.Verify(context.Background(), tt.token)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidToken) || err.Error() != "invalid_token" {
					t.Fatalf("err = %v, want ErrInvalidToken", err)
				}
				if got.Sub != "" || got.Kind != "" {
					t.Fatalf("principal not zero on failure: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Kind != tt.want.Kind || got.Sub != tt.want.Sub || got.Username != tt.want.Username ||
				strings.Join(got.Groups, ",") != strings.Join(tt.want.Groups, ",") {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestVerifyMisconfigured(t *testing.T) {
	key := newKey(t)
	keys := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}
	tok := sign(t, jose.RS256, key, "k1", baseClaims())
	emptyIss := sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { m["iss"] = "" }))
	now := func() time.Time { return fixedNow }
	tests := []struct {
		name  string
		v     *SessionVerifier
		token string
	}{
		{"no issuers", NewSessionVerifier(keys, nil, spaClient, now), tok},
		{"only empty issuer, empty iss", NewSessionVerifier(keys, []string{""}, spaClient, now), emptyIss},
		{"empty issuer among valid", NewSessionVerifier(keys, []string{issPublic, ""}, spaClient, now), tok},
		{"empty client id", NewSessionVerifier(keys, []string{issPublic}, "", now), tok},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.v.Verify(context.Background(), tt.token)
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("err = %v, want ErrInvalidToken", err)
			}
			if got.Sub != "" || got.Kind != "" {
				t.Fatalf("principal not zero: %+v", got)
			}
		})
	}
}

func TestVerifyErrorLeaksNoToken(t *testing.T) {
	key := newKey(t)
	keys := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}
	v := NewSessionVerifier(keys, []string{issPublic}, spaClient, func() time.Time { return fixedNow })
	tokens := []string{
		sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { m["azp"] = "other" })),
		sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { m["typ"] = "ID" })),
		sign(t, jose.RS256, newKey(t), "k1", baseClaims()),
		sign(t, jose.RS256, key, "k1", mutate(func(m map[string]any) { m["exp"] = 1 })),
	}
	for i, tok := range tokens {
		_, err := v.Verify(context.Background(), tok)
		if err == nil {
			t.Fatalf("token %d accepted", i)
		}
		for _, part := range strings.Split(tok, ".") {
			for n := 0; n+8 <= len(part); n += 4 {
				if strings.Contains(err.Error(), part[n:n+8]) {
					t.Fatalf("token %d: error text contains token substring %q", i, part[n:n+8])
				}
			}
		}
	}
}

func jwksJSON(t *testing.T, kid string, pub *rsa.PublicKey) []byte {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: kid, Algorithm: "RS256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyAfterKeyRotation(t *testing.T) {
	keyA, keyB := newKey(t), newKey(t)
	var useB atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if useB.Load() {
			_, _ = w.Write(jwksJSON(t, "kid-b", &keyB.PublicKey))
			return
		}
		_, _ = w.Write(jwksJSON(t, "kid-a", &keyA.PublicKey))
	}))
	defer srv.Close()

	keys := oidc.NewRemoteKeySet(context.Background(), srv.URL)
	v := NewSessionVerifier(keys, []string{issPublic}, spaClient, func() time.Time { return fixedNow })

	if _, err := v.Verify(context.Background(), sign(t, jose.RS256, keyA, "kid-a", baseClaims())); err != nil {
		t.Fatalf("token A: %v", err)
	}
	useB.Store(true)
	if _, err := v.Verify(context.Background(), sign(t, jose.RS256, keyB, "kid-b", baseClaims())); err != nil {
		t.Fatalf("token B after rotation: %v", err)
	}
	got, err := v.Verify(context.Background(), sign(t, jose.RS256, keyA, "kid-a", baseClaims()))
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("token A after rotation: err = %v, want ErrInvalidToken", err)
	}
	if got.Sub != "" || got.Kind != "" {
		t.Fatalf("principal not zero for rejected token A: %+v", got)
	}
}
