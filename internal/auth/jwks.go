package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
)

const (
	// refetchWindow is the minimum gap between two JWKS fetches, process-wide.
	refetchWindow = 10 * time.Second
	// maxJWKSBytes caps the JWKS response body.
	maxJWKSBytes = 1 << 20
	// fetchTimeout bounds one JWKS fetch regardless of the caller's context.
	fetchTimeout = 10 * time.Second
)

var errKeyLookupLimited = errors.New("key lookup limited")

type fetchCall struct{ done chan struct{} }

// JWKSKeySet verifies RS256 signatures against a cached JWKS. A token whose
// kid is cached never causes a fetch, whether or not its signature is good.
// Only a kid absent from the cache (or an empty cache) may trigger a fetch,
// at most once per refetchWindow process-wide; concurrent misses share one
// fetch. Safe for concurrent use.
type JWKSKeySet struct {
	url    string
	client *http.Client
	now    func() time.Time

	mu        sync.Mutex
	keys      map[string]jose.JSONWebKey
	lastFetch time.Time
	fetched   bool
	inflight  *fetchCall
}

var _ oidc.KeySet = (*JWKSKeySet)(nil)

// NewJWKSKeySet returns a key set that reads jwksURL with client (which should
// carry a timeout). now supplies the clock.
func NewJWKSKeySet(jwksURL string, client *http.Client, now func() time.Time) *JWKSKeySet {
	return &JWKSKeySet{url: jwksURL, client: client, now: now, keys: map[string]jose.JSONWebKey{}}
}

// VerifySignature implements oidc.KeySet. Errors carry no token detail, which
// SessionVerifier maps to invalid_token.
func (k *JWKSKeySet) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	ctx, span := otel.Tracer("nebari-user-secrets").Start(ctx, "auth.JWKSKeySet.VerifySignature")
	defer span.End()
	fail := func(reason string, err error) error {
		span.RecordError(err)
		span.SetStatus(codes.Error, reason)
		return err
	}

	jws, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(jws.Signatures) != 1 || jws.Signatures[0].Header.KeyID == "" {
		return nil, fail("no_kid", errors.New("no usable kid"))
	}
	kid := jws.Signatures[0].Header.KeyID

	key, ok, err := k.lookup(ctx, kid)
	if err != nil {
		return nil, fail("lookup", err)
	}
	if !ok {
		return nil, fail("unknown_kid", errors.New("unknown kid"))
	}
	payload, err := jws.Verify(&key)
	if err != nil {
		return nil, fail("signature", errors.New("signature invalid"))
	}
	return payload, nil
}

// lookup returns the cached key for kid, fetching the JWKS when kid is absent
// and the window allows.
func (k *JWKSKeySet) lookup(ctx context.Context, kid string) (jose.JSONWebKey, bool, error) {
	k.mu.Lock()
	if key, ok := k.keys[kid]; ok {
		k.mu.Unlock()
		return key, true, nil
	}
	if call := k.inflight; call != nil {
		k.mu.Unlock()
		select {
		case <-call.done:
		case <-ctx.Done():
			return jose.JSONWebKey{}, false, ctx.Err()
		}
		k.mu.Lock()
		key, ok := k.keys[kid]
		k.mu.Unlock()
		return key, ok, nil
	}
	now := k.now()
	if k.fetched && now.Sub(k.lastFetch) < refetchWindow {
		k.mu.Unlock()
		return jose.JSONWebKey{}, false, errKeyLookupLimited
	}
	call := &fetchCall{done: make(chan struct{})}
	k.inflight, k.lastFetch, k.fetched = call, now, true
	k.mu.Unlock()

	// The fetch is detached from the caller's cancellation: a client that
	// drops its connection must not abort a refresh that waiters share and
	// that has already spent the window. It keeps the span, and is bounded.
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
	keys, err := k.fetch(fctx)
	cancel()

	k.mu.Lock()
	if err == nil {
		k.keys = keys
	}
	k.inflight = nil
	key, ok := k.keys[kid]
	k.mu.Unlock()
	close(call.done)
	if err != nil {
		return jose.JSONWebKey{}, false, err
	}
	return key, ok, nil
}

func (k *JWKSKeySet) fetch(ctx context.Context) (map[string]jose.JSONWebKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return nil, errors.New("jwks request")
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, errors.New("jwks fetch failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, errors.New("jwks read failed")
	}
	if len(body) > maxJWKSBytes {
		return nil, errors.New("jwks response too large")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, errors.New("jwks parse failed")
	}
	keys := make(map[string]jose.JSONWebKey, len(set.Keys))
	for _, key := range set.Keys {
		if key.KeyID != "" && key.IsPublic() && key.Valid() && (key.Use == "" || key.Use == "sig") {
			keys[key.KeyID] = key
		}
	}
	return keys, nil
}
