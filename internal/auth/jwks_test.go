package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type signer struct {
	kid string
	key *rsa.PrivateKey
}

func newSigner(t *testing.T, kid string) signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return signer{kid, k}
}

func (s signer) jwk() jose.JSONWebKey {
	return jose.JSONWebKey{Key: &s.key.PublicKey, KeyID: s.kid, Algorithm: "RS256", Use: "sig"}
}

func (s signer) sign(t *testing.T, kid string) string {
	t.Helper()
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: s.key, KeyID: kid}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	o, err := sg.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := o.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type jwksServer struct {
	hits atomic.Int64
	mu   sync.Mutex
	body []byte
	code int
	srv  *httptest.Server
}

func newJWKSServer(t *testing.T, keys ...signer) *jwksServer {
	t.Helper()
	j := &jwksServer{code: 200}
	j.setKeys(keys...)
	j.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		j.hits.Add(1)
		j.mu.Lock()
		defer j.mu.Unlock()
		w.WriteHeader(j.code)
		_, _ = w.Write(j.body)
	}))
	t.Cleanup(j.srv.Close)
	return j
}

func (j *jwksServer) setKeys(keys ...signer) {
	set := jose.JSONWebKeySet{}
	for _, k := range keys {
		set.Keys = append(set.Keys, k.jwk())
	}
	b, _ := json.Marshal(set)
	j.mu.Lock()
	j.body = b
	j.mu.Unlock()
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestJWKSKeySet(t *testing.T) {
	a, b, other := newSigner(t, "a"), newSigner(t, "b"), newSigner(t, "a")
	type step struct {
		token   func(t *testing.T) string
		advance time.Duration
		mutate  func(j *jwksServer)
		wantErr bool
		hits    int64 // total server hits after the step
	}
	good := func(s signer) func(*testing.T) string { return func(t *testing.T) string { return s.sign(t, s.kid) } }
	tests := []struct {
		name  string
		start []signer
		steps []step
	}{
		{name: "first use fetches once, known kid then passes with no fetch", start: []signer{a}, steps: []step{
			{token: good(a), hits: 1}, {token: good(a), hits: 1}, {token: good(a), hits: 1},
		}},
		{name: "known kid with bad signature fails with no fetch", start: []signer{a}, steps: []step{
			{token: good(a), hits: 1},
			{token: func(t *testing.T) string { return other.sign(t, "a") }, advance: time.Minute, wantErr: true, hits: 1},
		}},
		{name: "unknown kid fetches once then is capped inside 10s", start: []signer{a}, steps: []step{
			{token: good(a), hits: 1},
			{token: good(b), advance: 11 * time.Second, wantErr: true, hits: 2},
			{token: good(b), advance: time.Second, wantErr: true, hits: 2},
		}},
		{name: "after 10s a rotated key verifies", start: []signer{a}, steps: []step{
			{token: good(a), hits: 1},
			{token: good(b), advance: 11 * time.Second, wantErr: true, hits: 2},
			{token: good(b), advance: 11 * time.Second, mutate: func(j *jwksServer) { j.setKeys(a, b) }, hits: 3},
			{token: good(b), hits: 3},
			{token: good(a), hits: 3},
		}},
		{name: "empty kid rejected without fetch", start: []signer{a}, steps: []step{
			{token: func(t *testing.T) string { return a.sign(t, "") }, wantErr: true, hits: 0},
		}},
		{name: "garbage token rejected without fetch", start: []signer{a}, steps: []step{
			{token: func(*testing.T) string { return "nope" }, wantErr: true, hits: 0},
		}},
		{name: "invalid JWKS body errors", start: []signer{a}, steps: []step{
			{token: good(a), mutate: func(j *jwksServer) { j.body = []byte("{not json") }, wantErr: true, hits: 1},
		}},
		{name: "oversized JWKS body errors", start: []signer{a}, steps: []step{
			{token: good(a), mutate: func(j *jwksServer) { j.body = []byte(strings.Repeat("a", maxJWKSBytes+10)) }, wantErr: true, hits: 1},
		}},
		{name: "non-200 JWKS errors", start: []signer{a}, steps: []step{
			{token: good(a), mutate: func(j *jwksServer) { j.code = 500 }, wantErr: true, hits: 1},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newJWKSServer(t, tc.start...)
			c := &clock{t: time.Unix(1_000_000, 0)}
			ks := NewJWKSKeySet(srv.srv.URL, srv.srv.Client(), c.now)
			for i, s := range tc.steps {
				c.add(s.advance)
				if s.mutate != nil {
					s.mutate(srv) // no request is in flight between steps
				}
				_, err := ks.VerifySignature(context.Background(), s.token(t))
				if (err != nil) != s.wantErr {
					t.Fatalf("step %d: err = %v, wantErr %v", i, err, s.wantErr)
				}
				if got := srv.hits.Load(); got != s.hits {
					t.Fatalf("step %d: hits = %d, want %d", i, got, s.hits)
				}
			}
		})
	}
}

func TestJWKSKeySetRejectsNonCompactTokens(t *testing.T) {
	a, b := newSigner(t, "a"), newSigner(t, "b")
	srv := newJWKSServer(t, a, b)
	ks := NewJWKSKeySet(srv.srv.URL, srv.srv.Client(), time.Now)
	mk := func(keys ...signer) jose.Signer {
		var sk []jose.SigningKey
		for _, k := range keys {
			sk = append(sk, jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: k.key, KeyID: k.kid}})
		}
		sg, err := jose.NewMultiSigner(sk, nil)
		if err != nil {
			t.Fatal(err)
		}
		return sg
	}
	tests := []struct {
		name string
		sg   jose.Signer
	}{
		{"single signature JSON serialization", mk(a)},
		{"two signature JSON serialization", mk(a, b)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, err := tc.sg.Sign([]byte("x"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ks.VerifySignature(context.Background(), o.FullSerialize()); err == nil {
				t.Fatal("non-compact token accepted")
			}
			if srv.hits.Load() != 0 {
				t.Fatal("fetched for a rejected token")
			}
		})
	}
}

// blockingServer holds every JWKS request until release is closed.
func blockingServer(t *testing.T, keys ...signer) (url string, client *http.Client, hits *atomic.Int64, started chan struct{}, release chan struct{}) {
	t.Helper()
	set := jose.JSONWebKeySet{}
	for _, k := range keys {
		set.Keys = append(set.Keys, k.jwk())
	}
	body, _ := json.Marshal(set)
	hits, started, release = &atomic.Int64{}, make(chan struct{}, 100), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		started <- struct{}{}
		<-release
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, srv.Client(), hits, started, release
}

func TestJWKSKeySetConcurrentMissesCoalesce(t *testing.T) {
	a := newSigner(t, "a")
	url, client, hits, started, release := blockingServer(t, a)
	ks := NewJWKSKeySet(url, client, (&clock{t: time.Unix(1_000_000, 0)}).now)
	tok := a.sign(t, "a")
	const n = 20
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { _, err := ks.VerifySignature(context.Background(), tok); errs <- err }()
	}
	<-started
	// Give the other callers time to reach the in-flight wait. Without
	// coalescing they would be refused by the window and fail.
	time.Sleep(100 * time.Millisecond)
	close(release)
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("hits = %d, want 1", got)
	}
}

func TestJWKSKeySetFetchSurvivesLeaderCancel(t *testing.T) {
	a := newSigner(t, "a")
	url, client, hits, started, release := blockingServer(t, a)
	c := &clock{t: time.Unix(1_000_000, 0)}
	ks := NewJWKSKeySet(url, client, c.now)
	tok := a.sign(t, "a")

	leaderCtx, cancel := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() { _, err := ks.VerifySignature(leaderCtx, tok); leaderErr <- err }()
	<-started
	waiterErr := make(chan error, 1)
	go func() { _, err := ks.VerifySignature(context.Background(), tok); waiterErr <- err }()
	time.Sleep(100 * time.Millisecond)
	cancel() // the client drops mid-fetch
	close(release)

	if err := <-waiterErr; err != nil {
		t.Fatalf("waiter failed by the leader's cancellation: %v", err)
	}
	<-leaderErr // the leader's own outcome is not asserted
	// A later lookup inside the window finds the refreshed key.
	c.add(time.Second)
	if _, err := ks.VerifySignature(context.Background(), tok); err != nil {
		t.Fatalf("later lookup: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("hits = %d, want 1", got)
	}
}
