package initfiles

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestHTTPResolveClientTimeouts pins the per-attempt timeouts: a dropped or
// stalled connection must fail within 5 s so the retry schedule can run inside
// the 30 s budget, and the response header wait must stay above the server's
// 20 s resolve timeout.
func TestHTTPResolveClientTimeouts(t *testing.T) {
	_, ca := tlsServer(t, func(http.ResponseWriter, *http.Request) {})
	c, err := NewHTTPResolveClient("https://user-secrets.ns.svc:8443/api/v1/resolve", ca)
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := c.hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.hc.Transport)
	}
	if tr.DialContext == nil {
		t.Error("transport has no DialContext (the zero dialer has no timeout)")
	}
	tests := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"dial timeout", newDialer().Timeout, 5 * time.Second},
		{"TLS handshake timeout", tr.TLSHandshakeTimeout, 5 * time.Second},
		{"response header timeout", tr.ResponseHeaderTimeout, 25 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %s, want %s", tt.name, tt.got, tt.want)
			}
		})
	}
}

// TestFetchRetriesStalledHandshake: a server that accepts TCP but never
// answers the TLS ClientHello fails each attempt after the 5 s handshake
// timeout, so a budget of 8 s makes a second attempt instead of spending
// everything on the first.
func TestFetchRetriesStalledHandshake(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about 8 s")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn) // held open, never read or written
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	_, ca := tlsServer(t, func(http.ResponseWriter, *http.Request) {})
	c, err := NewHTTPResolveClient("https://"+ln.Addr().String()+"/api/v1/resolve", ca)
	if err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	status, ok := Fetch(context.Background(), c, tokenPath, NewFileWriter(t.TempDir()), 8*time.Second)
	elapsed := time.Since(start)
	m := regexp.MustCompile(`^error unreachable .* after (\d+) attempts$`).FindStringSubmatch(status)
	if ok || m == nil {
		t.Fatalf("status = %q ok = %v, want error unreachable ... after N attempts", status, ok)
	}
	if n, _ := strconv.Atoi(m[1]); n < 2 {
		t.Fatalf("status = %q: %d attempt(s) in %s, want at least 2", status, n, elapsed.Round(time.Millisecond))
	}
	if elapsed > 12*time.Second {
		t.Fatalf("Fetch took %s with an 8 s budget", elapsed)
	}
}
