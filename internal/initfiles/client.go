package initfiles

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

var (
	// ErrCAMissing means the trust bundle is absent or holds no certificate.
	ErrCAMissing = errors.New("ca_missing")
	// ErrBadURL means the resolve URL is not an https URL with a host.
	ErrBadURL = errors.New("bad resolve url")
	// errBadResponse means a 200 body that does not match the contract.
	errBadResponse = errors.New("malformed resolve response")
	// errInvalidResponse means a well-formed 200 body with an entry that
	// breaks the contract.
	errInvalidResponse = errors.New("invalid resolve response")
)

// maxBody bounds what the client reads from a response. The files volume is
// 1 MiB, so a valid body is well under this even with base64 and JSON overhead.
const maxBody = 4 << 20

// Per-attempt limits. A dropped or stalled connection fails within
// dialTimeout or handshakeTimeout, so Fetch can retry inside its 30 s budget;
// headerTimeout stays above the server's 20 s resolve timeout.
const (
	dialTimeout      = 5 * time.Second
	handshakeTimeout = 5 * time.Second
	headerTimeout    = 25 * time.Second
)

// newDialer returns the dialer for resolve connections; its Timeout also
// bounds the DNS lookup.
func newDialer() *net.Dialer { return &net.Dialer{Timeout: dialTimeout} }

// codeRE is the shape of a contract error code; anything else is not echoed.
var codeRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// APIError is a non-200 answer from the resolve API.
type APIError struct {
	Status int
	Code   string
}

func (e *APIError) Error() string { return fmt.Sprintf("resolve: http %d %s", e.Status, e.Code) }

// HTTPResolveClient calls the resolve API over TLS (HTTP/1.1).
type HTTPResolveClient struct {
	url string
	hc  *http.Client
}

// NewHTTPResolveClient returns a client for rawURL that trusts only the
// certificates in caFile and checks the URL host against the server
// certificate. It returns ErrCAMissing when caFile is absent or has no
// certificate, and ErrBadURL when rawURL is not https with a host.
func NewHTTPResolveClient(rawURL, caFile string) (*HTTPResolveClient, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, fmt.Errorf("%w: want https://<host>[:port]/<path>", ErrBadURL)
	}
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCAMissing, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%w: no certificate in %s", ErrCAMissing, caFile)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		// A non-nil TLSNextProto keeps the transport on HTTP/1.1.
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		DialContext:           newDialer().DialContext,
		TLSHandshakeTimeout:   handshakeTimeout,
		ResponseHeaderTimeout: headerTimeout,
		DisableKeepAlives:     true,
		// Proxy stays nil: the call never leaves the cluster network.
	}
	return &HTTPResolveClient{
		url: u.String(),
		hc: &http.Client{
			Transport: tr,
			// Never follow a redirect with the token; report it instead.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

type resolveBody struct {
	Secrets *[]struct {
		Env      string `json:"env"`
		ValueB64 string `json:"value_b64"`
	} `json:"secrets"`
}

// Resolve posts the token and returns the decoded secrets. A non-200 answer is
// an *APIError; a network failure is returned as is. No error carries the
// token or a value.
func (c *HTTPResolveClient) Resolve(ctx context.Context, token string) ([]model.ResolvedSecret, error) {
	ctx, span := otel.Tracer("nebari-user-secrets").Start(ctx, "initfiles.HTTPResolveClient.Resolve")
	defer span.End()
	secrets, err := c.resolve(ctx, token)
	if err != nil {
		span.RecordError(err)
	}
	return secrets, err
}

func (c *HTTPResolveClient) resolve(ctx context.Context, token string) ([]model.ResolvedSecret, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadURL, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("read resolve response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp.StatusCode, body)
	}
	var rb resolveBody
	if err := json.Unmarshal(body, &rb); err != nil || rb.Secrets == nil {
		// The decoder's message may quote body bytes, so it is not wrapped.
		return nil, errBadResponse
	}
	out := make([]model.ResolvedSecret, 0, len(*rb.Secrets))
	for i, s := range *rb.Secrets {
		v, err := base64.StdEncoding.DecodeString(s.ValueB64)
		if err != nil {
			return nil, fmt.Errorf("%w: secret %d value is not base64", errInvalidResponse, i)
		}
		out = append(out, model.ResolvedSecret{Env: s.Env, Value: v})
	}
	return out, nil
}

// apiError reads the contract's {"error": "<code>"} body. A body without a
// well-formed code (a proxy page, say) gets a fixed code instead.
func apiError(status int, body []byte) *APIError {
	var eb struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &eb) == nil && codeRE.MatchString(eb.Error) {
		return &APIError{Status: status, Code: eb.Error}
	}
	if status == http.StatusServiceUnavailable {
		return &APIError{Status: status, Code: "unavailable"}
	}
	return &APIError{Status: status, Code: "bad_response"}
}
