// Package auth verifies the Keycloak access tokens the management API accepts.
package auth

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

// ErrInvalidToken is the only error Verify returns. It carries no detail so
// that nothing about a token or its claims can reach a response or a log.
var ErrInvalidToken = errors.New("invalid_token")

// SessionVerifier accepts only Keycloak access tokens issued to the landing
// page's SPA client.
type SessionVerifier struct {
	verifier *oidc.IDTokenVerifier // nil when misconfigured: every token is refused
	issuers  []string
	clientID string
}

// NewSessionVerifier builds a verifier. keys selects the signing key by kid,
// issuers lists the accepted iss values (exact match), clientID is the landing
// SPA client that azp must equal. With no issuers, an empty issuer entry or an empty clientID every
// token is refused.
func NewSessionVerifier(keys oidc.KeySet, issuers []string, clientID string, now func() time.Time) *SessionVerifier {
	v := &SessionVerifier{issuers: slices.Clone(issuers), clientID: clientID}
	if len(issuers) == 0 || clientID == "" || slices.Contains(issuers, "") {
		return v
	}
	v.verifier = oidc.NewVerifier(issuers[0], keys, &oidc.Config{
		SkipClientIDCheck:    true,
		SkipIssuerCheck:      true,
		SupportedSigningAlgs: []string{"RS256"},
		Now:                  now,
	})
	return v
}

type sessionClaims struct {
	Iss               string   `json:"iss"`
	Typ               string   `json:"typ"`
	Azp               string   `json:"azp"`
	Sub               string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
}

// Verify checks bearer, the raw token without the "Bearer " prefix. Every
// failure returns ErrInvalidToken.
func (v *SessionVerifier) Verify(ctx context.Context, bearer string) (model.Principal, error) {
	ctx, span := otel.Tracer("nebari-user-secrets").Start(ctx, "auth.SessionVerifier.Verify")
	defer span.End()

	reject := func(reason string) error {
		span.SetAttributes(attribute.String("auth.reason", reason))
		span.RecordError(ErrInvalidToken)
		span.SetStatus(codes.Error, reason)
		return ErrInvalidToken
	}

	if v.verifier == nil {
		return model.Principal{}, reject("misconfigured")
	}
	tok, err := v.verifier.Verify(ctx, bearer)
	if err != nil {
		return model.Principal{}, reject("signature")
	}
	var c sessionClaims
	if err := tok.Claims(&c); err != nil {
		return model.Principal{}, reject("claims")
	}
	switch {
	case !slices.Contains(v.issuers, c.Iss):
		return model.Principal{}, reject("iss")
	case c.Typ != "Bearer":
		return model.Principal{}, reject("typ")
	case c.Azp != v.clientID:
		return model.Principal{}, reject("azp")
	case c.Sub == "":
		return model.Principal{}, reject("sub")
	}
	return model.Principal{Kind: "user", Sub: c.Sub, Username: c.PreferredUsername, Groups: c.Groups}, nil
}
