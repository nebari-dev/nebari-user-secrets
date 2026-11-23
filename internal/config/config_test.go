package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebari-dev/nebari-user-secrets/internal/service"
)

const validBase = `
namespace: nebari-user-secrets
keycloak:
  jwksURL: https://kc.example/realms/nebari/protocol/openid-connect/certs
  issuers: ["https://kc.example/realms/nebari"]
  clientID: landing
tls:
  certFile: /tls/tls.crt
  keyFile: /tls/tls.key
`

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name     string
		doc      string
		wantErr  string
		check    func(t *testing.T, c *Config)
		warnings int
	}{
		{name: "valid with defaults", doc: validBase, check: func(t *testing.T, c *Config) {
			if c.Guard.Mode != "enforced" {
				t.Errorf("guard mode = %q, want enforced", c.Guard.Mode)
			}
			if c.Limits != service.DefaultLimits() {
				t.Errorf("limits = %+v, want defaults", c.Limits)
			}
			if c.Namespace != "nebari-user-secrets" || c.Keycloak.ClientID != "landing" {
				t.Errorf("unexpected config %+v", c)
			}
		}},
		{name: "partial limits keep other defaults", doc: validBase + "limits:\n  maxSecrets: 5\n", check: func(t *testing.T, c *Config) {
			want := service.DefaultLimits()
			want.MaxSecrets = 5
			if c.Limits != want {
				t.Errorf("limits = %+v, want %+v", c.Limits, want)
			}
		}},
		{name: "unverified is allowed and warns", doc: validBase + "guard:\n  mode: unverified\n", warnings: 1},
		{name: "unknown guard mode", doc: validBase + "guard:\n  mode: sometimes\n", wantErr: "guard.mode"},
		{name: "negative limit", doc: validBase + "limits:\n  maxSecrets: -1\n", wantErr: "limits"},
		{name: "missing issuer list", doc: strings.Replace(validBase, `  issuers: ["https://kc.example/realms/nebari"]`+"\n", "", 1), wantErr: "keycloak.issuers"},
		{name: "empty issuer list", doc: strings.Replace(validBase, `["https://kc.example/realms/nebari"]`, `[]`, 1), wantErr: "keycloak.issuers"},
		{name: "empty string issuer", doc: strings.Replace(validBase, `["https://kc.example/realms/nebari"]`, `["https://kc.example/realms/nebari", ""]`, 1), wantErr: "keycloak.issuers"},
		{name: "missing clientID", doc: strings.Replace(validBase, "  clientID: landing\n", "", 1), wantErr: "keycloak.clientID"},
		{name: "empty clientID", doc: strings.Replace(validBase, "clientID: landing", `clientID: ""`, 1), wantErr: "keycloak.clientID"},
		{name: "missing jwksURL", doc: strings.Replace(validBase, "  jwksURL: https://kc.example/realms/nebari/protocol/openid-connect/certs\n", "", 1), wantErr: "keycloak.jwksURL"},
		{name: "missing namespace", doc: strings.Replace(validBase, "namespace: nebari-user-secrets\n", "", 1), wantErr: "namespace"},
		{name: "missing tls", doc: strings.Replace(validBase, "  keyFile: /tls/tls.key\n", "", 1), wantErr: "tls"},
		{name: "unknown field", doc: validBase + "bogus: 1\n", wantErr: "parse config"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(p, []byte(tc.doc), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(p)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := len(c.Warnings()); got != tc.warnings {
				t.Errorf("warnings = %v, want %d", c.Warnings(), tc.warnings)
			}
			if tc.check != nil {
				tc.check(t, c)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("want error")
	}
}
