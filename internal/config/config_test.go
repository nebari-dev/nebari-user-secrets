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
			if c.Kubernetes != (Kubernetes{QPS: 50, Burst: 100}) {
				t.Errorf("kubernetes = %+v, want qps 50 burst 100", c.Kubernetes)
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
		{name: "kubernetes client limits set", doc: validBase + "kubernetes:\n  qps: 20.5\n  burst: 21\n", check: func(t *testing.T, c *Config) {
			if c.Kubernetes != (Kubernetes{QPS: 20.5, Burst: 21}) {
				t.Errorf("kubernetes = %+v, want qps 20.5 burst 21", c.Kubernetes)
			}
		}},
		{name: "kubernetes burst equal to qps", doc: validBase + "kubernetes:\n  qps: 30\n  burst: 30\n", check: func(t *testing.T, c *Config) {
			if c.Kubernetes != (Kubernetes{QPS: 30, Burst: 30}) {
				t.Errorf("kubernetes = %+v, want qps 30 burst 30", c.Kubernetes)
			}
		}},
		{name: "partial kubernetes keeps the other default", doc: validBase + "kubernetes:\n  qps: 10\n", check: func(t *testing.T, c *Config) {
			if c.Kubernetes != (Kubernetes{QPS: 10, Burst: 100}) {
				t.Errorf("kubernetes = %+v, want qps 10 burst 100", c.Kubernetes)
			}
		}},
		{name: "kubernetes qps in exponent form as the chart renders it", doc: validBase + "kubernetes:\n  qps: 1e+06\n  burst: 1000000\n", check: func(t *testing.T, c *Config) {
			if c.Kubernetes != (Kubernetes{QPS: 1e6, Burst: 1000000}) {
				t.Errorf("kubernetes = %+v, want qps 1e6 burst 1000000", c.Kubernetes)
			}
		}},
		{name: "negative kubernetes qps", doc: validBase + "kubernetes:\n  qps: -1\n", wantErr: "kubernetes.qps"},
		{name: "nan kubernetes qps is rejected by the parser", doc: validBase + "kubernetes:\n  qps: .nan\n", wantErr: "parse config"},
		{name: "negative kubernetes burst", doc: validBase + "kubernetes:\n  burst: -1\n", wantErr: "kubernetes.burst"},
		{name: "kubernetes burst below qps", doc: validBase + "kubernetes:\n  qps: 50\n  burst: 49\n", wantErr: "kubernetes.burst must be at least kubernetes.qps"},
		{name: "kubernetes qps above default burst", doc: validBase + "kubernetes:\n  qps: 200\n", wantErr: "kubernetes.burst must be at least kubernetes.qps"},
		{name: "kubernetes qps not a number", doc: validBase + "kubernetes:\n  qps: fast\n", wantErr: "parse config"},
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
