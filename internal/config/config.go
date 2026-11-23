// Package config loads and validates the service's values-rendered config
// file.
package config

import (
	"bytes"
	"fmt"
	"os"
	"slices"

	"sigs.k8s.io/yaml"

	"github.com/nebari-dev/nebari-user-secrets/internal/registry"
	"github.com/nebari-dev/nebari-user-secrets/internal/service"
)

// Guard modes.
const (
	GuardEnforced   = "enforced"
	GuardUnverified = "unverified"
)

// Config is the service configuration.
type Config struct {
	Namespace string          `json:"namespace"`
	Registry  registry.Config `json:"registry"`
	Keycloak  Keycloak        `json:"keycloak"`
	TLS       TLS             `json:"tls"`
	Guard     Guard           `json:"guard"`
	Limits    service.Limits  `json:"limits"`
	InitImage string          `json:"initImage"`
}

// Keycloak names the realm whose access tokens the management API accepts.
type Keycloak struct {
	JWKSURL  string   `json:"jwksURL"`
	Issuers  []string `json:"issuers"`
	ClientID string   `json:"clientID"`
}

// TLS names the serving certificate and key for the management listener.
type TLS struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// Guard selects how the policy guard gates delivery.
type Guard struct {
	Mode string `json:"mode"` // enforced (default) or unverified
}

// Load reads, defaults and validates the file at path. Unknown fields are
// rejected.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.UnmarshalStrict(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.Guard.Mode == "" {
		c.Guard.Mode = GuardEnforced
	}
	d := service.DefaultLimits()
	for _, l := range []struct {
		v   *int
		def int
	}{{&c.Limits.MaxSecrets, d.MaxSecrets}, {&c.Limits.MaxValueBytes, d.MaxValueBytes}, {&c.Limits.MaxRecordBytes, d.MaxRecordBytes}} {
		if *l.v < 0 {
			return nil, fmt.Errorf("config: limits must not be negative")
		}
		if *l.v == 0 {
			*l.v = l.def
		}
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	switch {
	case c.Namespace == "":
		return fmt.Errorf("config: namespace is required")
	case c.Keycloak.JWKSURL == "":
		return fmt.Errorf("config: keycloak.jwksURL is required")
	case len(c.Keycloak.Issuers) == 0 || slices.Contains(c.Keycloak.Issuers, ""):
		return fmt.Errorf("config: keycloak.issuers needs at least one entry and no empty entries")
	case c.Keycloak.ClientID == "":
		return fmt.Errorf("config: keycloak.clientID is required")
	case c.TLS.CertFile == "" || c.TLS.KeyFile == "":
		return fmt.Errorf("config: tls.certFile and tls.keyFile are required")
	case c.Guard.Mode != GuardEnforced && c.Guard.Mode != GuardUnverified:
		return fmt.Errorf("config: guard.mode must be %q or %q", GuardEnforced, GuardUnverified)
	}
	return nil
}

// Warnings lists conditions the operator should see in the startup log.
func (c *Config) Warnings() []string {
	var w []string
	if c.Guard.Mode == GuardUnverified {
		w = append(w, "guard.mode is unverified: secrets are delivered without a verified policy guard")
	}
	return w
}

// BuildRegistry validates and builds the registry from the config.
func (c *Config) BuildRegistry() (*registry.Registry, error) {
	raw, err := yaml.Marshal(c.Registry)
	if err != nil {
		return nil, fmt.Errorf("encode registry: %w", err)
	}
	return registry.Load(bytes.NewReader(raw))
}
