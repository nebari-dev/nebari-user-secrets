//go:build e2e

// Command nicrender renders the vendored nebari-infrastructure-core CA and
// trust-bundle templates (test/e2e/fixtures/nic) the way NIC renders them for
// certificate.type: letsencrypt, and writes the manifests to stdout.
//
// Letsencrypt is used because its root CA constraints are the strictest: a
// serving certificate that verifies here verifies on every certificate type.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// templateData holds the TemplateData fields the vendored templates use,
// filled as NewTemplateData does at de81b11 (pkg/argocd/writer.go:158-246)
// for certificate.type: letsencrypt. A template naming any other field fails
// to render, which flags drift.
type templateData struct {
	Domain                    string
	RootCASecretName          string
	CAIssuerName              string
	RootCAPermittedDNSDomains []string
	TrustBundlePEM            string
}

// manifests are rendered in this order: the root Certificate needs the
// self-signed issuer, the CA issuer needs the root, the Bundle reads the root.
var manifests = []string{
	"manifests/security/issuers/selfsigned-clusterissuer.yaml",
	"manifests/security/issuers/root-ca-certificate.yaml",
	"manifests/security/issuers/ca-clusterissuer.yaml",
	"manifests/security/trust-bundle/bundle.yaml",
}

// templateFuncs mirrors NIC's (pkg/argocd/writer.go:599-602 at de81b11).
var templateFuncs = template.FuncMap{
	"indent":  indentLines,
	"nindent": func(spaces int, s string) string { return "\n" + indentLines(spaces, s) },
}

// indentLines is a copy of NIC's (pkg/argocd/writer.go at de81b11): it
// prefixes every non-empty line of s with the given number of spaces.
func indentLines(spaces int, s string) string {
	pad := strings.Repeat(" ", spaces)
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		lines[i] = pad + line
	}
	return strings.Join(lines, "\n")
}

func letsencryptData() templateData {
	return templateData{
		Domain:                    "nebari.local",
		RootCASecretName:          "nebari-root-ca",
		CAIssuerName:              "nebari-ca-issuer",
		RootCAPermittedDNSDomains: []string{"svc", "svc.cluster.local"},
	}
}

func render(dir string, data templateData) ([]byte, error) {
	var out bytes.Buffer
	for _, name := range manifests {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		tmpl, err := template.New(name).Funcs(templateFuncs).Parse(string(raw))
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		fmt.Fprintf(&out, "---\n# Source: %s\n", name)
		if err := tmpl.Execute(&out, data); err != nil {
			return nil, fmt.Errorf("render %s: %w", name, err)
		}
		if !bytes.HasSuffix(out.Bytes(), []byte("\n")) {
			out.WriteByte('\n')
		}
	}
	return out.Bytes(), nil
}

func main() {
	dir := flag.String("dir", "test/e2e/fixtures/nic", "directory holding the vendored NIC templates")
	flag.Parse()
	b, err := render(*dir, letsencryptData())
	if err != nil {
		fmt.Fprintln(os.Stderr, "nicrender:", err)
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(b)
}
