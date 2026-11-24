// Package cluster embeds the cluster-scoped bundle's policy YAML so the
// service can compare the live admission guard against what this binary
// expects.
package cluster

import _ "embed"

// Policies is cluster/policies.yaml: both ValidatingAdmissionPolicies and both
// bindings, with the default install namespace.
//
//go:embed policies.yaml
var Policies []byte
