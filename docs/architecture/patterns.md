# Architecture patterns

### Go layout: cmd and internal
Binaries live in `cmd/<binary>` and contain wiring only. All other code lives in `internal/<pkg>`, one package per concern, with constructors that take interfaces and return concrete types.

**Confirmed:** 2026-11-20 (spec: docs/design/user-secrets-spec.md)

### Chart guardrails in validate.yaml
Unsafe or incomplete values are rejected at render time by `chart/templates/validate.yaml`, which emits no manifest and calls `fail` with a message naming the value to change. It covers the shared-namespace guard (the service namespace may not also be a registered workload or creator namespace unless `guard.allowSharedNamespace` is set), mode combinations (`allowSharedNamespace` only with `guard.mode: unverified`), required values (`keycloak.clientID`, `keycloak.jwksURL`, `keycloak.issuers`, `landing.namespace`, `landing.podSelector`) and the service's Kubernetes client rate limit (`kubernetes.qps` greater than 0, `kubernetes.burst` a whole number of at least 1 and at least `kubernetes.qps`). `test/chart` has a table-driven test that asserts each failure and that a valid override renders. The chart and the Go config are one contract: `TestConfigMapLoads` feeds the rendered `config.yaml` to `config.Load`, and `TestCreatorsConfigMapMatchesGo` compares the creators ConfigMap with `CreatorsConfigMapData`.

**Confirmed:** 2026-11-23 (spec: docs/design/user-secrets-spec.md, "validate.yaml"; precedent: external-auth-pack/chart/templates/validate.yaml)
