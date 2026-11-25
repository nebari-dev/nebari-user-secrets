# Architecture patterns

### Go layout: cmd and internal
Binaries live in `cmd/<binary>` and contain wiring only. All other code lives in `internal/<pkg>`, one package per concern, with constructors that take interfaces and return concrete types.

**Confirmed:** 2026-11-20 (spec: docs/design/user-secrets-spec.md)

### Chart guardrails in validate.yaml
Unsafe or incomplete values are rejected at render time by `chart/templates/validate.yaml`, which emits no manifest and calls `fail` with a message naming the value to change. It covers the shared-namespace guard (the service namespace may not also be a registered workload or creator namespace unless `guard.allowSharedNamespace` is set), mode combinations (`allowSharedNamespace` only with `guard.mode: unverified`), required values (`keycloak.clientID`, `keycloak.jwksURL`, `keycloak.issuers`, `landing.namespace`, `landing.podSelector`) and the service's Kubernetes client rate limit (`kubernetes.qps` greater than 0, `kubernetes.burst` a whole number of at least 1 and at least `kubernetes.qps`). `test/chart` has a table-driven test that asserts each failure and that a valid override renders. The chart and the Go config are one contract: `TestConfigMapLoads` feeds the rendered `config.yaml` to `config.Load`, and `TestCreatorsConfigMapMatchesGo` compares the creators ConfigMap with `CreatorsConfigMapData`.

**Confirmed:** 2026-11-23 (spec: docs/design/user-secrets-spec.md, "validate.yaml"; precedent: external-auth-pack/chart/templates/validate.yaml)

### Bash cluster harnesses behind Make targets
Cluster test harnesses are bash under `test/<area>/` driven by Make targets, and Go tests behind a build tag (`e2e`, `journeys`) read the harness's kubeconfig.

**Confirmed:** 2026-11-24 (spec: docs/superpowers/specs/2026-11-24-ci-tiers-design.md; precedent: Makefile, test/e2e/setup.sh, test/e2e/helpers_test.go)

### External versions pinned once
Every external version lives in `ci/pins.env` with a comment naming its source; anything that cannot read the file is cross-checked against it by a Tier 1 test.

**Confirmed:** 2026-11-24 (spec: docs/superpowers/specs/2026-11-24-ci-tiers-design.md; precedent: ci/pins.env, ci/load-pins.sh, test/journeys/catalog/pins_test.go)

### Vendored upstream files with SOURCE and drift check
A vendored copy carries a `SOURCE` file naming repo, commit and files, and a Make target diffs it against upstream.

**Confirmed:** 2026-11-24 (spec: docs/superpowers/specs/2026-11-24-ci-tiers-design.md; precedent: test/e2e/fixtures/nic/SOURCE, Makefile `nic-fixtures-check`)
