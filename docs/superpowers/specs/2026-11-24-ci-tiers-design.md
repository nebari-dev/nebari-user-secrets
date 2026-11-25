# Design: three-tier CI for nebari-user-secrets

**Date:** 2026-11-24
**Status:** approved 2026-11-24
**Repo:** nebari-user-secrets (this repo only)
**Builds on:** `docs/design/user-secrets.md` (the design doc, our feature source), `docs/design/user-secrets-spec.md` (the 22 journeys), `docs/superpowers/plans/2026-11-20-user-secrets-service.md` (the slice stack)

## Intent

From the CI slice on, every PR in the user-secrets stack should prove, in CI, as much of what the design doc promises as CI can reach, and say plainly what it cannot. Today CI runs unit tests and one kind job on `pull_request` only, lint has failed on every PR since #2 without anyone noticing, nothing runs in a merge queue, and nothing runs on a real Nebari. The goal is three tiers with a written map from features to tests, so a reviewer can see which promise each green check backs and which promises no check backs.

## Goals

- **Tier 1 (unit and integration):** every PR push and every merge-queue entry runs lint, `go test -race`, chart tests and the journey catalog check.
- **Tier 2 (kind):** a required check on every PR push and merge-queue entry. A kind cluster with the real dependencies (Calico, cert-manager, trust-manager, NIC's CA templates, a real Keycloak) runs the image built from the commit under test, and the admission-policy matrix runs once per supported Kubernetes version. Grown from the existing `make e2e-up && make e2e-test` and `test/policy/run-all.sh`, not rewritten.
- **Tier 3 (real Nebari):** user journeys on a Nebari deployed by the latest released NIC, with this repo's chart installed through an Argo CD Application in the platform GitOps repo, from the commit under test. Runs on `merge_group`, release tags and `workflow_dispatch`; skipped on `pull_request`.
- **One pins file** holds every external version the tiers depend on, and every tier reads it.
- **Every job summary** states the commit under test and every pinned version; Tier 3 also states the resolved NIC release.
- **Features have stable IDs** (F1...) taken from the design doc; journeys keep the spec's stable IDs (J1...J22) and each names its feature. Each journey check is mapped to a tier, or listed as not covered with a reason.
- **No gap passes as covered:** the catalog check fails Tier 1 when a check marked covered names a test that does not exist.

## Non-goals

- A Nebari-wide reusable journey harness or a published conformance contract. The F/J IDs are shaped so a later contract can adopt them, nothing more.
- Testing against NIC `main`. Tier 3 only ever uses a released NIC.
- Journeys that need data-science-pack, dask-gateway-pack or jhub-apps integration. Those packs have not shipped `userSecrets` support; their journeys stay on the not-covered list until they do.
- Turning on the merge queue or changing the `main` ruleset as part of this work. The design produces the report; the user changes the ruleset.

## Anti-goals

- A required check that needs a repository secret. Fork PRs run without secrets, so any such check would block every outside contributor.
- A check whose name says "journeys" but which only proves the platform came up.
- A not-covered journey hidden by a green check, or counted as covered because a narrower test passes.

## Constraints

- **Repo:** public, so a merge queue is available. The `main` ruleset today: one approval, squash only, no required status checks.
- **Stack:** plain chained PRs (#1 design, #2...#7), not `gh stack` (the extension is not installed). Only #1 targets `main`. GitHub retargets the next PR to `main` when its base branch merges and is deleted, so each PR enters the merge queue only once it is at the bottom of the stack. `merge_group` therefore only ever tests one PR on top of `main`.
- **NIC:** the latest release, v0.18.0 (2026-11-18), predates nebari-infrastructure-core#787 (merge commit `de81b1131fbe26fca289f841347d84af727f692f`, 2026-11-23). Without #787 there is no `nebari-ca-issuer` or trust bundle, our chart's serving certificate cannot be issued, and every Tier 3 run fails at install. The user's decision: Tier 3 is built now and stays non-blocking until a NIC release contains #787.
- **Runners:** standard `ubuntu-latest` (4 vCPU, 16 GB, 14 GB free disk for public repos). Whether Tier 3 fits is to be measured, not assumed (see "Report before turning anything on").
- **Deploy action:** `nebari-dev/action-nebari-sandbox@v3.0.0` (its `action.yml` and `add-software-pack/action.yml` at that tag). It deploys NIC's local provider on kind on the runner, outputs `kubeconfig`, `gitops-dir`, `keycloak-realm-admin-password`, `keycloak-issuer-url`, `ca-cert-path`, `gateway-ip`, and takes `nic-version`, `in-cluster-dns`, `timing-report`, `resource-summary`. Its `token` input is the workflow `GITHUB_TOKEN`, not a repo secret.

## Approaches

1. **A CI slice in the existing stack, after Slice 6 (chosen).** Tier 2 already lives in the stack (`test/e2e`, `make e2e-up`), so the new slice grows it, adds Tier 3 and the catalog, and later slices add their journeys' tests as they land. Cost: the stack is one PR longer, and later slices renumber.
2. **A separate CI project after the stack merges.** Cleaner history, but the open PRs stay unguarded until then and Tier 2 gets built twice.
3. **A Nebari-wide journey harness that other packs adopt.** Larger, and front-runs the conformance contract that is out of scope.

The user picked approach 1.

**Deploy action, sandbox vs deploy-nebari-action:** `action-nebari-sandbox` is used. It has in-cluster DNS for Keycloak, the CA path, the GitOps dir and `add-software-pack`, and it emits the timing and resource reports the throughput report needs. `deploy-nebari-action` has a full Argo CD convergence wait that the sandbox lacks; `add-software-pack`'s own Healthy wait covers our Applications, and Tier 3 adds a short whole-platform convergence check of its own (all Applications `Synced` and `Healthy`) before journeys start.

**Keeping Tier 3 non-blocking until NIC ships #787, mechanism (b) (my call, from my recommendation; the user picked approach 1 without choosing a or b):** Tier 3 is a required check from the day the ruleset requires anything. A gate step resolves the latest NIC release and asks GitHub whether that tag contains `de81b11`. While it does not, a `merge_group` run skips everything after the gate and passes with a summary line saying why (user decision: the queue should not pay the bring-up time for a failure we already expect); a tag or `workflow_dispatch` run runs in full, records every failure as a warning under a `NON-BLOCKING` heading, and exits 0. Once a release contains #787, the same job fails on any journey failure with nobody editing anything. The alternative (a), `continue-on-error` flipped by hand later, was rejected because nobody would remember to flip it.

## Features

Features are the design doc's promises, numbered in the order its Goals list them, plus three promises the Architecture and Threat model sections make. The IDs are stable: a feature is never renumbered, and a retired one keeps its number with status `retired`.

| ID | Feature | Design doc source |
|---|---|---|
| F1 | A user stores, rotates and deletes their own secrets through the management API, and never reads a value back | Goals 1 |
| F2 | Per-secret, per-app bindings; delivered names are always `NEBARI_SECRET_<SUFFIX>` | Goals 2 |
| F3 | Enabled secrets arrive at pod start as files, and optionally env vars, in notebooks, jhub-apps apps and Dask clusters | Goals 3, Delivery |
| F4 | Pod identity comes only from a registered creator, enforced by the API server; the service delivers nothing when it cannot confirm that | Goals 4, Pod identity and the admission guard |
| F5 | A user can see per app when delivery last happened and why it last failed | Goals 5 |
| F6 | Values are encrypted per user under a rotatable master key; a lost master key stops delivery | Goals 6, Storage and encryption |
| F7 | Every value read and every denial is audited | Goals 7 |
| F8 | Any pack can consume secrets by meeting the consumer contract, with values only | Goals 8, Consumer contract |
| F9 | Installing the service changes no existing workload | Goals 9 |
| F10 | The management API is reachable only from the landing page, inside the cluster | Threat model, Architecture |
| F11 | Secrets survive restarts and upgrades of the service | Architecture |
| F12 | Sharing consequences are stated where the user shares | Threat model |

## Journeys and checks

Journey IDs are the spec's J1...J22 (`docs/design/user-secrets-spec.md` "Journeys"), unchanged. Each journey belongs to one feature. A journey has one or more **checks**, ID `J<n>.<k>`, each assigned to one tier or marked not covered. Check status is one of:

- `covered`: the named tests exist and run in that tier today;
- `planned`: a named later slice adds the test; counts as not covered;
- `not-covered`: CI cannot do it; the reason says why and what would change that.

| Check | Feature | What it proves | Tier | Status at the CI slice |
|---|---|---|---|---|
| J1.1 | F1 | Add and list a secret with a token from the configured client | 2 (real Keycloak, direct grant) | covered |
| J1.2 | F1 | Same, with a token keycloak-js obtained for the real landing SPA client | 3 | not-covered: needs a browser login against the landing SPA; landing has no `userSecrets` screens yet (nebari-landing#236) |
| J1.3 | F1 | Add and list a secret on real Nebari, with a user created in the Nebari realm | 3 | planned: Slice 8 (covered once the proof run passes) |
| J2.1 | F1 | No response ever contains the value | 1 | covered |
| J3.1 | F2 | Suffix rules and the prefix invariant | 1 | covered |
| J4.1 | F3 | A notebook gets files and env vars; disabled means absent | 3 | not-covered: data-science-pack has no `userSecrets` integration released |
| J5.1 | F3 | Dask scheduler and every worker, both layouts | 3 | not-covered: dask-gateway-pack integration not released |
| J6.1 | F3 | jhub-apps app gets file and env var | 3 | not-covered: data-science-pack integration not released |
| J7.1 | F4 | Cross-user isolation with two real Keycloak users | 2 | covered |
| J7.2 | F4 | Admission policy matrix, one case per rule, per Kubernetes version | 2 (policy matrix) | covered |
| J7.3 | F4 | dask-gateway-pack's DaskCluster policy | - | not-covered: lives in dask-gateway-pack |
| J8.1 | F4 | Wrong app, wrong SA, user tokens at resolve, wrong client at management | 1 | covered |
| J9.1 | F11 | Restart and `helm upgrade` keep secrets; a replica answers throughout | 2 | covered |
| J10.1 | F1 | Rotate reaches pods started afterwards; delete removes it | 3 (test-consumer pod) | planned: Slice 9 (init container) |
| J11.1 | F7 | Audit sink and handler: `secret_read` fields, one `resolve_denied` per denial reason, no value or token substrings | 1 | covered |
| J11.2 | F7 | On kind: `resolve_denied` line for a rejected call, no value or token substrings | 2 | covered |
| J12.1 | F4 | Guard comparison and state table (every confirmed-bad cause) | 1 | covered |
| J12.2 | F4 | On kind: guard fail-closed, `verifiedSince` moves, resolve refused while unverified and for predating pods | 2 | covered |
| J13.1 | F3 | Byte-for-byte values in a test-consumer pod | 3 | planned: Slice 9 |
| J13.2 | F3 | Byte-for-byte in notebook and Dask pods | 3 | not-covered: pack integrations not released |
| J14.1 | F8 | New consumer by values only, on kind | 2 | planned: Slice 10 |
| J14.2 | F8 | New consumer pack installed by Argo CD on real Nebari resolves its secrets | 3 | planned: Slice 10 |
| J15.1 | F9 | Missing ConfigMap and unannotated pods, policy matrix | 2 (policy matrix) | covered |
| J15.2 | F9 | dsp and dask-gateway-pack golden files | - | not-covered: lives in those repos |
| J16.1 | F3 | Dask keeps scaling after the session ends | - | not-covered: dask-gateway-pack integration not released |
| J17.1 | F5 | Status after a failed resolve; unregistered SA; verification failure changes no status | 1 | covered |
| J17.2 | F5 | Soft and strict init behaviour, unit | 1 | planned: Slice 9 |
| J17.3 | F5 | Soft and strict init behaviour on kind | 2 | planned: Slice 9 |
| J18.1 | F12 | Sharing warning in the dsp share dialog | - | not-covered: dsp UI, not this repo |
| J19.1 | F10 | Rendered chart has no `NebariApp` or `HTTPRoute`; NetworkPolicy rules exact | 1 | covered |
| J19.2 | F10 | On kind with Calico: only the landing pod reaches 8444, only workload namespaces reach 8443 | 2 | covered |
| J20.1 | F6 | Sealing per user: a value opens only for its owner and secret name | 1 | covered |
| J20.2 | F6 | On kind: records hold no plaintext; a swapped entry fails resolve with `decrypt_failed` | 2 (e2e and integration) | covered |
| J21.1 | F6 | On kind: KEK rotation rewraps every record; a missing KEK fails closed | 2 (integration) | covered |
| J21.2 | F6 | KEK rotation while pods start, every start gets its secrets | 2 | planned: Slice 11 |
| J22.1 | F8 | Injector and failure modes on kind | 2 | planned: Slice 10 |
| J22.2 | F8 | Injector on real Nebari alongside NIC's other webhooks | 3 | planned: Slice 10 |
| P3.1 | F4, F11 | Platform check: the chart converges through Argo CD on real NIC, with its certificate issued by `nebari-ca-issuer` and trusted through the bundle | 3 | planned: Slice 8 (covered once the proof run passes) |

`P3.1` is a platform check, not a journey, and the catalog labels it so; a green Tier 3 with only `P3.1` and `J1.3` covered is reported as such, never as "journeys pass". "Covered" means the named test functions exist and run in that tier; the catalog names each one. Tier 2 includes the `integration`-tagged tests (`internal/store`, `internal/admin`), which run against the Tier 2 kind cluster in the `tier2-e2e` job; before Slice 7 no CI job ran them. Checks that once read "1 and 2" are split into a Tier 1 and a Tier 2 check, because a check has one tier. Found by the catalog check itself on its first run (2026-11-25): the first draft of this table claimed Tier 2 coverage for J17.1, J20 and J21 that only unit tests or unrun integration tests gave.

## Mocks: what CI cannot reach

| Dependency | In CI | Why |
|---|---|---|
| Keycloak (Tier 2) | Real Keycloak in kind (the version NIC deploys, `KEYCLOAK_IMAGE`), realm `nebari` imported from a committed fixture: users `alice` and `bob`, client `user-secrets-e2e` (public, direct grants, set as the service's `clientID`, the same `azp` code path as the landing client) and `other-client`. Served over HTTPS with a certificate from NIC's CA issuer, trusted through the bundle. Test passwords are fixture values, not secrets | Replaces the static JWKS stand-in, so J1 and J7 exercise the real token path (issuer, `azp`, JWKS fetched from Keycloak). Signing-key rotation is not exercised on kind; `TestVerifyAfterKeyRotation` (Tier 1) covers it |
| Keycloak (Tier 3) | The sandbox's own Keycloak; test users created through the admin API with the `keycloak-realm-admin-password` output | Action output, not a repo secret |
| Landing SPA browser login | Not mocked; J1.2 stays not-covered | A mock would prove only the mock |
| Container registry | None. The image is built on the runner and loaded with `kind load` into `us-e2e` (Tier 2) or `kind-<cluster-name>` (Tier 3) | No push, so no `packages: write` token |
| NIC templates (Tier 2) | Vendored copies at `de81b11`, drift-checked by `make nic-fixtures-check` | Already in place |
| Cloud KMS, external secret consumers | Not used by the first release | Out of scope |

No required check reads `secrets.*`. The catalog check enforces this by failing if any workflow file under `.github/workflows/` references `secrets.` other than `secrets.GITHUB_TOKEN`.

## Pins

One file, `ci/pins.env`, `KEY=value` lines with a comment per pin giving its source. It is the only place each version is written.

| Key | Today |
|---|---|
| `GOLANGCI_LINT_VERSION` | v2.4.0, installed with `install-mode: goinstall` so it is built with go.mod's toolchain (Slice 6) |
| `HELM_VERSION` | v4.3.2 |
| `KIND_VERSION` | v0.33.0 |
| `KIND_NODE_IMAGE` | kindest/node:v1.34.3 |
| `POLICY_K8S_VERSIONS` | v1.30.13 v1.32.11 v1.34.3 |
| `CALICO_VERSION` | v3.32.3 |
| `GATEWAY_API_VERSION` | v1.6.1 |
| `CERT_MANAGER_VERSION` | v1.17.2 |
| `TRUST_MANAGER_VERSION` | v0.22.1 |
| `NIC_FIXTURES_REF` | de81b1131fbe26fca289f841347d84af727f692f |
| `NIC_REQUIRED_COMMIT` | de81b1131fbe26fca289f841347d84af727f692f (#787) |
| `KEYCLOAK_IMAGE` | quay.io/keycloak/keycloak:<tag>@sha256:<digest>, matching the Keycloak NIC deploys |
| `GO_BUILDER_IMAGE` | golang:1.26@sha256:<digest> (Task 28's carry-forward lands here) |
| `PAUSE_IMAGE` | registry.k8s.io/pause:3.10@sha256:ee6521f2... |
| `CURL_IMAGE` | curl image by digest, for in-cluster HTTP from `setup.sh` and the e2e helpers (added in Task 24) |
| `SANDBOX_ACTION_REF` | v3.0.0 (documentation only, see below) |

Readers: `test/e2e/setup.sh`, `test/policy/run-all.sh`, `test/policy/run.sh` and `hack/kind.sh` load it through `ci/load-pins.sh`, which exports each line as literal text (bash cannot `source` an unquoted value with spaces, such as `POLICY_K8S_VERSIONS`, and quoting would leak quotes into Make and `$GITHUB_ENV`); the Makefile `include`s it; workflows load it into `$GITHUB_ENV` in their first step; the Dockerfile takes `GO_BUILDER_IMAGE` as a build arg from the Makefile. Two pins cannot be read from a file: the Go constant `guard.PauseImage` and the `uses:` refs in workflows (GitHub does not template `uses:`). For these, Tier 1's catalog test asserts that the constant equals `PAUSE_IMAGE`, that the Dockerfile's `ARG GO_BUILDER_IMAGE` default equals the pin, and that every `nebari-dev/action-nebari-sandbox` ref in the workflows equals `SANDBOX_ACTION_REF`.

## Job summaries

Every tier's last step (`if: always()`) writes to `$GITHUB_STEP_SUMMARY`:

1. the commit under test (`github.sha`, and for `merge_group` the queue's head and base SHAs);
2. every pin from `ci/pins.env`, as a table;
3. the tier's check results from the catalog: covered checks run in this tier with pass or fail, and the not-covered and planned checks with their reasons.

Tier 3 adds the resolved NIC release tag and its commit, whether it contains `NIC_REQUIRED_COMMIT` (and so whether this run is `BLOCKING` or `NON-BLOCKING`), and the sandbox's `timing-report` and `resource-summary`.

The user's request ended mid-sentence at "Write the resolved NIC version, the commit under test, and every"; this design reads it as "every pinned dependency version".

## Workflows and triggers

| Workflow / job | `pull_request` | `merge_group` | tag `v*` | `workflow_dispatch` | Required check name |
|---|---|---|---|---|---|
| `ci.yml` / `tier1` | yes | yes | yes | yes | `tier1` |
| `ci.yml` / `tier2-e2e` | yes | yes | yes | yes | `tier2-e2e` |
| `ci.yml` / `tier2-policy` (matrix) | yes | yes | yes | yes | `tier2-policy (v1.30.13)`, `(v1.32.11)`, `(v1.34.3)` |
| `journeys.yml` / `tier3` | skipped (job `if:`), counts as passing | yes | yes | yes | `tier3` |

`tier3` lives in its own workflow file but is triggered on `pull_request` too, so the required check reports (as skipped) on every PR instead of waiting forever. `workflow_dispatch` takes no NIC version input: it always resolves the latest release, so a dispatch run cannot test NIC `main` either.

Tier 3 steps:

1. Load pins; resolve the latest NIC release (`gh api repos/nebari-dev/nebari-infrastructure-core/releases/latest`) and whether it contains `NIC_REQUIRED_COMMIT` (`compare/<commit>...<tag>`, status `ahead` or `identical`); set `BLOCKING`.
2. `action-nebari-sandbox` with `nic-version: <resolved tag>`, `in-cluster-dns: true`, `timing-report: true`, `resource-summary: true`.
3. Build the image from the checkout and `kind load` it into `kind-<cluster-name>`.
4. `add-software-pack` for `user-secrets` with `chart-source: chart`, and an Application manifest from `test/journeys/gitops/` that sets the image tag to the build and the chart values a Nebari install would set.
5. Platform convergence check: every Argo CD Application `Synced` and `Healthy`, bounded wait.
6. `go test -tags journeys ./test/journeys/...` against the sandbox kubeconfig, with outputs passed as env.
7. Summary. If `BLOCKING` is false: in `merge_group`, steps 2-6 are skipped and the job passes; on tag and dispatch, failures from steps 2-6 are summary warnings and the job exits 0. If true, they fail the job.

**One-off proof run (user decision).** Before the CI slice's checkpoint, Tier 3 is run once by hand with the sandbox's `nic-version` set to `de81b1131fbe26fca289f841347d84af727f692f` (the #787 merge), on a scratch branch whose workflow is edited for that run only and never merged. Its passing output is the evidence that `P3.1` and `J1.3` are `covered`. No trigger in the merged workflows can select a NIC commit; they only resolve the latest release.

## Report before turning anything on

Before anyone changes the ruleset, the CI slice's checkpoint delivers a written report with:

- **Merge queue:** available (public repo); the proposed ruleset (required checks `tier1`, `tier2-e2e`, the three `tier2-policy` checks, `tier3`; merge method squash; build concurrency and batch size from the measurements below).
- **Stacking:** how the chained PRs interact with the queue (above), measured on one real retarget.
- **Tier 3 time and size:** `timing-report` and `resource-summary` from the one-off proof run on the #787 commit (full run, journeys included) and from one `workflow_dispatch` run on the latest release (platform bring-up only, stopping at our install); the report labels which is which.
- **Queue throughput:** with Tier 3 at T minutes and Tier 2 at its measured time, the queue merges at most one group per max(T, Tier 2) minutes per concurrent build; the report gives the batch size that keeps a typical day's merges under an hour, and what a failing batch costs (bisection reruns).
- **Runner fit:** peak memory and disk from `resource-summary` against the standard runner's 16 GB and 14 GB; if it does not fit, the report says so and Tier 3 stays dispatch-only until a larger runner is decided.

## Coverage honesty

- `test/journeys/catalog.yaml` is the single source for features, journeys, checks, tiers, statuses, test names and reasons. `docs/ci/coverage.md` is generated from it by `make coverage-doc` and checked in; Tier 1 fails if it is stale.
- The catalog test (Tier 1) fails when: a `covered` check names a test function that does not exist under the build tag its tier uses; a `planned` or `not-covered` check has no reason; a journey in the spec's table has no catalog entry; a feature has no journey; or a workflow reads a secret other than `GITHUB_TOKEN`.
- Each slice that adds a journey's test flips its check to `covered` in the same PR.
- Narrated evidence in the plan's Journeys table is not CI coverage, and the catalog never cites it.

## Program Design
**Scale:** full

### Existing patterns
Promoted wording: **Bash cluster harnesses behind Make targets:** cluster test harnesses are bash under `test/<area>/` driven by Make targets, and Go tests behind a build tag (`e2e`, `journeys`) read the harness's kubeconfig. **External versions pinned once:** every external version lives in `ci/pins.env` with a comment naming its source; anything that cannot read the file is cross-checked against it by a Tier 1 test. **Vendored upstream files with SOURCE and drift check:** a vendored copy carries a `SOURCE` file naming repo, commit and files, and a Make target diffs it against upstream.

| Pattern | Tag | Source | Promote? |
|---|---|---|---|
| Layout is `cmd/<binary>` plus `internal/<pkg>` | [documented: AGENTS.md, docs/architecture/patterns.md] | AGENTS.md | n/a |
| Go tests are table-driven; constructors take interfaces and return concrete types | [documented: AGENTS.md] | AGENTS.md | n/a |
| Contracts change with their entry in `docs/architecture/contracts.md` in the same PR | [documented: AGENTS.md] | AGENTS.md | n/a |
| Bash cluster harnesses behind Make targets | [inferred] | Makefile, test/e2e/setup.sh, test/e2e/helpers_test.go | yes |
| External versions pinned once | [inferred] | test/e2e/setup.sh:12-25, test/policy/run-all.sh:7, hack/kind.sh:6 | yes |
| Vendored upstream files with SOURCE and drift check | [inferred] | test/e2e/fixtures/nic/SOURCE, Makefile `nic-fixtures-check` | yes |

### Component contracts
| Contract | Status | Owner | Consumers | Verified by | Promote? | Notes |
|---|---|---|---|---|---|---|
| Pins file `ci/pins.env` | new | nebari-user-secrets | Makefile, test/e2e/setup.sh, test/policy/run-all.sh, hack/kind.sh, .github/workflows/*.yml, test/journeys catalog test | n/a (new) | n/a | `KEY=value`, unquoted, loaded as literal text (no shell evaluation), no `$(`, backtick or `${` |
| Journey catalog `test/journeys/catalog.yaml` | new | nebari-user-secrets | catalog test, summary tool, docs/ci/coverage.md | n/a (new) | n/a | schema in Data models |
| Required check names | new | nebari-user-secrets | `main` ruleset (set by the user) | n/a (new) | n/a | `tier1`; `tier2-e2e`; `tier2-policy (<version>)`; `tier3`. Renaming one breaks the ruleset silently |
| Make targets for the kind tiers | changed-compatible | nebari-user-secrets | .github/workflows/ci.yml, docs/superpowers/plans/2026-11-20-user-secrets-service.md (validation commands), developers | `grep -rn 'e2e-up\|e2e-test\|policy-test' .github Makefile docs` | n/a | `make e2e-up`; `make e2e-test`; `make policy-test`. Same targets; versions now come from pins; `policy-test` accepts `K8S_VERSION` to run one version |
| Static JWKS server in `e2e-keycloak` | changed-breaking | nebari-user-secrets | test/e2e/setup.sh (`gen_key`, `install_jwks`), test/e2e/fixtures/jwks.yaml, test/e2e/fixtures/values.yaml (issuer/JWKS URL), test/e2e/helpers_test.go (token minting), test/e2e/e2e_test.go:384 (`jwks.e2e-keycloak.svc:443` in the network test) | `grep -rn 'jwks\|e2e-keycloak\|KID' test/e2e` | n/a | replaced by real Keycloak; both consumers change in the CI slice |
| Consumed: action-nebari-sandbox v3.0.0 inputs and outputs | unchanged | nebari-dev/action-nebari-sandbox | .github/workflows/journeys.yml | `gh api repos/nebari-dev/action-nebari-sandbox/contents/action.yml?ref=v3.0.0` | no | external; pinned by ref |
| Consumed: NIC root App-of-Apps reads `apps/*.yaml` in the GitOps dir | unchanged (implicit) | nebari-infrastructure-core | add-software-pack, test/journeys/gitops | `gh api repos/nebari-dev/action-nebari-sandbox/contents/add-software-pack/action.yml?ref=v3.0.0` | no | add-software-pack wraps it |
| Consumed: NIC cluster CA and trust bundle | unchanged | nebari-infrastructure-core | chart, Tier 2 fixtures, Tier 3 | docs/architecture/contracts.md "Consumed: NIC cluster CA and trust bundle" | n/a | Tier 3 is the first test against a real NIC |

**Pins file.** Promises one line per pin, `KEY=value`, values without spaces except `POLICY_K8S_VERSIONS` (space-separated), comments with `#`. Bash readers load it with `ci/load-pins.sh` (literal export, never `source`), Make `include`s it, and workflows append it with `grep -v '^#' >> $GITHUB_ENV`. A missing key is a reader error, never a silent default.

**Journey catalog.** Promises the schema below. The catalog test is its validator; a malformed catalog fails Tier 1.

**Required check names.** The ruleset matches checks by name, so a renamed job makes a required check wait forever. The names are written in `contracts.md`, and a change to them is a contract change.

**Keycloak replacing the JWKS stand-in.** Token minting in the e2e helpers moves from signing with a local key to a direct-grant request against the test client. The network test's control target moves to Keycloak's in-cluster address.

### Data models and types
```yaml
# test/journeys/catalog.yaml
features:
  - id: F1                      # stable, never reused
    title: "..."
    source: "docs/design/user-secrets.md#goals"
    status: active              # active | retired
journeys:
  - id: J1                      # = spec Journeys row number
    feature: F1
    checks:
      - id: J1.1
        tier: 2                 # 1 | 2 | 3
        status: covered         # covered | planned | not-covered
        tests: [TestManagementWithKeycloak]   # required when covered
        reason: ""              # required unless covered
        until: ""               # planned: slice; not-covered: what would change it
platform_checks:
  - id: P3.1
    tier: 3
    status: covered
    tests: [TestChartConvergesOnNebari]
```

```go
// test/journeys/catalog (package catalog)
type Catalog struct {
	Features       []Feature `json:"features"`
	Journeys       []Journey `json:"journeys"`
	PlatformChecks []Check   `json:"platform_checks"`
}
type Feature struct{ ID, Title, Source, Status string }
type Journey struct {
	ID, Feature string
	Checks      []Check
}
type Check struct {
	ID, Status, Reason, Until string
	Tier                      int
	Tests                     []string
}
```

Build tag per tier: 1 = none, 2 = `e2e` or `integration` (and the policy matrix's `run.sh` section headings for J7.2 and J15.1), 3 = `journeys`.

### Method signatures
```go
// package catalog
func Load(r io.Reader) (*Catalog, error)
func (c *Catalog) Validate(index TestIndex, specJourneys []string) []error
func SpecJourneyIDs(spec io.Reader) ([]string, error)   // reads the spec's Journeys table
func RenderCoverage(c *Catalog, w io.Writer) error       // docs/ci/coverage.md
func RenderSummary(c *Catalog, pins Pins, results Results, w io.Writer) error

type TestIndex interface{ Has(tier int, name string) bool }
func NewSourceIndex(root string) (*SourceIndex, error)   // go/parser over *_test.go, by build tag; run.sh case names for tier 2 policy

type Pins map[string]string
func LoadPins(r io.Reader) (Pins, error)
type Results map[string]string                           // check id -> pass | fail | skip, from go test -json
```

### Program layout
```text
~ .github/workflows/ci.yml            tier1, tier2-e2e, tier2-policy; adds merge_group, tags, dispatch
+ .github/workflows/journeys.yml      tier3
+ ci/pins.env                         all pins
~ Makefile                            sources pins; coverage-doc, journeys-test; policy-test K8S_VERSION
~ Dockerfile                          ARG GO_BUILDER_IMAGE
~ hack/kind.sh                        reads pins
~ test/e2e/setup.sh                   reads pins; Keycloak replaces JWKS server
+ test/e2e/fixtures/keycloak/         realm import, Deployment, Service, Certificate
~ test/e2e/helpers_test.go            tokens from Keycloak direct grant
~ test/e2e/e2e_test.go                network test control target
~ test/policy/run-all.sh              reads pins; one version via K8S_VERSION
+ test/journeys/catalog.yaml
+ test/journeys/catalog/              package catalog + catalog_test.go (Tier 1)
+ test/journeys/cmd/summary/main.go   writes $GITHUB_STEP_SUMMARY (follows cmd/<binary> under the test tree)
+ test/journeys/gitops/user-secrets.yaml   Argo CD Application for add-software-pack
+ test/journeys/nebari_test.go        //go:build journeys; P3.1, J1.3, later J10.1, J13.1, J14.2, J22.2
+ docs/ci/coverage.md                 generated
~ docs/architecture/contracts.md      pins file, catalog, check names
```

### Call stacks
```text
Production (Tier 1, every event):
  ci.yml tier1
    → load ci/pins.env into $GITHUB_ENV
    → golangci-lint (GOLANGCI_LINT_VERSION) run
    → make test
      → go test ./... -race (includes test/journeys/catalog)
        → catalog.Load, SourceIndex, SpecJourneyIDs → Validate
        → coverage.md freshness, pin cross-checks, workflow secret scan
    → summary (go run ./test/journeys/cmd/summary --tier 1)

Production (Tier 2):
  ci.yml tier2-e2e
    → make e2e-up (image-load; setup.sh: kind, Calico, cert-manager, trust-manager, NIC CA, Keycloak, chart)
    → make e2e-test (go test -tags e2e -json)
    → summary --tier 2 --results <json>
  ci.yml tier2-policy (matrix over POLICY_K8S_VERSIONS)
    → make policy-test K8S_VERSION=<v>

Production (Tier 3, merge_group / tag / dispatch):
  journeys.yml tier3
    → resolve latest NIC release; compare with NIC_REQUIRED_COMMIT → BLOCKING
    → action-nebari-sandbox (kind, NIC local provider)
    → docker build; kind load into kind-<cluster-name>
    → add-software-pack (chart from checkout → GitOps dir → root App-of-Apps → Argo CD)
    → convergence check (all Applications Synced/Healthy)
    → go test -tags journeys ./test/journeys/... -json
      → Keycloak admin API (realm admin password output) creates test users
      → management API via port-forward; resolve from test pods
    → summary --tier 3 (NIC tag, BLOCKING, timing-report, resource-summary)
```

### Component trees and DI
`catalog.Validate` takes a `TestIndex` interface; production passes `NewSourceIndex(repoRoot)`, tests pass a fake index. `RenderSummary` takes `Pins` and `Results` values, built by `cmd/summary` from `ci/pins.env` and `go test -json` output. The journey tests in `test/journeys` take their endpoints and credentials from env set by the workflow, the same way `test/e2e` reads `.kube/e2e`.

### Test approach and seams
| Boundary | Seam | Real/fake | Level | Proves |
|---|---|---|---|---|
| Catalog vs test sources | `TestIndex` | fake in table tests; real `SourceIndex` over the repo in one test | unit (Tier 1) | covered checks name real tests; gaps carry reasons |
| Spec journeys vs catalog | `SpecJourneyIDs` | real spec file | unit (Tier 1) | no journey is missing from the catalog |
| Pins vs Go constant, Dockerfile, workflow refs | `LoadPins` | real files | unit (Tier 1) | the pins file is the single source |
| Summary rendering | `RenderSummary` with fixed Pins and Results | fake inputs | unit (Tier 1) | summary lists commit, every pin, NIC tag, statuses |
| Service vs Keycloak (Tier 2) | OIDC issuer URL | real Keycloak | e2e on kind | real token path for J1.1, J7.1 |
| Service vs real Nebari (Tier 3) | sandbox kubeconfig and outputs | real NIC release | journeys | P3.1, J1.3 and later Tier 3 checks |
| NIC containment gate | GitHub compare API | real; exercised by one `workflow_dispatch` before and after a qualifying release | manual, recorded in the report | the gate flips by itself |

## Journeys

The definition of done for the CI work itself (IDs C1...C8, separate from the service's J1...J22). Evidence is filled in at the CI slice's checkpoint.

| # | Item | Proof | Check method | Evidence |
|---|------|-------|--------------|----------|
| C1 | A PR from a fork gets every required check to a result without any repo secret | A fork PR shows `tier1`, `tier2-e2e` and the three `tier2-policy` checks passing and `tier3` skipped; the catalog test fails on a workflow that reads `secrets.` other than `GITHUB_TOKEN` | automated: catalog test table case; narrated: checks list of a real fork PR | |
| C2 | A reviewer can tell from any job summary what was tested against what | Each tier's summary shows the commit SHA, every pin from `ci/pins.env`, and per check pass/fail or its not-covered reason; Tier 3 adds the NIC tag, `BLOCKING`/`NON-BLOCKING`, timing and resource reports | automated: `RenderSummary` table test; narrated: screenshots of real summaries from all three tiers | |
| C3 | A gap cannot pass as covered | Tier 1 fails on each of: a `covered` check naming a missing test, a journey removed from the catalog, a missing reason, a stale `docs/ci/coverage.md`, a pin out of sync with the Go constant, the Dockerfile or the sandbox ref | automated: catalog table tests, one case per failure | |
| C4 | Changing a pin changes it everywhere | Editing `CALICO_VERSION` in `ci/pins.env` alone changes what `make e2e-up` installs; no pinned version string appears outside `ci/pins.env` except the three cross-checked ones | automated: catalog test grep; narrated: `setup.sh` log line after the edit | |
| C5 | Tier 2 runs the commit's own image against real Keycloak and the policy matrix | `tier2-e2e` obtains tokens from Keycloak (no JWKS stand-in left in `test/e2e`); the three `tier2-policy` jobs each report their Kubernetes version | narrated: CI run links and log excerpts | |
| C6 | Tier 3 installs our chart through Argo CD on NIC and runs journeys | The one-off run on `de81b11` passes `P3.1` and `J1.3` with the Application `Synced`/`Healthy` and the certificate issued by `nebari-ca-issuer`; a dispatch run on the latest release reports `NON-BLOCKING` and exits 0 | narrated: both run links and summaries | |
| C7 | Tier 3 starts blocking by itself once NIC ships #787 | The gate says non-blocking for v0.18.0 and blocking for a tag containing `de81b11`; in `merge_group` while non-blocking, `tier3` passes with the skip line. The `merge_group` half is verified after the user turns the queue on | automated: gate table test with a fake compare API; narrated: a `merge_group` run after turn-on | |
| C8 | The user has the turn-on report before anything is turned on | Report covers merge queue and proposed ruleset, stacking behaviour, measured Tier 3 time and size, queue throughput and batch size, runner fit; the `main` ruleset is unchanged | narrated: report in the PR; `gh api repos/nebari-dev/nebari-user-secrets/rulesets` output before and after | |

## Calls made after the builder check

These are my calls, not the user's; each is open to correction at review.

- **Which PRs the new checks guard.** The CI slice sits after Slice 6, so PRs #1 to #7 carry the old `ci.yml` (jobs `ci` and `e2e`) and never report `tier1` and the rest. The ruleset requiring the new names is therefore turned on only after the CI slice has merged to `main`; the report says so. Until then the old jobs keep running on the earlier PRs. No backport into earlier branches.
- **Lint.** The lint fix lands on the Slice 6 branch: `ci.yml` keeps golangci-lint v2.4.0 but sets `install-mode: goinstall`, so the action builds it with go.mod's Go 1.26 instead of downloading the Go 1.25 binary that refuses this module. No linter version change, so no new findings; PRs #2 to #6 stay red until their slices merge in order.
- **What non-blocking covers.** While the latest NIC release lacks #787, every step after the gate (platform bring-up, image build and load, install, convergence, journey tests) reports failures as warnings and the job exits 0. The gate step itself retries its two GitHub API calls three times and fails the job if it still cannot decide, because guessing either way is wrong: guessing blocking stalls the queue, guessing non-blocking hides real failures once #787 ships.
- **Slice numbering.** The CI work is two slices, because one PR would be well over the plan's 400-line guideline: Slice 7 (Tiers 1 and 2, pins, catalog, Keycloak) and Slice 8 (Tier 3, gate, proof run, turn-on report). Later slices renumber: init container 9, injector 10, release 11. The catalog's `until:` values and the table above use these numbers. The `GO_BUILDER_IMAGE` pin takes over Task 28's builder pin.
- **Runner does not fit.** No switch is built now. If the report shows Tier 3 does not fit a standard runner, the user edits `journeys.yml` to drop `merge_group` and removes `tier3` from the ruleset.

## What is left to the builder

- The Keycloak version to pin (match what the latest NIC release deploys) and the realm fixture's contents beyond two users and two clients.
- The bounded waits (convergence check, add-software-pack `wait-timeout`), set from the measured runs.
- How `go test -json` results map to check IDs: by test function name from the catalog.
