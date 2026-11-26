# nebari-user-secrets Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Implementers never commit, push or open PRs; the controller does that at each slice's Checkpoint.

**Goal:** Build the nebari-user-secrets service, init binary, injector, chart and cluster bundle, and prove them end to end on kind with a test consumer.

**Architecture:** One Go module with two binaries (`user-secrets`: management API, resolve API, injector webhook, guard, admin commands; `user-secrets-init`: fetch and env wrapper), `internal/` packages behind interfaces, a Helm chart for the namespaced objects and `cluster/` for the cluster-scoped ones. Delivered as eleven stacked slices, each a PR against the previous slice's branch, starting from `docs/user-secrets-design` (nebari-user-secrets#1).

**Tech Stack:** Go 1.26; `k8s.io/{api,apimachinery,client-go}` v0.35.0; `sigs.k8s.io/controller-runtime` v0.23.1 (admission webhook helpers only); `github.com/coreos/go-oidc/v3` v3.21.0; `k8s.io/pod-security-admission` v0.35.0 (tests); `go.opentelemetry.io/otel` v1.45.0; standard library `crypto/aes` and `crypto/cipher`; Helm 3 chart; kind for integration and e2e.

**Spec:** `docs/design/user-secrets-spec.md` (detailed spec, with Program Design) and `docs/design/user-secrets.md` (design), both in nebari-user-secrets. Slices 7 and 8 implement `docs/superpowers/specs/2026-11-24-ci-tiers-design.md` (CI tiers, with its own Program Design and CI Journeys C1-C8).

**Scope:** nebari-user-secrets only (decided 2026-11-20). data-science-pack, dask-gateway-pack and nebari-landing get their own plans against the working service. Journeys 4, 5, 6 (dsp half), 10, 16 and 18 are proved there, not here; the five contracts those repos own are not touched by this plan (see "Lint result" at the end).

## Journeys

| # | Item | Proof | Check method | Evidence |
|---|------|-------|--------------|----------|
| 1 | A user can add a secret through the management API, as the landing page does | With an access token for the configured client, `PUT /api/v1/secrets/vendor_key` returns `201`, and `GET /api/v1/secrets` lists it with its bindings; on a dev cluster the same works with a token keycloak-js obtained for the real landing SPA client. The landing screens are not part of this item; they are tracked in nebari-landing#236 | automated: `internal/httpapi` tests, and e2e on kind with a test Keycloak client that allows direct grants, set as the service's `clientID` (the same `azp` code path); narrated: dev cluster `curl` transcript with a real landing token | |
| 2 | After saving, the API never returns the value again | Every management API response for that secret (list, update, delete, errors) contains no substring of the value or its base64 | automated: `internal/httpapi` test `TestValueNeverReturned` | |
| 3 | A user can enable a secret per app and choose its suffix; the name is always `NEBARI_SECRET_<SUFFIX>` | Enabling `vendor_key` for `notebook` with suffix `VENDOR_API_KEY` shows `NEBARI_SECRET_VENDOR_API_KEY`; suffixes `ld_preload`, `A=B`, `../x` and empty are rejected; no stored record can make resolve return an unprefixed name | automated: `internal/service` tests `TestBindings`, `TestEnvNameAlwaysPrefixed` | |
| 4 | A notebook started after enabling has the secret as a file and, with `exportEnv`, as an env var; disabled means absent | File and `os.environ["NEBARI_SECRET_VENDOR_API_KEY"]` equal the stored value; after disabling and restarting both are absent and `.status` reads `ok 0` | narrated: dev cluster, terminal transcripts from two server starts | |
| 5 | A Dask cluster has the secret on the scheduler and every worker, including adaptively added ones, in either namespace layout | `client.run` and `client.run_on_scheduler` return the value after `cluster.adapt(minimum=1, maximum=4)` scales up; repeated with dask-gateway-pack in a separate namespace | narrated: notebook transcript, both layouts | |
| 6 | A jhub-apps app runs with the secrets enabled for jhub-apps, as a file and as an env var | A deployed Panel/Streamlit app shows the file present and `os.environ.get("NEBARI_SECRET_VENDOR_API_KEY") is not None` as `True`; with the binding removed and the app restarted, both are absent | automated: dsp unit test that a jhub-apps spawner's final manifest carries the export annotation, and `internal/inject` test that the annotation puts the wrapper ahead of the existing `args`; narrated: dev cluster screenshots | |
| 7 | Another user, or anyone who is not a registered creator for that namespace and app, cannot get A's secrets | B's pods resolve none of A's; with the bundle installed the API server rejects: a labelled pod from a non-creator with A's `sub`; a creator's labelled pod outside its namespace or app (controller annotating `app=notebook`); an annotated pod without the label; adding the label or changing an annotation later, including via `pods/status`; a `pods/binding` carrying user-secrets metadata; an image patch on A's pod; an ephemeral container on A's pod; a TokenRequest for audience `user-secrets` by anyone but a kubelet; a real pod create by the service's ServiceAccount. dask-gateway-pack's policy rejects an annotated DaskCluster from a non-gateway principal. An unlabelled pod gets 403 at resolve | automated: e2e `test_cross_user_isolation` (two real Keycloak users) and integration `test/policy/run.sh` (the spike matrix, one case per rule) on kind | |
| 8 | A pod gets only the secrets enabled for its own app, and no user token can resolve | (a) a `dask`-annotated pod running as the notebook SA gets 403; (b) a `dask` pod with only notebook bindings gets an empty list; (c) any Keycloak token, including one with `user-secrets` in `aud`, gets 401 at resolve; (d) a token for the same user issued to any client other than the landing SPA gets `401` at the management API | automated: `internal/podidentity` (a), `TestResolveFiltersByApp` (b), `internal/httpapi` (c), `internal/auth` and `internal/httpapi` (d) | |
| 9 | Secrets survive a restart or upgrade of the service | Store a secret, `kubectl rollout restart` and `helm upgrade` the service, resolve still returns it; during the rollout at least one replica answers | automated: integration `test_durability_across_restart` on kind | |
| 10 | Rotate means pods started afterwards get the new value; delete means they get nothing | After rotate, a new notebook sees the new value; after delete, the file and env var are absent | narrated: dev cluster transcript of three server starts | |
| 11 | Every value read produces an audit record an admin can find, and denials are logged | `kubectl logs` shows a `secret_read` line with owner_sub, reader_sub, secret, app, pod, pod_uid, sa, guard after a spawn, and a `resolve_denied` line with a reason after a rejected call; no value or token substrings appear | automated: `internal/audit` test; narrated: `kubectl logs` excerpt | |
| 12 | Without a verified guard nothing is delivered; the override restores delivery visibly | Each of: a binding removed, a binding at `[Warn, Audit]`, binding B narrowed or its `paramRef` changed, a `paramRef` added to binding A, a policy edited, the ConfigMap drifted, a probe admitted, the canary denied → a new notebook has no secret files, `.status` reads `error guard_not_verified`, a `guard_state confirmed_bad` line is logged; API unreachable or a probe denied by Pod Security → delivery continues for up to 2 minutes, then stops; `guard.mode: unverified` → delivery with `"guard":"overridden"` and a warning; a pod created while a binding was at `[Warn]` is refused with `pod_predates_guard` after the switch to `[Deny]`, and a pod created afterwards resolves | automated: unit `internal/guard` table and integration `test_guard_fail_closed` on kind; narrated transcript | |
| 13 | Values reach notebook and Dask pods byte for byte | A secret with suffix `ESCAPE_TEST` uploaded as a file containing `{"k":"a$$b$(HOME){username}"}`, a newline and a non-UTF-8 byte is enabled for `notebook` and `dask`; the file in a new notebook and in every worker and the scheduler is byte-identical (`sha256sum`); the env var matches for the UTF-8 part | automated: `internal/initfiles` and storage round-trip tests; narrated: dev cluster transcript comparing hashes | |
| 14 | A new pack can consume secrets by meeting the consumer contract, with no change to the service or the cluster bundle beyond values | Adding app `test-consumer` (workload SA, creator with its namespace) in values lets a pod built per the contract by that creator resolve exactly the user's `test-consumer` secrets; `git diff` of the service and `cluster/` is empty | automated: e2e `test_new_consumer_by_values_only` on kind | |
| 15 | Existing installs are unaffected until a pack opts in, and a missing ConfigMap never breaks the cluster or the guard | With `userSecrets.enabled: false`, dsp's and dask-gateway-pack's rendered charts and created pod manifests equal the committed golden files from the previous release; with nebari-user-secrets and the bundle installed, unannotated pods from any ServiceAccount still succeed; with the `user-secrets-creators` ConfigMap deleted and both bindings at `[Deny]`, unannotated pods (including in `kube-system`), `pods/status` updates and other-audience token requests still succeed, labelled pods are denied, and policy A's rules still hold | automated: dsp and dask-gateway-pack golden tests, integration `test/policy/run.sh` (missing-ConfigMap section) | |
| 16 | An existing Dask cluster keeps scaling with secrets after the user's Keycloak session ends; a new cluster then needs a fresh login, as today | With the user's sessions revoked, `adapt()` on a running cluster adds workers that have the secret; `new_cluster()` fails with the gateway's authentication error and succeeds after logging in again | narrated: dev cluster notebook transcript | |
| 17 | A user can see why their secrets did not arrive | With the service's NetworkPolicy blocking a namespace (soft mode), a new notebook starts, `.status` reads `error unreachable`, the wrapper prints a warning; with an unregistered SA, `GET /api/v1/secrets` reports the app's last failure as `not_registered`; a pod that fails verification (for example a UID mismatch) changes no user's status; in `strict` mode the pod does not start | automated: `internal/initfiles` tests for soft and strict; narrated: dev cluster transcript of the API response and pod status | |
| 18 | Sharing consequences are stated where the user decides to share | dsp's share dialog help shows the sharing warning text. The same warning next to Dask bindings is landing page text and is checked under nebari-landing#236, not here | narrated: dsp share dialog screenshot | |
| 19 | The management API is reachable only inside the cluster, and only from the landing page | The rendered chart has no `NebariApp` or `HTTPRoute`; on kind, a pod in a workload namespace cannot connect to `:8444`, a test pod in the landing namespace carrying the configured frontend labels can, and that test pod cannot connect to `:8443`. No landing install is needed | automated: chart `helm template` test and an integration test on kind with a CNI that enforces NetworkPolicy | |
| 20 | Stored values are encrypted with a key per user, and a copy of the records alone reveals nothing | After storing `vendor_key`, `kubectl get secret us-<sub> -o json` contains neither the value nor its base64; copying user A's sealed entry or wrapped data key into user B's record makes resolve for B fail with `decrypt_failed` and return nothing of A's | automated: `internal/crypto` tests and integration `test_records_hold_no_plaintext` on kind; narrated: `kubectl get secret` excerpt | |
| 21 | An admin can rotate the master key without interrupting delivery, and a lost master key stops delivery instead of silently starting over | `user-secrets admin rotate-kek` while notebooks start: every start during and after the rotation gets its secrets; afterwards every record names the new id and `retire-kek <old>` succeeds; with `user-secrets-kek` deleted and records present, the service generates no key, resolve and management return `503 kek_unavailable`, and a `key_event kek_unavailable` line is logged | automated: integration `test_kek_rotation` and `test_kek_missing_fails_closed` on kind | |
| 22 | A pack sets only the label and annotations, and the injector does the rest; when the injector is down the pack's failure mode decides | A pod with only SA, label and annotations from a registered creator starts with the init container, files and `.status ok`; an unlabelled pod in the same namespace is unchanged; with the service scaled to zero, a `soft` pod starts with no `/var/run/nebari/secrets` and a `strict` pod is refused at creation, and unlabelled pods are unaffected | automated: `internal/inject` table and integration `test_injector_failure_modes` on kind | |

## CI Journeys (from docs/superpowers/specs/2026-11-24-ci-tiers-design.md) and checks

Journey IDs are the spec's J1...J22 (`docs/design/user-secrets-spec.md` "Journeys"), unchanged. Each journey belongs to one feature. A journey has one or more **checks**, ID `J<n>.<k>`, each assigned to one tier or marked not covered. Check status is one of:

- `covered`: the named tests exist and run in that tier today;
- `planned`: a named later slice adds the test; counts as not covered;
- `not-covered`: CI cannot do it; the reason says why and what would change that.

| Check | Feature | What it proves | Tier | Status at the CI slice |
|---|---|---|---|---|
| J1.1 | F1 | Add and list a secret with a token from the configured client | 2 (real Keycloak, direct grant) | covered |
| J1.2 | F1 | Same, with a token keycloak-js obtained for the real landing SPA client | 3 | not-covered: needs a browser login against the landing SPA; landing has no `userSecrets` screens yet (nebari-landing#236) |
| J1.3 | F1 | Add and list a secret on real Nebari, with a user created in the Nebari realm | 3 | covered |
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
| J11.1 | F7 | `secret_read` and `resolve_denied` lines, no value substrings | 1 and 2 | covered |
| J12.1 | F4 | Guard fail-closed table and on kind | 1 and 2 | covered |
| J13.1 | F3 | Byte-for-byte values in a test-consumer pod | 3 | planned: Slice 9 |
| J13.2 | F3 | Byte-for-byte in notebook and Dask pods | 3 | not-covered: pack integrations not released |
| J14.1 | F8 | New consumer by values only, on kind | 2 | planned: Slice 10 |
| J14.2 | F8 | New consumer pack installed by Argo CD on real Nebari resolves its secrets | 3 | planned: Slice 10 |
| J15.1 | F9 | Missing ConfigMap and unannotated pods, policy matrix | 2 (policy matrix) | covered |
| J15.2 | F9 | dsp and dask-gateway-pack golden files | - | not-covered: lives in those repos |
| J16.1 | F3 | Dask keeps scaling after the session ends | - | not-covered: dask-gateway-pack integration not released |
| J17.1 | F5 | Status after a failed resolve; unregistered SA; verification failure changes no status | 2 | covered |
| J17.2 | F5 | Soft and strict init behaviour | 1 and 2 | planned: Slice 9 |
| J18.1 | F12 | Sharing warning in the dsp share dialog | - | not-covered: dsp UI, not this repo |
| J19.1 | F10 | Chart has no route; NetworkPolicy enforced by Calico | 1 and 2 | covered |
| J20.1 | F6 | Records hold no plaintext; swapped keys fail with `decrypt_failed` | 1 and 2 | covered |
| J21.1 | F6 | KEK rotation under load; missing KEK fails closed | 2 | covered |
| J22.1 | F8 | Injector and failure modes on kind | 2 | planned: Slice 10 |
| J22.2 | F8 | Injector on real Nebari alongside NIC's other webhooks | 3 | planned: Slice 10 |
| P3.1 | F4, F11 | Platform check: the chart converges through Argo CD on real NIC, with its certificate issued by `nebari-ca-issuer` and trusted through the bundle | 3 | covered |

`P3.1` is a platform check, not a journey, and the catalog labels it so; a green Tier 3 with only `P3.1` and `J1.3` covered is reported as such, never as "journeys pass". "Covered" for J7.1, J9.1, J11.1, J12.1, J17.1, J20.1 and J21.1 means the e2e tests that exist on the Slice 6 branch; the catalog names each test function.

## Mocks: what CI cannot reach

| Dependency | In CI | Why |
|---|---|---|
| Keycloak (Tier 2) | Real Keycloak in kind, realm imported from a committed fixture (two users, a direct-grant test client, the landing client id). Test passwords are fixture values, not secrets | Replaces the static JWKS stand-in, so J1 and J7 exercise the real token path (issuer, `azp`, key rotation over JWKS) |
| Keycloak (Tier 3) | The deployed Nebari's own Keycloak; the test client and user created through the admin API as the master realm admin (the deploy action's `keycloak-admin-password` output; the nebari realm's admin has no admin API roles) | Action output, not a repo secret |
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
| `DEPLOY_ACTION_REF` | v0.3.0 (nebari-dev/deploy-nebari-action; documentation only, see below) |

Readers: `test/e2e/setup.sh`, `test/policy/run-all.sh`, `hack/kind.sh` and the Makefile source it; workflows load it into `$GITHUB_ENV` in their first step; the Dockerfile takes `GO_BUILDER_IMAGE` as a build arg from the Makefile. Two pins cannot be read from a file: the Go constant `guard.PauseImage` and the `uses:` refs in workflows (GitHub does not template `uses:`). For these, Tier 1's catalog test asserts that the constant equals `PAUSE_IMAGE`, that the Dockerfile's `ARG GO_BUILDER_IMAGE` default equals the pin, and that every `nebari-dev/deploy-nebari-action` ref in the workflows equals `DEPLOY_ACTION_REF`.

## Job summaries

Every tier's last step (`if: always()`) writes to `$GITHUB_STEP_SUMMARY`:

1. the commit under test (`github.sha`, and for `merge_group` the queue's head and base SHAs);
2. every pin from `ci/pins.env`, as a table;
3. the tier's check results from the catalog: covered checks run in this tier with pass or fail, and the not-covered and planned checks with their reasons.

Tier 3 adds the resolved NIC release tag and its commit, whether it contains `NIC_REQUIRED_COMMIT` (and so whether this run is `BLOCKING` or `NON-BLOCKING`), and Tier 3's own timing (wall time per step) and resource figures (runner memory and disk, pod requests against node allocatable), since the deploy action reports none.

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
2. `deploy-nebari-action` with `config: test/journeys/nic-config.yaml` (the action's default local kind config with a fixed `project_name`), `nic-version: <resolved tag>`, `wait: true` (Argo CD convergence) and `destroy: true`.
3. Build the image from the checkout and `kind load` it into `kind-<cluster-name>`.
4. `test/journeys/register-app.sh` for `user-secrets` (the chart plus `values-nebari.yaml`) and `user-secrets-cluster` (`cluster/`): copies each into NIC's local GitOps repository (`~/.nic/gitops/<project_name>`), writes its Application manifest from `test/journeys/gitops/` into `apps/` (the image tag of the build and the chart values a Nebari install would set), commits, refreshes `nebari-root` and waits for the Application to exist.
5. Platform convergence check: every Argo CD Application `Synced` and `Healthy`, bounded wait.
6. `go test -tags journeys ./test/journeys` against the deployed cluster's kubeconfig, with outputs passed as env.
7. Summary. If `BLOCKING` is false: in `merge_group`, steps 2-6 are skipped and the job passes; on tag and dispatch, failures from steps 2-6 are summary warnings and the job exits 0. If true, they fail the job.

**One-off proof run (user decision).** Before the CI slice's checkpoint, Tier 3 is run once by hand with the deploy action's `nic-version` set to `de81b1131fbe26fca289f841347d84af727f692f` (the #787 merge), on a scratch branch whose workflow is edited for that run only and never merged. Its passing output is the evidence that `P3.1` and `J1.3` are `covered`. No trigger in the merged workflows can select a NIC commit; they only resolve the latest release.

## Report before turning anything on

Before anyone changes the ruleset, the CI slice's checkpoint delivers a written report with:

- **Merge queue:** available (public repo); the proposed ruleset (required checks `tier1`, `tier2-e2e`, the three `tier2-policy` checks, `tier3`; merge method squash; build concurrency and batch size from the measurements below).
- **Stacking:** how the chained PRs interact with the queue (above), measured on one real retarget.
- **Tier 3 time and size:** Tier 3's own timing and resource figures from the one-off proof run on the #787 commit (full run, journeys included) and from one `workflow_dispatch` run on the latest release (platform bring-up only, stopping at our install); the report labels which is which.
- **Queue throughput:** with Tier 3 at T minutes and Tier 2 at its measured time, the queue merges at most one group per max(T, Tier 2) minutes per concurrent build; the report gives the batch size that keeps a typical day's merges under an hour, and what a failing batch costs (bisection reruns).
- **Runner fit:** memory and disk from Tier 3's resource figures against the standard runner's 16 GB and 14 GB; if it does not fit, the report says so and Tier 3 stays dispatch-only until a larger runner is decided.

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
| Pins file `ci/pins.env` | new | nebari-user-secrets | Makefile, test/e2e/setup.sh, test/policy/run-all.sh, hack/kind.sh, .github/workflows/*.yml, test/journeys catalog test | n/a (new) | n/a | `KEY=value`, shell-sourceable, no command substitution |
| Journey catalog `test/journeys/catalog.yaml` | new | nebari-user-secrets | catalog test, summary tool, docs/ci/coverage.md | n/a (new) | n/a | schema in Data models |
| Required check names | new | nebari-user-secrets | `main` ruleset (set by the user) | n/a (new) | n/a | `tier1`; `tier2-e2e`; `tier2-policy (<version>)`; `tier3`. Renaming one breaks the ruleset silently |
| Make targets for the kind tiers | changed-compatible | nebari-user-secrets | .github/workflows/ci.yml, docs/superpowers/plans/2026-11-20-user-secrets-service.md (validation commands), developers | `grep -rn 'e2e-up\|e2e-test\|policy-test' .github Makefile docs` | n/a | `make e2e-up`; `make e2e-test`; `make policy-test`. Same targets; versions now come from pins; `policy-test` accepts `K8S_VERSION` to run one version |
| Static JWKS server in `e2e-keycloak` | changed-breaking | nebari-user-secrets | test/e2e/setup.sh (`gen_key`, `install_jwks`), test/e2e/fixtures/jwks.yaml, test/e2e/fixtures/values.yaml (issuer/JWKS URL), test/e2e/helpers_test.go (token minting), test/e2e/e2e_test.go:384 (`jwks.e2e-keycloak.svc:443` in the network test) | `grep -rn 'jwks\|e2e-keycloak\|KID' test/e2e` | n/a | replaced by real Keycloak; both consumers change in the CI slice |
| Consumed: deploy-nebari-action v0.3.0 inputs and outputs | unchanged | nebari-dev/deploy-nebari-action | .github/workflows/journeys.yml | `gh api repos/nebari-dev/deploy-nebari-action/contents/action.yml?ref=v0.3.0` | no | external; pinned by ref |
| Consumed: NIC root App-of-Apps reads `apps/*.yaml` in the GitOps dir | unchanged (implicit) | nebari-infrastructure-core | test/journeys/register-app.sh, test/journeys/gitops | `gh api repos/nebari-dev/nebari-infrastructure-core/contents/pkg/argocd/templates/apps/root.yaml?ref=<tag>` | no | register-app.sh writes to it |
| Consumed: NIC cluster CA and trust bundle | unchanged | nebari-infrastructure-core | chart, Tier 2 fixtures, Tier 3 | docs/architecture/contracts.md "Consumed: NIC cluster CA and trust bundle" | n/a | Tier 3 is the first test against a real NIC |

**Pins file.** Promises one line per pin, `KEY=value`, values without spaces except `POLICY_K8S_VERSIONS` (space-separated), comments with `#`. Readers `source` it or load it with `grep -v '^#' >> $GITHUB_ENV`. A missing key is a reader error, never a silent default.

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

Build tag per tier: 1 = none, 2 = `e2e` (and the policy matrix's `run.sh` case names for J7.2 and J15.1), 3 = `journeys`.

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
+ test/journeys/gitops/user-secrets.yaml   Argo CD Application for register-app.sh
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
    → deploy-nebari-action (kind, NIC local provider, test/journeys/nic-config.yaml; waits for Argo CD)
    → docker build; kind load into cluster <project_name>
    → register-app.sh (chart from checkout → ~/.nic/gitops/<project_name> → root App-of-Apps → Argo CD)
    → convergence check (all Applications Synced/Healthy)
    → go test -tags journeys ./test/journeys -json
      → Keycloak admin API (master admin password output) creates the test client and user
      → management API via port-forward; resolve from test pods
    → summary --tier 3 (NIC tag, BLOCKING, Tier 3's timing and resource figures)
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
| Service vs real Nebari (Tier 3) | deploy action kubeconfig and outputs | real NIC release | journeys | P3.1, J1.3 and later Tier 3 checks |
| NIC containment gate | GitHub compare API | real; exercised by one `workflow_dispatch` before and after a qualifying release | manual, recorded in the report | the gate flips by itself |

## Journeys

The definition of done for the CI work itself (IDs C1...C8, separate from the service's J1...J22). Evidence is filled in at the CI slice's checkpoint.

| # | Item | Proof | Check method | Evidence |
|---|------|-------|--------------|----------|
| C1 | A PR from a fork gets every required check to a result without any repo secret | A fork PR shows `tier1`, `tier2-e2e` and the three `tier2-policy` checks passing and `tier3` skipped; the catalog test fails on a workflow that reads `secrets.` other than `GITHUB_TOKEN` | automated: catalog test table case; narrated: checks list of a real fork PR | 2026-11-25 catalog half: `TestScanWorkflowSecrets` rejects a workflow reading `secrets.` (table rows pass); PR #8 run https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45629281918 needed no secrets. Fork PR half 2026-11-26: throwaway draft PR #10 from the fork dcmcand/nebari-user-secrets ran tier1, tier2-e2e and the three tier2-policy checks to pass with no repository secrets, tier3 skipped (run 45801081036) |
| C2 | A reviewer can tell from any job summary what was tested against what | Each tier's summary shows the commit SHA, every pin from `ci/pins.env`, and per check pass/fail or its not-covered reason; Tier 3 adds the NIC tag, `BLOCKING`/`NON-BLOCKING`, timing and resource reports | automated: `RenderSummary` table test; narrated: screenshots of real summaries from all three tiers | 2026-11-25 tiers 1 and 2: `TestRenderSummary` table passes; every job of run https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45629281918 ran its Summary step (commit, pins, check statuses). Tier 3 half and screenshots: Slice 8; 2026-11-26 tier 3: https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45651421474 and https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45796258597 ran the Summary step with NIC tag and commit and BLOCKING/NON-BLOCKING; timing and resource tables now also in the job log |
| C3 | A gap cannot pass as covered | Tier 1 fails on each of: a `covered` check naming a missing test, a journey removed from the catalog, a missing reason, a stale `docs/ci/coverage.md`, a pin out of sync with the Go constant, the Dockerfile or the deploy action ref | automated: catalog table tests, one case per failure | 2026-11-25: `go test ./test/journeys/catalog -run 'TestValidate\|TestPinsMatchSources\|TestScanWorkflowSecrets' -v` -> 36 PASS lines (one table row per failure case), 0 FAIL; `make coverage-doc && git diff --exit-code docs/ci/coverage.md` -> no diff |
| C4 | Changing a pin changes it everywhere | Editing `CALICO_VERSION` in `ci/pins.env` alone changes what `make e2e-up` installs; no pinned version string appears outside `ci/pins.env` except the three cross-checked ones | automated: catalog test grep; narrated: `setup.sh` log line after the edit | 2026-11-25: `CALICO_VERSION=v3.32.2` set in `ci/pins.env` only, `make e2e-up` logged `==> installing Calico v3.32.2`, then reverted; the catalog copy scan (`TestPinsMatchSources`) passes |
| C5 | Tier 2 runs the commit's own image against real Keycloak and the policy matrix | `tier2-e2e` obtains tokens from Keycloak (no JWKS stand-in left in `test/e2e`); the three `tier2-policy` jobs each report their Kubernetes version | narrated: CI run links and log excerpts | 2026-11-25: run https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45629281918: tier2-e2e setup deployed Keycloak 26.8.1 and tokens came from it (no JWKS stand-in in `test/e2e`); the three tier2-policy jobs logged Server Version v1.30.13, v1.32.11, v1.34.3, each 42 passed, 0 failed |
| C6 | Tier 3 installs our chart through Argo CD on NIC and runs journeys | The one-off run on `de81b11` passes `P3.1` and `J1.3` with the Application `Synced`/`Healthy` and the certificate issued by `nebari-ca-issuer`; a dispatch run on the latest release reports `NON-BLOCKING` and exits 0 | narrated: both run links and summaries | 2026-11-26: proof https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45651421474 (attempt 2) green, P3.1 and J1.3 pass, certificate from nebari-ca-issuer; release https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45796258597 NON-BLOCKING, exit 0 |
| C7 | Tier 3 starts blocking by itself once NIC ships #787 | The gate says non-blocking for v0.18.0 and blocking for a tag containing `de81b11`; in `merge_group` while non-blocking, `tier3` passes with the skip line. The `merge_group` half is verified after the user turns the queue on | automated: gate table test with a fake compare API; narrated: a `merge_group` run after turn-on | 2026-11-26: `TestDecide` table (behind/diverged non-blocking, ahead/identical blocking, errors never guess) passes; real gate: v0.18.0 behind de81b11, blocking=false. merge_group half: after the user turns the queue on |
| C8 | The user has the turn-on report before anything is turned on | Report covers merge queue and proposed ruleset, stacking behaviour, measured Tier 3 time and size, queue throughput and batch size, runner fit; the `main` ruleset is unchanged | narrated: report in the PR; `gh api repos/nebari-dev/nebari-user-secrets/rulesets` output before and after | 2026-11-26: docs/ci/turn-on-report.md; ruleset identical before (2026-11-25) and after (2026-11-26) |

## Global Constraints

- Go module `github.com/nebari-dev/nebari-user-secrets`, `go 1.26`; pins exactly as in Tech Stack. Kubernetes 1.30 or later.
- Layout `cmd/<binary>` + `internal/<pkg>`; image `gcr.io/distroless/static:nonroot`, `USER 65532:65532`, `CGO_ENABLED=0`, multi-arch (`linux/amd64`, `linux/arm64`).
- OpenTelemetry: every exported function in `internal/` starts a span from `otel.Tracer("nebari-user-secrets")` named `<package>.<Function>`; errors go to `span.RecordError`. `slog` JSON only in `cmd/` and `internal/httpapi`; audit through `AuditSink`.
- Go tests are table-driven. Constructors take interfaces and return concrete types.
- Secret names `^[A-Za-z_][A-Za-z0-9_]{0,63}$`; suffixes `^[A-Z][A-Z0-9_]{0,63}$`; delivered names `^NEBARI_SECRET_[A-Z][A-Z0-9_]{0,63}$`.
- Limits: 50 secrets per user; value at most 32768 bytes before encryption; encoded `record.json` at most 524288 bytes.
- Label `nebari.dev/user-secrets: "true"`; annotations `nebari.dev/user-secrets-sub`, `nebari.dev/user-secrets-app`, `nebari.dev/user-secrets-export-env`, `nebari.dev/user-secrets-containers`; label `nebari.dev/user-secrets-failure: strict`.
- Token audience `user-secrets`, `expirationSeconds: 600`. Ports: resolve `8443`, management `8444`, injector `9443`.
- Files under `/var/run/nebari/secrets` mode `0440`; `.status` is `ok <count>` or `error <code> <detail>`; wrapper at `/var/run/nebari/user-secrets-bin/user-secrets-env`; memory `emptyDir` `sizeLimit: 1Mi`. Reserved volume and container name prefix `user-secrets-`.
- No value, token or data key in any log, audit line, error message, response or pod spec.
- No AI attribution in commits or PRs.
- CI (Slices 7-8): no workflow reads `secrets.*` other than `secrets.GITHUB_TOKEN`; every external version lives only in `ci/pins.env` (cross-checked: `guard.PauseImage`, the Dockerfile `GO_BUILDER_IMAGE` default, `deploy-nebari-action` refs); required check names exactly `tier1`, `tier2-e2e`, `tier2-policy (<version>)`, `tier3`; Tier 3 resolves the latest NIC release and never a NIC branch or commit, except the one-off proof run on a scratch branch that is never merged; the `main` ruleset is not changed.

## Deviations from the spec (approve at plan review)

| Spec says | Plan does | Why |
|---|---|---|
| Owner Secret named `us-<sub>` ("Keycloak `sub` is a UUID") | `us-` + first 32 hex chars of SHA-256(`sub`); the record's `ownerSub` is checked on every read | Keycloak gives users federated without import an id of the form `f:<component>:<username>`, which is not a valid Secret name. The hash is valid for any `sub`, and the stored `ownerSub` check catches a collision. Spec text updated in Task 1. |
| `NewSessionVerifier(jwks JWKSSource, ...)` | `NewSessionVerifier(keys oidc.KeySet, issuers []string, clientID string)` | go-oidc v3.21.0's `RemoteKeySet` already selects by `kid` and refetches on an unknown one (`oidc/jwks.go:61`, `:155`); tests use `oidc.StaticKeySet`. |
| `Injector.Patch(pod) ([]jsonpatch.Operation, error)` | `Injector.Mutate(pod *corev1.Pod) (*corev1.Pod, error)`, pure; the handler builds the patch with `admission.PatchResponseFromRaw` (controller-runtime v0.23.1 `pkg/webhook/admission/response.go:88`) | Tests assert on the resulting pod instead of on patch operations. |
| Guard expectation "embedded via `embed.FS` from the same YAML `cluster/` ships" | `cluster/embed.go` (`package cluster`) embeds `policies.yaml` and `webhook.yaml`; `internal/guard` imports it | Go cannot embed files outside the package directory. |

## Review Focus

1. **Keycloak rotates its signing key mid-session.** A token signed with a new `kid` must verify without a restart. Test `TestVerifyAfterKeyRotation` in Task 8.
2. **A `sub` that is not a UUID** (`f:ldap-id:alice`). Store, seal and resolve must work. Test `TestNonUUIDSub` in Task 4 and `TestSealOpenNonUUIDSub` in Task 2.
3. **Two browser tabs save at once.** Both writes must persist; the second retries on a `resourceVersion` conflict and never drops the first. Test `TestConcurrentUpsertsBothPersist` in Task 9.
4. **An init container that runs again** (pod sandbox restart) after a secret was deleted. The deleted file must disappear, not linger from the first run. Test `TestWriteAllRemovesStale` in Task 29.
5. **A record at the size limit.** Values of 32768 bytes grow to about 43.7 KB once sealed and base64-encoded, so about 11 fit; acceptance must follow the encoded size, never a plaintext estimate, and the stored record must never exceed 524288 bytes. Test `TestLimitCountsEncodedSize` in Task 9.
6. **The merge queue while Tier 3 is non-blocking.** `tier3` must still report success, not stay pending or skipped-forever, or every queued PR waits. Proven by the release-run and fork-PR rows of Slice 8's Validation and the `merge_group` skip-line case in `TestRenderSummary` (Task 25).
7. **The NIC gate on a GitHub API hiccup.** A 403 rate limit or 5xx must fail the gate, not silently pick blocking or non-blocking. `TestDecide` and `TestGitHubAPI` in Task 26.

---

## Slice Map

| # | Slice | Repos | PRs | Depends on | Journeys |
|---|---|---|---|---|---|
| 1 | Values sealed per user | nebari-user-secrets | nebari-user-secrets#2 | - | 20 |
| 2 | Encrypted records in Kubernetes, with master-key rotation | nebari-user-secrets | nebari-user-secrets#3 | Slice 1 | 21, 20 |
| 3 | Management API | nebari-user-secrets | nebari-user-secrets#4 | Slice 2 | 1, 2, 3, 8 |
| 4 | Installable service | nebari-user-secrets | nebari-user-secrets#5 | Slice 3 | 1, 9, 19 |
| 5 | Admission guard verification | nebari-user-secrets | nebari-user-secrets#6 | Slice 4 | 12, 15 |
| 6 | Resolve | nebari-user-secrets | nebari-user-secrets#7 | Slice 5 | 7, 8, 11, 12, 17 |
| 7 | CI tiers 1 and 2 with a journey catalog | nebari-user-secrets | nebari-user-secrets#8 | Slice 6 | 1, 7 |
| 8 | Tier 3 on a real Nebari and the turn-on report | nebari-user-secrets | nebari-user-secrets#9 | Slice 7 | 1 |
| 9 | Init container and env wrapper | nebari-user-secrets | nebari-user-secrets#10 | Slice 8 | 13, 17 |
| 10 | Injector | nebari-user-secrets | nebari-user-secrets#11 | Slice 9 | 14, 22, 7, 6 |
| 11 | Release and operations | nebari-user-secrets | nebari-user-secrets#12 | Slice 10 | 21 |

Merge order: nebari-user-secrets#1 (design) -> #2 -> #3 -> #4 -> #5 -> #6 -> #7 -> #8 -> #9 -> #10 -> #11 -> #12. Each PR's base is the previous slice's branch.

---

## Slice 1: Values sealed per user
**Goal:** A secret value sealed for one user opens only for that user and that secret name, under a master key that can be swapped.
**Repos / branches:** nebari-user-secrets: `feat/us-01-sealing` (base: `docs/user-secrets-design`)
**PRs:** nebari-user-secrets#2 "Seal values per user" (links spec + plan)
**Depends on:** -
**Contracts touched:** Owner record `record.json` in `us-<sub>`; status record in `us-<sub>-status`
**Docs updated:** docs/architecture/contracts.md, AGENTS.md, docs/architecture/patterns.md (Go services in nebari-dev use `cmd/<binary>` + `internal/<pkg>` layout and a distroless nonroot image), docs/design/user-secrets-spec.md
**Advances journeys:** 20
**Validation:**
| Step | Command / action | Expected |
|---|---|---|
| unit | `go test ./... -race -cover` | pass; `internal/crypto` coverage at least 90% |
| lint | `golangci-lint run` | 0 issues |
| vet | `go vet ./...` | no output |

### Task 1: Module, model types and repo conventions

**Files:**
- Create: `go.mod`, `Makefile`, `.golangci.yml`, `.github/workflows/ci.yml`, `internal/model/model.go`, `internal/model/model_test.go`, `docs/architecture/contracts.md`, `docs/architecture/patterns.md`, `AGENTS.md`
- Modify: `docs/design/user-secrets-spec.md` (Storage: owner Secret name; data model `OwnerRecord`), `.gitignore`

**Interfaces:**
- Produces: package `model` exactly as the spec's "Data models and types" (with `WrappedKey`, `Sealed`), plus `func SecretName(ownerSub string) string`, `func StatusSecretName(ownerSub string) string`, `func DeliveredName(suffix string) string`, `func ValidSecretName(string) bool`, `func ValidSuffix(string) bool`, `func ValidDeliveredName(string) bool`.

- [ ] **Step 1: Write the failing tests** in `internal/model/model_test.go`: `TestSecretName` table (`"0b5a…uuid"` → `"us-"` + 32 lowercase hex chars; `"f:ldap:alice"` → valid DNS-1123 label per `validation.IsDNS1123Label`; two different subs → different names; `StatusSecretName(s) == SecretName(s)+"-status"`). `TestValidators` table with the spec's rejected suffixes `ld_preload`, `A=B`, `../x`, `""` and the accepted `VENDOR_API_KEY`. `TestOwnerRecordJSONRoundTrip`: a record with a `Sealed` value containing bytes `0x00 0xff '\n'` marshals and unmarshals byte-identical, and the JSON has keys `schemaVersion`, `ownerSub`, `dataKey`, `secrets`, `sealed`.
- [ ] **Step 2: Run** `go test ./internal/model/...`: Expected: FAIL (package does not exist).
- [ ] **Step 3: Implement** `internal/model/model.go`: the spec's types; `SecretName` = `"us-" + hex(sha256(sub))[:32]`; validators compile the regexes from Global Constraints once.
- [ ] **Step 4: Repo conventions.** `Makefile` targets `test` (`go test ./... -race -cover`), `lint` (`golangci-lint run`), `build`, `policy-test` (`bash test/policy/run-all.sh`). `.golangci.yml` = nebari-operator's linters minus `ginkgolinter`. `ci.yml` on pull_request: `make lint test` on Go 1.26. `AGENTS.md` holds the contracts pointer from the registries reference and the OpenTelemetry/slog conventions above. `docs/architecture/patterns.md` gets the promoted Go layout pattern (Confirmed 2026-11-20). `docs/architecture/contracts.md` gets the owner record and status record entries (Owner: nebari-user-secrets; Consumers: none outside this repo). In the spec, change "named `us-<sub>` (Keycloak `sub` is a UUID, which is a valid name)" to the hashed name and its reason.
- [ ] **Step 5: Run** `go test ./internal/model/... && golangci-lint run`: Expected: PASS, 0 issues.

### Task 2: Sealer and the master-key interface

**Files:**
- Create: `internal/crypto/kek.go`, `internal/crypto/sealer.go`, `internal/crypto/memkek.go`, `internal/crypto/sealer_test.go`

**Interfaces:**
- Consumes: `model.WrappedKey`, `model.OwnerRecord`, `model.SecretEntry`.
- Produces: `type KeyEncryptionKey interface { PrimaryID(ctx) (string, error); Wrap(ctx, dek []byte, ownerSub string) (model.WrappedKey, error); Unwrap(ctx, w model.WrappedKey, ownerSub string) ([]byte, error) }`; `func NewMemoryKEK(keys map[string][]byte, primary string) *MemoryKEK` (tests and the AES-GCM wrap used by Slice 2's Kubernetes implementation: `func WrapWithKey(key, dek []byte, ownerSub string) ([]byte, error)`, `func UnwrapWithKey(key, ct []byte, ownerSub string) ([]byte, error)`); `func NewSealer(k KeyEncryptionKey, rand io.Reader) *Sealer` with `NewDataKey`, `Seal`, `Open`, `Rewrap` as in the spec; `var ErrDecrypt = errors.New("decrypt_failed")`.

- [ ] **Step 1: Write the failing tests** (table-driven, fixed `rand` reader for determinism where needed):
  - `TestSealOpenRoundTrip`: values `""`, `"\x00\xff\n"`, 32768 random bytes open to the same bytes.
  - `TestSealedBoundToOwnerAndName`: an entry sealed for owner A, name `k1`, opened with record B (own data key) → `ErrDecrypt`; opened in A's record under name `k2` → `ErrDecrypt`.
  - `TestWrappedKeyBoundToOwner`: A's `DataKey` copied into B's record → `Open` returns `ErrDecrypt`.
  - `TestTamperedCiphertextFails`: flip one byte of `Sealed` → `ErrDecrypt`.
  - `TestRewrapUnderNewPrimary`: record wrapped under `k1`; set primary `k2`; `Rewrap` returns `changed == true`, `DataKey.KEKID == "k2"`, values still open; second `Rewrap` returns `false`.
  - `TestSealOpenNonUUIDSub`: owner `f:ldap-id:alice` round-trips.
  - `TestAADUnambiguous`: (sub `"ab"`, name `"c"`) and (sub `"a"`, name `"bc"`) produce different associated data.
- [ ] **Step 2: Run** `go test ./internal/crypto/...`: Expected: FAIL.
- [ ] **Step 3: Implement.** AES-256-GCM via `crypto/aes` + `cipher.NewGCM`; `Sealed` = 12-byte nonce || ciphertext||tag. Value associated data = length-prefixed (`uint32` big-endian) concatenation of `"nebari-user-secrets/v1"`, `sub`, `name`; wrap associated data = the same encoding of `"nebari-user-secrets/kek/v1"`, `sub`. `Open` maps every `cipher` error to `ErrDecrypt` with no detail. Spans per exported function.
- [ ] **Step 4: Run** `go test ./internal/crypto/... -cover`: Expected: PASS, coverage at least 90%.

**Evidence (2026-11-20, Go 1.26.11 toolchain):**
```
$ go test ./... -race -cover
ok  github.com/nebari-dev/nebari-user-secrets/internal/crypto  coverage: 93.6% of statements
ok  github.com/nebari-dev/nebari-user-secrets/internal/model   coverage: 100.0% of statements
exit=0
$ golangci-lint run
0 issues.
$ go vet ./...
exit=0
```
Task reviews: Task 1 spec ✅ quality approved (3 Minor); Task 2 spec ✅ quality approved (4 Minor), fix round 1 enforced 32-byte data keys, scoped re-review: fixed.

**Checkpoint (controller, after the last task; implementers ignore):** run validation, paste evidence, open PR(s), STOP for go-ahead.

---

## Slice 2: Encrypted records in Kubernetes, with master-key rotation
**Goal:** Encrypted owner records persist in Kubernetes Secrets, the master key bootstraps safely, and an admin can rotate or retire it without losing access.
**Repos / branches:** nebari-user-secrets: `feat/us-02-store` (base: `feat/us-01-sealing`)
**PRs:** nebari-user-secrets#3 "Store encrypted records and rotate the master key" (links spec + plan)
**Depends on:** Slice 1
**Contracts touched:** Owner record `record.json` in `us-<sub>`; status record in `us-<sub>-status`, Master-key Secret `user-secrets-kek` and the `user-secrets admin` commands, Audit log line format
**Docs updated:** docs/architecture/contracts.md
**Advances journeys:** 21, 20
**Validation:**
| Step | Command / action | Expected |
|---|---|---|
| unit | `go test ./... -race -cover` | pass |
| integration | `make kind-up && go test -tags integration ./internal/store/... ./internal/admin/... -v` | pass, including `TestKEKRotationOnKind` (journey 21) and `TestRecordsHoldNoPlaintext` (journey 20) |
| lint | `golangci-lint run` | 0 issues |

### Task 3: Audit sink

**Files:** Create `internal/audit/audit.go`, `internal/audit/audit_test.go`

**Interfaces:**
- Produces: the spec's `AuditSink` interface plus `KeyEvent(ctx, event, ownerSub, actor, detail string)`; `func NewSlogAuditSink(l *slog.Logger) *SlogAuditSink`. Line formats exactly as the spec's "Audit" section; every line has `"audit": true`.

- [ ] **Step 1: Write the failing test** `TestAuditLines`: each method writes one JSON line to a `bytes.Buffer` logger with the spec's field names (`event`, `owner_sub`, `reader_sub`, `secret`, `app`, `pod`, `pod_uid`, `sa`, `guard`, `ts`); `TestAuditNeverLogsSecrets`: calling every method with arguments containing `"s3cr3t-value"` in non-value fields where a caller could misuse them is impossible by signature (no value parameter exists); assert the buffer never contains `"value"` as a key.
- [ ] **Step 2: Run** `go test ./internal/audit/...`: FAIL.
- [ ] **Step 3: Implement** with `slog.Logger.LogAttrs` at `Info`.
- [ ] **Step 4: Run**: PASS.

### Task 4: Kubernetes secret store

**Files:** Create `internal/store/store.go`, `internal/store/kubernetes.go`, `internal/store/kubernetes_test.go`, `internal/store/integration_test.go` (build tag `integration`), `hack/kind.sh`; Modify `Makefile` (`kind-up`, `kind-down`)

**Interfaces:**
- Consumes: `model.*`.
- Produces: the spec's `SecretStore` interface plus `AnyRecords(ctx) (bool, error)` and `ListOwners(ctx) ([]string, error)`; `func NewKubernetesSecretStore(c kubernetes.Interface, namespace string, clock func() time.Time) *KubernetesSecretStore`; `var ErrConflict`, `ErrNotFound`, `ErrOwnerMismatch`. Records carry label `nebari.dev/user-secrets-record: owner` (owners) or `status`; `AnyRecords` lists by that label with `Limit: 1`.

- [ ] **Step 1: Write the failing tests** with `k8s.io/client-go/kubernetes/fake`: `TestGetMissingReturnsNotFound`; `TestPutCreatesThenUpdatesWithResourceVersion` (stale version → `ErrConflict`); `TestOwnerMismatch` (Secret under A's name holding `ownerSub` B → `ErrOwnerMismatch`); `TestNonUUIDSub`; `TestRecordDeliveryRateLimited` (two calls within a minute for the same app write once; another app writes; failure of the write returns nil and is not retried); `TestDeliveriesRoundTrip`; `TestAnyRecords` (false on empty, true after one Put, ignores `-status` Secrets).
- [ ] **Step 2: Run** `go test ./internal/store/...`: FAIL.
- [ ] **Step 3: Implement.** One Secret per owner, key `record.json`; status Secret key `status.json`; Secrets are `Type: Opaque` with the record label. `hack/kind.sh up` creates kind `us-dev` (image `kindest/node:v1.34.3`, kubeconfig `./.kube/kind`), `down` deletes it.
- [ ] **Step 4: Write the integration test** `TestRecordsHoldNoPlaintext` (journey 20): Put a record sealed with a `MemoryKEK`, read the raw Secret via the API, assert it contains neither the plaintext nor its base64.
- [ ] **Step 5: Run** `go test ./internal/store/... && make kind-up && go test -tags integration ./internal/store/... -v`: PASS.

### Task 5: Kubernetes master key with fail-closed bootstrap

**Files:** Create `internal/crypto/kubekek.go`, `internal/crypto/kubekek_test.go`

**Interfaces:**
- Consumes: `RecordLister` (`AnyRecords`), `WrapWithKey`, `UnwrapWithKey`, `AuditSink.KeyEvent`.
- Produces: `func NewKubernetesKEK(c kubernetes.Interface, namespace string, records RecordLister, audit KeyAuditor) *KubernetesKEK` implementing `KeyEncryptionKey`, plus `Bootstrap(ctx) error`, `AddKey(ctx) (id string, err error)`, `Retire(ctx, id string, inUse func(ctx) (map[string]int, error)) error`; `var ErrKEKUnavailable = errors.New("kek_unavailable")`; `type KeyAuditor interface{ KeyEvent(ctx, event, ownerSub, actor, detail string) }`. Secret `user-secrets-kek`: data keys `<id>` (32 bytes) and `primary`; ids are `k` + UTC `20060102T150405Z`.

- [ ] **Step 1: Write the failing tests** (fake clientset, table-driven `TestBootstrap`): no Secret + no records → creates it, `kek_created` logged; no Secret + records → `ErrKEKUnavailable`, nothing created, `kek_unavailable` logged; no Secret + list error → `ErrKEKUnavailable`; Secret present → loads, creates nothing; create returns `AlreadyExists` (reactor) → re-reads and succeeds. `TestWrapUsesPrimary`, `TestUnwrapUnknownID` → `ErrKEKUnavailable`, `TestRetireRefusesInUse`, `TestRetireRefusesPrimary`.
- [ ] **Step 2: Run**: FAIL.
- [ ] **Step 3: Implement.** Keys cached in memory after `Bootstrap`; the Secret is re-read on an unknown id before returning `ErrKEKUnavailable`. Never creates the Secret anywhere but `Bootstrap`.
- [ ] **Step 4: Run**: PASS.

### Task 6: Admin commands

**Files:** Create `internal/admin/admin.go`, `internal/admin/admin_test.go`, `internal/admin/integration_test.go` (tag `integration`), `cmd/user-secrets/main.go`, `cmd/user-secrets/admin.go`

**Interfaces:**
- Consumes: `SecretStore` (`Get`, `Put`, `ListOwners`), `*crypto.Sealer`, `*crypto.KubernetesKEK`, `AuditSink`.
- Produces: `func RotateKEK(ctx, s Store, k *crypto.KubernetesKEK, seal *crypto.Sealer, a KeyAuditor, actor string) (Report, error)`; `func RetireKEK(ctx, ..., id string) error`; `func RotateDEK(ctx, ..., owner string) (Report, error)` (`owner == ""` means all); `type Report struct{ Rewrapped int; ByKEK map[string]int }`. CLI: `user-secrets admin rotate-kek|retire-kek <id>|rotate-dek [--owner <sub>]`, `--namespace` (default from `POD_NAMESPACE`), `--actor` (required, recorded in `key_event`).

- [ ] **Step 1: Write the failing tests:** `TestRotateKEKRewrapsAll` (3 records under `k1` → all under the new id, `Report.ByKEK` has only the new id, values open); `TestRotateKEKRetriesConflict` (a reactor returns one `Conflict` on Put → retried, succeeds); `TestRotateDEKReencrypts` (new `DataKey.Ciphertext` differs, values open, `dek_rotated` logged); `TestRetireAfterRotate`.
- [ ] **Step 2: Run**: FAIL.
- [ ] **Step 3: Implement** with up to 5 conflict retries per record (re-Get, re-apply). `cmd/user-secrets/main.go` dispatches subcommands with the standard library `flag` package; only `admin` exists in this slice.
- [ ] **Step 4: Integration test** `TestKEKRotationOnKind` (journey 21, store-level): write 3 records, run `RotateKEK` while a goroutine opens every record in a loop, assert zero open failures and that `RetireKEK(old)` then succeeds; `TestKEKMissingFailsClosed`: delete `user-secrets-kek` with records present, `Bootstrap` → `ErrKEKUnavailable` and no Secret created.
- [ ] **Step 5: Run** `go test ./internal/admin/... && go test -tags integration ./internal/admin/... -v`: PASS. Update `docs/architecture/contracts.md` with the master-key Secret, the admin commands and the `key_event` audit lines.

**Evidence (2026-11-20, Go 1.26.11 toolchain, kind us-dev on kindest/node:v1.34.3):**
```
$ go test ./... -race -cover
ok  internal/admin   coverage: 81.5%    ok  internal/audit  coverage: 100.0%
ok  internal/crypto  coverage: 91.2%    ok  internal/model  coverage: 100.0%
ok  internal/store   coverage: 84.1%    (cmd/user-secrets: no unit tests yet, deferred to Task 11)
$ go test -tags integration ./internal/store/... ./internal/admin/... -v
--- PASS: TestRecordsHoldNoPlaintext (0.03s)        # journey 20
--- PASS: TestKEKRotationOnKind (14.81s)            # journey 21: concurrent opens during rotate-kek, 0 failures, retire-kek succeeds
--- PASS: TestKEKMissingFailsClosed (0.21s)         # journey 21: no key generated while records exist
(all other store and admin tests PASS) ok store 0.124s, ok admin 15.251s
$ golangci-lint run                          -> 0 issues.
$ golangci-lint run --build-tags integration -> 0 issues.
$ go vet ./... ; go vet -tags integration ./... -> clean
```
Task reviews: Task 3 clean. Task 4 approved, 1 fix round (Create NotFound not a conflict). Task 5: Important (stale cached primary after an outside rotation) fixed by reading the live primary on every wrap, plus a follow-up so concurrent reads cannot regress it. Task 6: Important (conflict test could not catch a stale re-write) fixed with real concurrent writes; admin commands now load the master key and never create it.

**Checkpoint (controller, after the last task; implementers ignore):** run validation, paste evidence, open PR(s), STOP for go-ahead.

---

## Slice 3: Management API
**Goal:** A user with a landing-page token can create, list, rotate, rebind and delete their own secrets over the management API, and no response ever contains a value.
**Repos / branches:** nebari-user-secrets: `feat/us-03-management-api` (base: `feat/us-02-store`)
**PRs:** nebari-user-secrets#4 "Management API" (links spec + plan)
**Depends on:** Slice 2
**Contracts touched:** Management API on `:8444` (`/api/v1/secrets`; `/api/v1/apps`; `/api/v1/status`), Audit log line format
**Docs updated:** docs/architecture/contracts.md
**Advances journeys:** 1, 2, 3, 8
**Validation:**
| Step | Command / action | Expected |
|---|---|---|
| unit | `go test ./... -race -cover` | pass, including `TestValueNeverReturned`, `TestBindings`, `TestEnvNameAlwaysPrefixed`, `TestVerifyAfterKeyRotation` |
| lint | `golangci-lint run` | 0 issues |

### Task 7: Registry

**Files:** Create `internal/registry/registry.go`, `internal/registry/registry_test.go`

**Interfaces:**
- Produces: `type Config struct { Apps []App; Creators []model.Creator }`, `type App struct { ID model.AppID; Workloads []Workload }`, `type Workload struct{ Namespace, ServiceAccount string }`; `func Load(r io.Reader) (*Registry, error)` (YAML, `sigs.k8s.io/yaml`); `(*Registry).WorkloadAllowed(app, ns, sa) bool`, `Creators() []model.Creator`, `Apps() []model.AppID`, `CreatorsConfigMapData() map[string]string` (key `<ns>.<sa>`, value `namespaces=<a,b>;apps=<x,y>`, sorted).

- [ ] **Step 1: Failing tests:** `TestLoadRejects` table (duplicate app id, creator username not `system:serviceaccount:<ns>:<name>`, app id not matching `^[a-z][a-z0-9-]{0,31}$`, namespace containing `.`); `TestWorkloadAllowed`; `TestCreatorsConfigMapData` equals exactly `{"hub-ns.hub": "namespaces=hub-ns;apps=jhub-apps,notebook"}` for the matching input (sorted lists).
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement.** **Step 4: Run**: PASS.

### Task 8: Landing token verifier

**Files:** Create `internal/auth/session.go`, `internal/auth/session_test.go`; Modify `go.mod` (`github.com/coreos/go-oidc/v3 v3.21.0`)

**Interfaces:**
- Produces: `func NewSessionVerifier(keys oidc.KeySet, issuers []string, clientID string, now func() time.Time) *SessionVerifier`; `(*SessionVerifier).Verify(ctx, bearer string) (model.Principal, error)`; `var ErrInvalidToken`. Uses `oidc.NewVerifier(issuers[0], keys, &oidc.Config{SkipClientIDCheck: true, SkipIssuerCheck: true, SupportedSigningAlgs: []string{"RS256"}, Now: now})` (go-oidc v3.21.0 `oidc/verify.go:72-106`), then checks `iss` in `issuers`, `typ == "Bearer"`, `azp == clientID`, non-empty `sub`.

- [ ] **Step 1: Failing tests** (real RSA keys, tokens signed with `github.com/go-jose/go-jose/v4`, `oidc.StaticKeySet`): `TestVerify` table: valid → principal with `Sub`, `Username` (`preferred_username`), `Groups`; wrong `azp`; `typ: "ID"`; expired; issuer not in list; second issuer in list accepted; `alg: HS256`; `none`; missing `sub`; token with `user-secrets` in `aud` but wrong `azp`. All failures return `ErrInvalidToken` with no token text in the error. `TestVerifyAfterKeyRotation`: an `httptest` JWKS server switches keys; with `oidc.NewRemoteKeySet` a token with the new `kid` verifies.
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement.** **Step 4: Run**: PASS.

### Task 9: Secret service, management side

**Files:** Create `internal/service/service.go`, `internal/service/manage.go`, `internal/service/manage_test.go`

**Interfaces:**
- Consumes: `store.SecretStore`, `*crypto.Sealer`, `audit.AuditSink`, `*registry.Registry`.
- Produces: `type Limits struct{ MaxSecrets, MaxValueBytes, MaxRecordBytes int }` with `DefaultLimits() Limits` = 50 / 32768 / 524288; `func NewSecretService(s store.SecretStore, c *crypto.Sealer, a audit.AuditSink, r *registry.Registry, l Limits) *SecretService`; `ListForOwner`, `Upsert(ctx, u model.Principal, in UpsertInput) (model.SecretSummary, bool /*created*/, error)`, `Delete`; `type UpsertInput struct{ Name, Description string; Value []byte /*nil = keep*/; Bindings []model.Binding }`; typed errors `ErrInvalidName`, `ErrInvalidSuffix`, `ErrUnknownApp`, `ErrLimitExceeded`, `ErrNotFound`, `ErrEnvConflict`, `ErrValueRequired`.

- [ ] **Step 1: Failing tests:** `TestBindings` (suffix `VENDOR_API_KEY` for `notebook` → summary `Name: "NEBARI_SECRET_VENDOR_API_KEY"`, `Path: "/var/run/nebari/secrets/NEBARI_SECRET_VENDOR_API_KEY"`; suffixes `ld_preload`, `A=B`, `../x`, `""` → `ErrInvalidSuffix`; unknown app → `ErrUnknownApp`; same suffix twice for one app across secrets → `ErrEnvConflict`); `TestEnvNameAlwaysPrefixed` (summaries and stored bindings never hold the prefix in `Env`; `Name` always has it); `TestUpsertCreateRequiresValue`; `TestUpsertKeepsValueWhenNil` (opens to the old value); `TestLimitCountsEncodedSize` (Review Focus 5: keep adding 32 KiB secrets; the first one whose encoded record would exceed 524288 bytes is rejected with `ErrLimitExceeded`, every earlier one is accepted, and the stored Secret never exceeds the limit); `TestConcurrentUpsertsBothPersist` (Review Focus 3: two goroutines upsert different names against a fake store that returns one conflict → both present); `TestSecretWriteAudited`; `TestDeleteUnknown` → `ErrNotFound`; first write for a new owner creates a data key.
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement** with up to 5 conflict retries. **Step 4: Run**: PASS.

### Task 10: Management HTTP API

**Files:** Create `internal/httpapi/management.go`, `internal/httpapi/errors.go`, `internal/httpapi/management_test.go`

**Interfaces:**
- Consumes: `*auth.SessionVerifier`, `*service.SecretService`, `*registry.Registry`, `GuardStatus interface{ State() guard.GuardState }` (a stub returning `{State: "unknown", Mode: "enforced", Reason: "not_started"}` until Slice 5: `internal/httpapi/guardstub.go`).
- Produces: `func NewManagementHandler(v Verifier, s *service.SecretService, r *registry.Registry, g GuardStatus, log *slog.Logger) http.Handler`; routes and status codes exactly as the spec's "Management API"; error bodies `model.APIError`; `type Verifier interface{ Verify(ctx, string) (model.Principal, error) }`.

- [ ] **Step 1: Failing tests** (`httptest`, fake verifier and fake store): `TestRoutes` table covering every route, method and error code in the spec (`401 invalid_token`, `400 invalid_name|invalid_suffix|unknown_app|grants_not_supported|limit_exceeded`, `404 not_found`, `409 env_conflict`, `503 kubernetes_unavailable|kek_unavailable`); `TestValueNeverReturned` (journey 2: upload `"zq-unique-value-91"`, then every route and every error response body contains neither it nor its base64); `TestOnlyCallersRecord` (verifier returns sub A; no path or query parameter can address B); `TestCookieIgnored` (a session cookie without `Authorization` → 401); `TestRequestBodyLimit` (body over 64 KiB → 413).
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement** with `http.ServeMux` patterns (`GET /api/v1/secrets`, `PUT /api/v1/secrets/{name}`, ...), `http.MaxBytesReader`. **Step 4: Run**: PASS. Add the management API entry to `docs/architecture/contracts.md`.

**Evidence (2026-11-20, Go 1.26.11 toolchain):**
```
$ go test ./... -race -cover
ok internal/auth 100.0%   ok internal/httpapi 97.5%   ok internal/registry 98.6%   ok internal/service 89.1%
ok internal/admin 81.5%   ok internal/audit 100.0%    ok internal/crypto 91.2%     ok internal/model 100.0%   ok internal/store 84.1%
(TestValueNeverReturned, TestBindings, TestEnvNameAlwaysPrefixed, TestVerifyAfterKeyRotation, TestLimitCountsEncodedSize,
 TestConcurrentUpsertsBothPersist, TestFirstWritesRaceForNewOwner all PASS)
$ golangci-lint run ; golangci-lint run --build-tags integration -> 0 issues. ; 0 issues.
$ go vet ./... ; go vet -tags integration ./... -> clean
```
Task reviews: Task 7 clean. Task 8 approved; hardened (empty issuer entries refused, fail-closed rows pinned, misconfiguration rows proven to bite by mutation). Task 9 approved; wire code fixed to invalid_suffix, deterministic first-write race test added. Task 10 approved; strict trailing-data check, empty value refused, panic recovery that logs only the type, Allow on 405, log and header leak assertions.

**Checkpoint (controller, after the last task; implementers ignore):** run validation, paste evidence, open PR(s), STOP for go-ahead.

---

## Slice 4: Installable service
**Goal:** The service installs with Helm on a cluster that has NIC's cluster CA, serves the management API over TLS to the landing frontend only, and keeps secrets across restarts and upgrades.
**Repos / branches:** nebari-user-secrets: `feat/us-04-chart` (base: `feat/us-03-management-api`)
**PRs:** nebari-user-secrets#5 "Image, chart and end-to-end harness" (links spec + plan)
**Depends on:** Slice 3
**Contracts touched:** Management API on `:8444` (`/api/v1/secrets`; `/api/v1/apps`; `/api/v1/status`), Creator registry and `user-secrets-creators` ConfigMap, `ClusterIssuer` `nebari-ca-issuer` and ConfigMap `nebari-trust-bundle` (key `ca-certificates.crt`), consumed as merged in nebari-infrastructure-core#787 at `de81b11` (`docs/internal-certificates.md`; root `nebari-root-ca` in `cert-manager`, ECDSA P-256, `rotationPolicy: Never`, critical name constraints permitting `svc` and `svc.cluster.local` on every certificate type and excluding all IP addresses; Bundle with `useDefaultCAs: true`)
**Docs updated:** docs/architecture/contracts.md, docs/architecture/patterns.md (Render-time chart guardrails in a `validate.yaml` template that `fail`s on unsafe values), docs/design/user-secrets-spec.md and docs/design/user-secrets.md ("Requires" and the contracts row: #787 merged at `de81b11`, no longer "proposed"; open question 5 narrowed to the upgrade path for clusters created by #776 before #787, whose root lacks the `svc` constraints)
**Advances journeys:** 1, 9, 19
**Validation:**
| Step | Command / action | Expected |
|---|---|---|
| unit | `go test ./... -race -cover` | pass |
| chart | `helm lint chart -f chart/ci/lint-values.yaml && go test ./test/chart/...` | pass; `TestNoExternalSurface`, `TestNetworkPolicyPorts`, `TestValidateFails`, `TestCertificateWithinNICConstraints` |
| image | `make image` | builds `linux/amd64` and `linux/arm64` |
| nic fixtures | `make nic-fixtures-check` | the vendored NIC templates match nebari-infrastructure-core at `NIC_REF` (default `de81b11`) byte for byte |
| e2e | `make e2e-up && go test -tags e2e ./test/e2e/... -run 'TestManagement|TestDurability|TestNetworkExposure|TestServingCert' -v` | pass (journeys 1, 9, 19); the serving chain verifies to NIC's rendered root under its name constraints |

**Evidence (2026-11-23, Go 1.26.11 toolchain, kind us-e2e on kindest/node:v1.34.3, Calico v3.32.3, cert-manager v1.17.2, trust-manager v0.22.1, NIC templates at `de81b11`):**
```
$ go test ./... -race -cover
ok cmd/user-secrets 39.3%   ok cmd/user-secrets-init 66.7%   ok internal/auth 96.0%      ok internal/config 87.9%
ok internal/httpapi 97.5%   ok internal/telemetry 91.3%      ok internal/crypto 91.2%    ok internal/store 84.1%
ok internal/service 89.1%   ok internal/registry 98.6%       ok internal/admin 81.5%     ok test/chart
$ helm lint chart -f chart/ci/lint-values.yaml && go test ./test/chart/... -v
1 chart(s) linted, 0 chart(s) failed
PASS TestNoExternalSurface, TestNetworkPolicyPorts, TestCreatorsConfigMapMatchesGo, TestValidateFails (14 rows),
     TestCertificateWithinNICConstraints, TestPodSecurityRestricted, TestConfigMapLoads
$ make image   -> exit 0; bin/image.oci.tar index: linux/amd64, linux/arm64 (+2 buildx attestation manifests)
$ make nic-fixtures-check   -> NIC fixtures match de81b1131fbe26fca289f841347d84af727f692f
$ GOTOOLCHAIN=go1.26.11 make lint   -> 0 issues (e2e build tag included)
$ make e2e-up && make e2e-test
PASS TestServiceReadyUnderPolicy
PASS TestServingCertChainsToNICRoot (user-secrets.us-system.svc, .svc.cluster.local, root refuses probe.example.com: CANotAuthorizedForThisName)
PASS TestManagementCreateList                      (journey 1)
PASS TestManagementRejectsOtherClient (landing 200, other azp 401)
PASS TestDurabilityAcrossRestart                   (journey 9, partial: see below)
PASS TestNetworkExposure (control connects; workload -> 8444 timed out; landing -> 8444 connects;
                          landing -> 8443 timed out)  (journey 19)
ok test/e2e
```
Journeys: 19 met in full on kind with Calico. 1 met for the automated half (a static JWKS signer stands in for a direct-grant Keycloak client; same `azp` path); the narrated dev-cluster `curl` with a real landing token stays open. 9 partial: restart and `helm upgrade --reuse-values` keep the record and a replica answers throughout, but the value is read back through the store, not through resolve, which arrives in Slice 6; Task 21 re-runs durability through resolve.
Task reviews: Task 11 approved after round 1 (own JWKS key set because go-oidc v3.21.0 `oidc/jwks.go:163-177` refetches on a known kid with a bad signature; fetch detached from the request context). Task 12 approved. Task 13 approved (no placeholder required values; creator ServiceAccount namespace counted as shared). Task 14 approved (NIC templates vendored and rendered; CI `ci` job gains helm).

### Task 11: Serve command

**Files:** Create `cmd/user-secrets/serve.go`, `internal/config/config.go`, `internal/config/config_test.go`, `internal/telemetry/telemetry.go`

**Interfaces:**
- Consumes: everything above.
- Produces: `user-secrets serve --config /etc/user-secrets/config.yaml`; `config.Config{ Namespace string; Registry registry.Config; Keycloak struct{ JWKSURL string; Issuers []string; ClientID string }; TLS struct{ CertFile, KeyFile string }; Guard struct{ Mode string /*enforced|unverified*/ }; Limits service.Limits; InitImage string }` loaded and validated by `config.Load(path) (*Config, error)`; `telemetry.Setup(ctx) (shutdown func(context.Context) error, err error)` honouring `OTEL_EXPORTER` (`none` default in-cluster, `otlp`, `console`) like NIC.

- [ ] **Step 1: Failing tests** `TestLoadConfig` table (missing issuer, unknown guard mode, `unverified` logged as warning field, limits default when absent).
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement** `serve`: build the dependency graph per the spec's "Component trees and DI" (only the parts that exist so far), `KubernetesKEK.Bootstrap` before listening (on `ErrKEKUnavailable` serve 503 `kek_unavailable` instead of exiting), TLS server on `:8444` reloading the cert files on change (`tls.Config.GetCertificate` with a file-mtime cache), `/healthz` and `/readyz` on plain `:8080`, graceful shutdown on SIGTERM. **Step 4: Run**: PASS.

### Task 12: Image

**Files:** Create `Dockerfile`, `.dockerignore`; Modify `Makefile` (`image`, `IMG ?= ghcr.io/nebari-dev/nebari-user-secrets:dev`)

- [ ] **Step 1:** Multi-stage like nebari-operator's `Dockerfile` (`golang:1.26` builder, `CGO_ENABLED=0`, both binaries to `/`, `gcr.io/distroless/static:nonroot`, `USER 65532:65532`, `ENTRYPOINT ["/user-secrets"]`). `cmd/user-secrets-init` is a stub `main` printing usage until Slice 9.
- [ ] **Step 2: Run** `make image`: Expected: image builds; `docker run --rm $IMG --help` prints usage.

### Task 13: Helm chart

**Files:** Create `chart/Chart.yaml`, `chart/values.yaml`, `chart/templates/{_helpers.tpl,deployment.yaml,service.yaml,certificate.yaml,configmap.yaml,creators-configmap.yaml,rbac.yaml,networkpolicy.yaml,pdb.yaml,serviceaccount.yaml,validate.yaml}`, `test/chart/chart_test.go`

**Interfaces:**
- Produces values: `registry` (as `registry.Config`), `keycloak.{jwksURL,issuers,clientID}`, `landing.{namespace,podSelector}`, `guard.mode`, `guard.allowSharedNamespace`, `limits`, `image`, `initImage`, `replicas: 2`. Certificate `user-secrets-tls` from `ClusterIssuer nebari-ca-issuer`, `dnsNames` `user-secrets.<ns>.svc` and `.svc.cluster.local`. Service ports `resolve 8443`, `management 8444`, `injector 9443` (target ports declared now; servers added in later slices). NetworkPolicy in this slice: ingress `8444` only from `landing.namespace` + `landing.podSelector`; nothing else. `creators-configmap.yaml` renders `user-secrets-creators` from `registry` with the same key/value encoding as `CreatorsConfigMapData`.

- [ ] **Step 1: Failing tests** in `test/chart` (run `helm template` via `os/exec`, parse with `sigs.k8s.io/yaml`): `TestNoExternalSurface` (no `NebariApp`, `HTTPRoute`, `Ingress`, no `LoadBalancer`/`NodePort` Service); `TestNetworkPolicyPorts` (8444 from the landing selector only); `TestCreatorsConfigMapMatchesGo` (chart output data equals `registry.CreatorsConfigMapData()` for the same values file); `TestValidateFails` table (`helm template` fails when the service namespace is a registered workload or creator namespace without `guard.allowSharedNamespace`; when `allowSharedNamespace` is set without `guard.mode: unverified`; when `keycloak.clientID` is empty); `TestCertificateWithinNICConstraints` (the `Certificate` uses `issuerRef` `ClusterIssuer nebari-ca-issuer`; every `dnsNames` entry ends in `.svc` or `.svc.cluster.local`, the only names #787's root permits on `letsencrypt` and `existing` clusters; no `ipAddresses`, which the root excludes); `TestPodSecurityRestricted` (the Deployment's pod passes `policy.NewEvaluator(policy.DefaultChecks(), nil).EvaluatePod` at `restricted`, pod-security-admission v0.35.0 `policy/registry.go:49`, `:67`).
- [ ] **Step 2: Run** `go test ./test/chart/...`: FAIL. **Step 3: Implement** the chart. RBAC per the spec's program layout for what exists now: Role in the service namespace on `secrets` (`get`, `list`, `create`, `update`, `delete`). **Step 4: Run** `helm lint chart && go test ./test/chart/...`: PASS. Write the promoted `validate.yaml` pattern to `docs/architecture/patterns.md`.

### Task 14: End-to-end harness and management journeys

**Files:** Create `test/e2e/setup.sh`, `test/e2e/fixtures/nic/` (verbatim copies of nebari-infrastructure-core `pkg/argocd/templates/manifests/security/issuers/{selfsigned-clusterissuer,root-ca-certificate,ca-clusterissuer}.yaml`, `pkg/argocd/templates/manifests/security/trust-bundle/bundle.yaml` and `pkg/argocd/templates/values/{cert-manager,trust-manager}/base.yaml` at `de81b11`, plus `SOURCE` naming the repo, commit and paths), `test/e2e/nicrender/main.go` (build tag `e2e`), `test/e2e/fixtures/jwks.yaml`, `test/e2e/e2e_test.go`, `test/e2e/helpers_test.go` (build tag `e2e`); Modify `Makefile` (`e2e-up`, `e2e-down`, `nic-fixtures-check`), `.github/workflows/ci.yml` (e2e job on kind)

**Interfaces:**
- Produces: `nicrender` renders the vendored NIC templates with `text/template` and the `indent` func NIC uses (`templateFuncs`, `pkg/argocd/writer.go:599-600` at `de81b11`), filling the fields exactly as `NewTemplateData` does for `certificate.type: letsencrypt` (`writer.go:244`): `RootCASecretName: nebari-root-ca`, `CAIssuerName: nebari-ca-issuer`, `RootCAPermittedDNSDomains: [svc, svc.cluster.local]`, `Domain: nebari.local`, no `TrustBundlePEM`. Letsencrypt is chosen because its constraints are the strictest, so a serving certificate that verifies here verifies on every type. `nic-fixtures-check` fetches the same paths from nebari-infrastructure-core at `NIC_REF` (`gh api ... -H 'Accept: application/vnd.github.raw'`) and diffs them; it is a manual drift check when NIC changes, not a CI gate.
- Produces: `setup.sh` creates kind `us-e2e` (v1.34.3, Calico so NetworkPolicy is enforced), installs cert-manager v1.17.2 and trust-manager v0.22.1 with NIC's vendored `base.yaml` values (trust namespace `cert-manager`, `defaultPackage.enabled: true`, which the Bundle's `useDefaultCAs: true` needs), applies the `nicrender` output, waits for `nebari-root-ca` Ready and `nebari-trust-bundle` to appear in the landing namespace, deploys a static JWKS server (`jwks.yaml`, an nginx serving a test key the tests sign with) and installs the chart with `keycloak.jwksURL` pointing at it. Helpers: `signToken(t, sub, azp string) string`, `mgmtClient(t)` (port-forward through a pod in the landing namespace carrying the frontend labels; `RootCAs` is only the `ca-certificates.crt` read from `nebari-trust-bundle` in the landing namespace, never the system pool, and `ServerName` is `user-secrets.<ns>.svc` because the dial target is localhost).

- [ ] **Step 1: Write** `TestServingCertChainsToNICRoot` (reads the leaf from `user-secrets-tls` and `x509.Verify`s it against `nebari-trust-bundle` for `DNSName` `user-secrets.<ns>.svc` and `.svc.cluster.local`; a probe `Certificate` from `nebari-ca-issuer` for `probe.example.com`, verified for that name against the same bundle, fails with `x509.CertificateInvalidError` reason `x509.CANotAuthorizedForThisName`, which proves the root's constraints are in force in the harness, as #787's "root refuses example.com" journey does), `TestManagementCreateList` (journey 1: PUT `vendor_key` → 201, GET lists it with bindings), `TestManagementRejectsOtherClient` (journey 8d: `azp` other → 401), `TestDurabilityAcrossRestart` (journey 9: store, `kubectl rollout restart`, `helm upgrade --reuse-values`, value still resolves through the store and at least one replica answered `/readyz` throughout, polled every 500 ms), `TestNetworkExposure` (journey 19: a pod in a workload namespace cannot connect to 8444 within 3 s; the landing-labelled pod can).
- [ ] **Step 2: Run** `make e2e-up && go test -tags e2e ./test/e2e/... -v`: Expected first: FAIL until the chart and fixtures are complete; then PASS. Update `docs/architecture/contracts.md` with the creators ConfigMap and the consumed NIC CA contract.

**Checkpoint (controller, after the last task; implementers ignore):** run validation, paste evidence, open PR(s), STOP for go-ahead.

---

## Slice 5: Admission guard verification
**Goal:** Each replica knows whether policies A and B are in force, reports it on `/api/v1/status`, and never forgets a pod admitted while they were not.
**Repos / branches:** nebari-user-secrets: `feat/us-05-guard` (base: `feat/us-04-chart`)
**PRs:** nebari-user-secrets#6 "Guard verification" (links spec + plan)
**Depends on:** Slice 4
**Contracts touched:** Cluster bundle (`cluster/` with `cluster/REVIEW.md`), Creator registry and `user-secrets-creators` ConfigMap, Audit log line format
**Docs updated:** docs/architecture/contracts.md, cluster/REVIEW.md
**Advances journeys:** 12, 15
**Validation:**
| Step | Command / action | Expected |
|---|---|---|
| unit | `go test ./... -race -cover` | pass, `internal/guard` table covers every confirmed-bad case in journey 12 |
| policy | `make policy-test` | every version `RESULT: <n> passed, 0 failed`; transcripts updated in `test/policy/results/` |
| e2e | `go test -tags e2e ./test/e2e/... -run TestGuard -v` | pass (`TestGuardFailClosed`, `TestGuardVerifiedSinceMoves`) |

**Evidence (2026-11-23, Go 1.26.11 toolchain, kind us-e2e on kindest/node:v1.34.3, Calico v3.32.3, NIC templates at `de81b11`):**
```
$ go test ./... -race -cover
ok cmd/user-secrets 40.9%   ok internal/guard 94.2%     ok internal/httpapi 97.5%   ok internal/auth 96.0%
ok internal/config 87.9%    ok internal/crypto 91.2%    ok internal/store 84.1%     ok internal/service 89.1%
ok internal/registry 98.6%  ok internal/admin 81.5%     ok internal/audit 100.0%    ok internal/model 100.0%
ok internal/telemetry 91.3% ok cmd/user-secrets-init 66.7%                           ok test/chart
  internal/guard TestCompare covers every confirmed-bad case of journey 12 (binding removed, [Warn], [Audit],
  [Warn, Audit], binding B narrowed or paramRef changed, paramRef added to binding A, policy edited, ConfigMap
  drift or missing); TestGuard covers probe admitted, canary denied, API error and Pod Security as unknown
  (119 s allowed, 120 s denied), verifiedSince moves, override mode
$ make policy-test
RESULT: 42 passed, 0 failed   (v1.30.13, v1.32.11, v1.34.3; transcripts in test/policy/results/)
$ go test -tags e2e ./test/e2e/... -run TestGuard -v
--- PASS: TestGuardFailClosed (4.67s)
--- PASS: TestGuardVerifiedSinceMoves (3.11s)
ok test/e2e
$ make e2e-test   -> 9/9 PASS, incl. TestMissingConfigMapLeavesClusterWorking and the Slice 4 tests
$ make image      -> exit 0 (amd64 + arm64; the binary embeds cluster/policies.yaml through .dockerignore)
$ GOTOOLCHAIN=go1.26.11 make lint -> 0 issues;  helm lint chart -f chart/ci/lint-values.yaml -> 0 failed
```
Journeys: 12 partial. Every confirmed-bad cause is covered by the unit table, and on kind a binding switched to `[Warn]` reads `confirmed_bad` on every replica within 10 s, while restoring it reads `verified` in about 2 s and moves `verifiedSince` (API-server time + 30 s). The delivery half (no secret files, `.status` `error guard_not_verified`, `pod_predates_guard`) needs resolve and the init container, in Slices 6 and 7. 15 partial (service half): with `user-secrets-creators` deleted the guard reads `confirmed_bad` and an unlabelled pod in `default` creates; the missing-ConfigMap section of the policy matrix passes on all three versions. The dsp and dask-gateway-pack golden tests belong to those repos' plans.
Found on the real cluster: the API server applies a binding change up to 1 s late (`generic/policy_source.go`), so the guard probes 2 s after the latest watch event and retries on a 2-30 s backoff while not verified. Spec "Guard verification" updated to match.
Task reviews: Task 15 approved (Minor round; kustomize test found an over-indented line in `policies.yaml` that would have read as `confirmed_bad` on a correct install). Task 16 approved after round 1 (denial matched on the exact VAP status cause, checked at apiserver v0.30.0 and v0.35.0). Task 17 approved after 3 rounds (per-probe outcomes; persisted bad-seen marker cleared only by the replica that observed it; recheck under lock). Task 18 approved after the settle/backoff ruling and a Minor round.

### Task 15: Embedded expectation and reader RBAC

**Files:** Create `cluster/embed.go`, `cluster/rbac.yaml`, `internal/guard/expect.go`, `internal/guard/expect_test.go`; Modify `cluster/kustomization.yaml`, `cluster/REVIEW.md`

**Interfaces:**
- Produces: `package cluster` with `//go:embed policies.yaml` → `var Policies []byte`; `type Expectation struct{...}`; `func NewExpectation(namespace string) (Expectation, error)` (applies the same two substitutions as the kustomization); `(Expectation).Compare(p Policies, b Bindings, cm *corev1.ConfigMap, wantCM map[string]string) (ok bool, reason string)`. `cluster/rbac.yaml`: `ClusterRoleBinding` to `system:auth-delegator` and `ClusterRole`/`ClusterRoleBinding` `user-secrets-guard-reader` (`get`, `list`, `watch` on the two policies and two bindings by `resourceNames`), service account namespace substituted by kustomize.

- [ ] **Step 1: Failing tests** `TestCompare` table, one row per confirmed-bad case in the spec's guard bullets (policy spec edited; binding A gains `paramRef`; binding A `matchResources` set; binding B `paramRef` name, namespace or `parameterNotFoundAction` changed; binding B `objectSelector` changed; `validationActions` `[Warn]`, `[Audit]`, `[Warn, Audit]` fail; `[Deny, Audit]` passes; ConfigMap data drift; ConfigMap missing) plus the matching good row; `TestExpectationMatchesKustomize` (runs `kubectl kustomize cluster/` with namespace `us-test` and compares to `NewExpectation("us-test")`).
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement.** **Step 4: Run**: PASS.

### Task 16: Watcher and prober

**Files:** Create `internal/guard/watch.go`, `internal/guard/probe.go`, `internal/guard/probe_test.go`

**Interfaces:**
- Produces: `func NewInformerWatcher(c kubernetes.Interface, namespace string) *InformerWatcher` implementing the spec's `AdmissionWatcher` (field-selector informers by name); `func NewDryRunProber(c kubernetes.Interface, namespace, pauseImage string) *DryRunProber` implementing `Prober`; `type ProbeResult struct{ LabelledDeniedByB, UnlabelledDeniedByA, CanaryAdmitted, Inconclusive bool; Detail string }`. Probe pods are `restricted`-compliant with the pause image pinned by digest (`registry.k8s.io/pause:3.10sha256:…`, digest filled at implementation time from `crane digest`), and are recognised by the policies' exact messages from `cluster/policies.yaml`.

- [ ] **Step 1: Failing tests** with fake clientset reactors on `create pods` (dry-run): B's message → `LabelledDeniedByB`; any other error → `Inconclusive`; canary error → `CanaryAdmitted == false`; `TestProbePodsRestricted` (each probe pod passes pod-security-admission `restricted`).
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement.** **Step 4: Run**: PASS.

### Task 17: Guard state machine and verifiedSince

**Files:** Create `internal/guard/guard.go`, `internal/guard/state.go`, `internal/guard/guard_test.go`

**Interfaces:**
- Produces: the spec's `NewGuard(w, p, expected, mode, grace, now)`, `Evaluate`, `Allows`, `State`, `VerifiedSince`, plus `Run(ctx) error` (evaluate on watch events and every 5 minutes); `GuardState` as in the spec; state persisted in ConfigMap `user-secrets-guard-state` (`fingerprint`, `verifiedSince` RFC 3339) with `resourceVersion` concurrency.

- [ ] **Step 1: Failing tests** (`TestGuard` table with fake watcher, prober and clock): every journey-12 cause → `confirmed_bad` immediately and `Allows() == false`; API error → `unknown`, still allowed for 119 s, denied at 120 s; Pod-Security-denied probe → `unknown`; recovery after `confirmed_bad` → `verified` with `VerifiedSince` = API-server write time + 30 s; fingerprint change (binding `generation` +2, ConfigMap `resourceVersion` change, policy `uid` change) moves `VerifiedSince` once probes pass; `VerifiedSince` never decreases when another replica stored a later value; `unverified` mode → `Allows()` true with mode `overridden` and no persistence; every state change emits one `guard_state` audit line.
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement.** **Step 4: Run**: PASS.

### Task 18: Wire the guard and test it on kind

**Files:** Modify `cmd/user-secrets/serve.go`, `internal/httpapi/management.go` (drop `guardstub.go`), `chart/templates/rbac.yaml` (guard-state ConfigMap `get`/`create`/`update` by name, `pods` `create` for probes), `test/e2e/setup.sh` (apply `cluster/` after the chart); Create `test/e2e/guard_test.go`

- [ ] **Step 1: Write** `TestGuardFailClosed` (journey 12: with the bundle at `[Deny]` status reports `verified`; patch binding B to `[Warn]` → `confirmed_bad` within 10 s; restore → `verified`) and `TestGuardVerifiedSinceMoves` (the restore moves `verifiedSince` past the patch time) and `TestMissingConfigMapLeavesClusterWorking` (journey 15, service side: delete `user-secrets-creators`, status `confirmed_bad`, an unlabelled pod in `default` creates fine).
- [ ] **Step 2: Run** e2e: FAIL. **Step 3: Implement the wiring.** **Step 4: Run** e2e and `make policy-test`: PASS; commit the refreshed transcripts. Update `cluster/REVIEW.md` (the two bindings now ship) and `docs/architecture/contracts.md`.

**Checkpoint (controller, after the last task; implementers ignore):** run validation, paste evidence, open PR(s), STOP for go-ahead.

---

## Slice 6: Resolve
**Goal:** A labelled pod from a registered creator gets exactly its user's secrets for its app with its own token, and every other caller gets nothing and leaves an audit line.
**Repos / branches:** nebari-user-secrets: `feat/us-06-resolve` (base: `feat/us-05-guard`)
**PRs:** nebari-user-secrets#7 "Resolve API" (links spec + plan)
**Depends on:** Slice 5
**Contracts touched:** `POST /api/v1/resolve` (resolve API), Pod label `nebari.dev/user-secrets` and annotations `nebari.dev/user-secrets-sub` and `-app`, Owner record `record.json` in `us-<sub>`; status record in `us-<sub>-status`, Audit log line format
**Docs updated:** docs/architecture/contracts.md
**Advances journeys:** 7, 8, 11, 12, 17
**Validation:**
| Step | Command / action | Expected |
|---|---|---|
| unit | `go test ./... -race -cover` | pass, including `TestResolveFiltersByApp`, `TestPodVerifier` |
| e2e | `go test -tags e2e ./test/e2e/... -run 'TestResolve|TestCrossUser|TestDecryptFailed' -v` | pass |

### Task 19: Pod verifier

**Files:** Create `internal/podidentity/verifier.go`, `internal/podidentity/kube.go`, `internal/podidentity/verifier_test.go`

**Interfaces:**
- Produces: the spec's `TokenReviewer`, `PodGetter`, `NewPodVerifier(r, p, reg)`, `Verify(ctx, bearer) (model.PodClaim, error)`; client-go implementations `NewKubeTokenReviewer(c)` and `NewKubePodGetter(c)`; typed errors carrying the spec's reasons `not_pod_bound`, `uid_mismatch`, `not_annotated`, `not_registered`.

- [ ] **Step 1: Failing tests** `TestPodVerifier` table: unauthenticated review → `not_pod_bound` (401); no `pod-name`/`pod-uid` in `extra` → `not_pod_bound`; pod missing → 403; UID differs → `uid_mismatch`; unlabelled pod → `not_annotated`; label without annotations → `not_annotated`; `dask` app with the notebook SA → `not_registered` (journey 8a); happy path returns namespace, name, UID, SA, app and `Principal{Kind: "user", Sub}`. Audience passed to the review is exactly `[]string{"user-secrets"}`.
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement.** **Step 4: Run**: PASS.

### Task 20: Resolve service and HTTP

**Files:** Create `internal/service/resolve.go`, `internal/service/resolve_test.go`, `internal/httpapi/resolve.go`, `internal/httpapi/resolve_test.go`; Modify `cmd/user-secrets/serve.go` (`:8443`), `chart/templates/networkpolicy.yaml` (8443 from registered workload namespaces), `chart/templates/rbac.yaml` (per registered namespace Role: `pods` `get`)

**Interfaces:**
- Produces: `(*SecretService).Resolve(ctx, c model.PodClaim, g model.GuardMode) ([]model.ResolvedSecret, error)`; `func NewResolveHandler(v PodClaimVerifier, s *service.SecretService, g GuardAllower, a audit.AuditSink, now func() time.Time) http.Handler` at `POST /api/v1/resolve` with the spec's responses (`value_b64`), `pod_predates_guard` check against `VerifiedSince` in enforced mode, status recorded only for verified pods.

- [ ] **Step 1: Failing tests:** `TestResolveFiltersByApp` (journey 8b); `TestResolveNeverUnprefixed` (a corrupted record with `Env: "LD_PRELOAD"` yields no entry); `TestResolveDecryptFailed` (journey 20: a record holding another owner's data key → `500 decrypt_failed`, `key_event decrypt_failed`, nothing returned); handler table: guard not allowed → `503 guard_not_verified`; pod created at or before `VerifiedSince` → `403 pod_predates_guard`; overridden mode skips it and audit lines carry `"guard":"overridden"`; KEK unavailable → `503 kek_unavailable`; a Keycloak-looking JWT → 401 (journey 8c); one `secret_read` per returned secret and one `resolve_denied` per denial (journey 11); a UID-mismatch pod records no delivery status (journey 17).
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement.** **Step 4: Run**: PASS.

### Task 21: Resolve on kind

**Files:** Create `test/e2e/resolve_test.go`, `test/e2e/fixtures/consumer.yaml` (namespace `test-consumer`, workload SA `tc-workload`, creator SA `tc-creator` with `edit` there), values file `test/e2e/fixtures/values-consumer.yaml` registering app `test-consumer`

- [ ] **Step 1: Write** `TestResolveFromLabelledPod`: as `tc-creator`, create a labelled pod (hand-built: projected token volume, a curl image calling resolve with the trust bundle); its log shows exactly the user's `test-consumer` secrets. `TestCrossUserIsolation` (journey 7, service half): user B's pod gets none of A's; an unlabelled pod with the token gets 403; `TestDecryptFailedOnKind`.
- [ ] **Step 2: Run**: PASS after wiring. Update `docs/architecture/contracts.md` (resolve API, pod metadata).

**Evidence (2026-11-24, Go 1.26.11 toolchain, kind us-e2e on kindest/node:v1.34.3, Calico v3.32.3, NIC templates at `de81b11`):**
```
$ go test ./... -race -cover
ok cmd/user-secrets 42.7%   ok internal/podidentity 100.0%  ok internal/httpapi 98.0%  ok internal/service 91.8%
ok internal/store 84.9%     ok internal/guard 94.2%         ok internal/auth 96.0%     ok internal/registry 98.6%
ok internal/crypto 91.2%    ok internal/config 90.0%        ok internal/admin 81.5%    ok internal/audit 100.0%
ok internal/model 100.0%    ok internal/telemetry 91.3%     ok cmd/user-secrets-init 66.7%   ok test/chart
$ go test -count=1 -race ./internal/... -run 'TestResolveFiltersByApp|TestPodVerifier' -v
--- PASS: TestPodVerifier (0.00s)
--- PASS: TestResolveFiltersByApp (0.46s)
$ go test -tags e2e ./test/e2e/... -run 'TestResolve|TestCrossUser|TestDecryptFailed' -v
--- PASS: TestResolveFromLabelledPod (3.54s)
--- PASS: TestCrossUserIsolation (4.72s)
--- PASS: TestDecryptFailedOnKind (3.74s)
--- PASS: TestResolveGuard (39.09s)
--- PASS: TestResolveDeniedAudit (5.65s)
ok test/e2e 56.748s
$ make e2e-test   -> 15/15 PASS (118.1 s, rerun after Task 21b), incl. TestServiceReadyUnderPolicy (now asserts both ingress rules exactly) and TestDurabilityThroughResolve
$ GOTOOLCHAIN=go1.26.11 make lint -> 0 issues;  go vet ./... -> no output
```
Journeys: 7 partial: on kind, user B's labelled pod resolves only B's secrets and none of A's, an unlabelled pod with its projected token gets 403 `not_annotated`, and A's management token at resolve gets 401 `not_pod_bound` (`TestCrossUserIsolation`); the API-server refusals (non-creator, label or annotation changes, and the rest) are the policy matrix in `test/policy` (Slice 5). The two-real-Keycloak-users version waits for the CI slice's Keycloak. 8 covered: (a) `TestPodVerifier` (dask-annotated pod as the notebook SA gets 403), (b) `TestResolveFiltersByApp`, (c) on kind, a user's Keycloak management token at resolve gets 401 `not_pod_bound` (`TestCrossUserIsolation`; the `internal/httpapi` case proves only the 401 mapping); a token with `user-secrets` in `aud` is not tested yet, (d) unchanged from Slice 3. 9 re-checked through resolve: after `rollout restart` and `helm upgrade` resolve returns the stored value. 11 partial: `secret_read` lines carry owner_sub, reader_sub, secret, app, pod, pod_uid, sa, guard, and each denial writes exactly one `resolve_denied` with its reason, with no value or token substrings (unit table `TestResolveHandler`; on kind `TestResolveDeniedAudit` checks one reason, `not_annotated`); the narrated `kubectl logs` excerpt waits for a dev cluster. 12 delivery half on kind: with binding B at `[Warn]` resolve answers 503 `guard_not_verified`; a labelled pod created while B was at `[Warn]` is refused 403 `pod_predates_guard` after restore, and a pod created afterwards resolves (`TestResolveGuard`); the notebook `.status` half needs Slice 9. 17 partial: an unregistered SA records `not_registered` as the app's last failure and a pod that fails verification changes no user's status (unit: `TestResolveHandler`, `TestRecordDeliveryKeepsOtherOutcome`; not yet read back through `GET /api/v1/secrets`); soft and strict init behaviour is Slice 9. 20: copying A's sealed entry into B's record makes resolve for B fail with `decrypt_failed` and return nothing of A's (`TestDecryptFailedOnKind`).
Found on the real cluster: an HTTP/2 client kept waiting until the post-response status write returned, so the resolve server is HTTP/1.1 only (`TestTLSServerProtocols`) and recorded responses carry `Content-Length`. A pod created within about 30 s after `verifiedSince` moves is refused `pod_predates_guard` for its lifetime (documented in `contracts.md`; Slice 9's init container will see it).
Found in the fresh-eyes review: the single Kubernetes client ran on client-go's default 5 req/s, burst 10 per API group (client-go v0.35.0 `rest/config.go:47-48`), so a pod-start burst queued and resolve traffic could delay the guard's probes into `unknown`. Task 21b (user-approved): the guard has its own client; the store, master key and pod verification share one limiter set by `kubernetes.qps`/`burst` (default 50/100); each resolve's Kubernetes calls are bounded by 20 s and answer 503 `kubernetes_unavailable` on timeout.
CI: the `ci` job had failed on every PR since #2 because golangci-lint-action's prebuilt v2.4.0 binary is built with Go 1.25 and refuses this Go 1.26 module (lint was only ever run locally). `ci.yml` now sets `install-mode: goinstall`, so the same v2.4.0 is built with go.mod's toolchain.
Task reviews: Task 19 approved after fix round 1 (4 addressed). Task 20 approved after fix round 1 (Content-Length, owner mismatch maps to `decrypt_failed`, token pod identity on `resolve_denied`, HTTP/1.1-only ruling). Task 21 approved with no Critical or Important findings; 6 Minor parked for the final review. Task 21b approved, 4 Minor parked. Fresh-eyes over the whole slice: 1 Important (the throttling, fixed by Task 21b), 9 Minor parked or fixed (evidence wording).

**Checkpoint (controller, after the last task; implementers ignore):** run validation, paste evidence, open PR(s), STOP for go-ahead.

---

## Slice 7: CI tiers 1 and 2 with a journey catalog
**Goal:** Every PR push and merge-queue entry runs lint, unit and chart tests, the kind suite against real Keycloak and the policy matrix per Kubernetes version, all from one pins file, and the catalog check fails any gap that claims to be covered.
**Repos / branches:** nebari-user-secrets: `feat/us-07-ci` (base: `feat/us-06-resolve`)
**PRs:** nebari-user-secrets#8 "CI tiers 1 and 2 with a journey catalog" (links both specs + plan)
**Depends on:** Slice 6
**Contracts touched:** Pins file `ci/pins.env`, Journey catalog `test/journeys/catalog.yaml`, Required check names, Make targets for the kind tiers, Static JWKS server in `e2e-keycloak` (expand), Static JWKS server in `e2e-keycloak` (migrate), Static JWKS server in `e2e-keycloak` (contract)
**Docs updated:** docs/architecture/contracts.md, docs/architecture/patterns.md (Bash cluster harnesses behind Make targets, External versions pinned once, Vendored upstream files with SOURCE and drift check), docs/ci/coverage.md
**Advances journeys:** 1, 7
**Advances CI journeys:** C1 (catalog half), C2 (tiers 1 and 2), C3, C4, C5
**Validation:**
| Step | Command / action | Expected |
|---|---|---|
| unit | `go test ./... -race -cover` | pass, including `test/journeys/catalog` (`TestRepoCatalog` validates the real catalog, spec, test sources and workflows) |
| lint | `GOTOOLCHAIN=go1.26.11 make lint` | 0 issues |
| gap cases (C3) | `go test ./test/journeys/catalog -run 'TestValidate|TestPinsMatchSources|TestScanWorkflowSecrets' -v` | each failure case in C3 and C1 is its own passing table row |
| coverage doc | `make coverage-doc && git diff --exit-code docs/ci/coverage.md` | no diff |
| e2e | `make e2e-up && make e2e-test` | all pass; `grep -rn 'jwks\|KID=' test/e2e` finds nothing; setup log shows Keycloak ready |
| policy | `make policy-test K8S_VERSION=v1.30.13` (repeat for v1.32.11, v1.34.3) | `RESULT: ... 0 failed` for each |
| pin edit (C4) | set `CALICO_VERSION=v3.32.2` in `ci/pins.env` only, `make e2e-up`, then revert | setup log reads `installing Calico v3.32.2` |
| CI | push the branch and open PR #8 | checks `tier1`, `tier2-e2e`, `tier2-policy (v1.30.13)`, `tier2-policy (v1.32.11)`, `tier2-policy (v1.34.3)` pass; each summary shows the SHA, every pin and the tier's check statuses |

### Task 22: Pins file and its readers

**Files:**
- Create: `ci/pins.env`, `test/journeys/catalog/pins.go`, `test/journeys/catalog/pins_test.go`
- Modify: `Makefile`, `Dockerfile`, `hack/kind.sh`, `test/e2e/setup.sh`, `test/policy/run-all.sh`, `.github/workflows/ci.yml`

**Interfaces:**
- Produces: package `catalog` (`github.com/nebari-dev/nebari-user-secrets/test/journeys/catalog`): `type Pins map[string]string`; `func LoadPins(r io.Reader) (Pins, error)`; `func (p Pins) Require(keys ...string) error`.

- [ ] **Step 1: Write `TestLoadPins`** (table): comments and blank lines are skipped; `KEY=value` parses; a duplicate key, a line without `=`, a lowercase key, and a value containing `$(`, a backtick or `${` each return an error naming the line number; `POLICY_K8S_VERSIONS=v1.30.13 v1.32.11 v1.34.3` keeps its spaces. `Require("MISSING")` errors with the key name.
- [ ] **Step 2: Write `TestPinsMatchSources`** against the real repo: `PAUSE_IMAGE` equals `guard.PauseImage`; the Dockerfile's `ARG GO_BUILDER_IMAGE=` default equals the pin; every `nebari-dev/action-nebari-sandbox@<ref>` in `.github/workflows/*.yml` equals `SANDBOX_ACTION_REF` (none until Slice 8); no file outside `ci/pins.env`, `docs/`, `*.md`, `go.sum`, `test/policy/results/` and `test/e2e/fixtures/nic/` contains any pin value except those three cross-checked sources. Run: FAIL (no `ci/pins.env`).
- [ ] **Step 3: Write `ci/pins.env`** with exactly the keys in the spec's Pins table (`KEYCLOAK_IMAGE` arrives in Task 24), each preceded by a `#` line naming its source. `GO_BUILDER_IMAGE` is `golang:1.26@sha256:<digest>` read with `docker buildx imagetools inspect golang:1.26` (the multi-arch index digest).
- [ ] **Step 4: Readers.** Scripts `set -a; source "$ROOT/ci/pins.env"; set +a` and drop their own version variables. `run-all.sh` loops over `${K8S_VERSION:-$POLICY_K8S_VERSIONS}`. Makefile: `include ci/pins.env` and `export`, `image-load`/`image` pass `--build-arg GO_BUILDER_IMAGE=$(GO_BUILDER_IMAGE)`, `policy-test` passes `K8S_VERSION`. Dockerfile: `ARG GO_BUILDER_IMAGE=<pin>` before `FROM --platform=$BUILDPLATFORM ${GO_BUILDER_IMAGE} AS builder`. `ci.yml`: a first step in each job appends `grep -v '^#' ci/pins.env | grep .` to `$GITHUB_ENV`; helm, kind and golangci-lint versions read `env.*`.
- [ ] **Step 5: Run** `go test ./test/journeys/catalog -race -v`, `make e2e-up && make e2e-test`, `make policy-test K8S_VERSION=v1.34.3`: PASS.

### Task 23: Journey catalog, validator and coverage doc

**Files:**
- Create: `test/journeys/catalog.yaml`, `test/journeys/catalog/{catalog.go,index.go,spec.go,coverage.go,workflows.go,catalog_test.go}`, `docs/ci/coverage.md`
- Modify: `Makefile` (`coverage-doc`)

**Interfaces:**
- Consumes: `Pins`, `LoadPins` (Task 22).
- Produces: `Catalog`, `Feature`, `Journey`, `Check` exactly as the CI spec's Data models (json tags `id`, `title`, `source`, `status`, `feature`, `checks`, `tier`, `tests`, `reason`, `until`, `platform_checks`); `func Load(r io.Reader) (*Catalog, error)` (sigs.k8s.io/yaml, unknown fields rejected); `type TestIndex interface{ Has(tier int, name string) bool }`; `func NewSourceIndex(root string) (*SourceIndex, error)`; `func (c *Catalog) Validate(index TestIndex, specJourneys []string) []error`; `func SpecJourneyIDs(spec io.Reader) ([]string, error)`; `func RenderCoverage(c *Catalog, w io.Writer) error`; `func ScanWorkflowSecrets(files map[string][]byte) []error`.

- [ ] **Step 1: Write `TestValidate`** (table, fake `TestIndex`): a valid catalog gives no errors; each of these gives exactly one error naming the check or journey id: `covered` check whose test the index lacks; `covered` with no tests; `planned` or `not-covered` with empty `reason`; `planned` with empty `until`; a spec journey id absent from the catalog; a catalog journey absent from the spec; an `active` feature with no journey; a journey naming an unknown feature; tier outside 1-3; a duplicate check id.
- [ ] **Step 2: Write `TestSourceIndex`** over a temp tree: tier 1 finds `func TestX(t *testing.T)` in `_test.go` files with no `//go:build` line; tier 2 finds tests in files with `//go:build e2e` or `//go:build integration`, and a name of the form `run.sh:<label>` when `test/policy/run.sh` contains `<label>`; tier 3 finds tests in files with `//go:build journeys`; a test in the wrong tier's file is not found.
- [ ] **Step 3: Write `TestScanWorkflowSecrets`**: `${{ secrets.FOO }}` errors naming file and line; `${{ secrets.GITHUB_TOKEN }}` and `github.token` pass.
- [ ] **Step 4: Write `TestRepoCatalog`**: loads `test/journeys/catalog.yaml`, `SpecJourneyIDs` of `docs/design/user-secrets-spec.md`, `NewSourceIndex` of the repo root and every `.github/workflows/*.yml`; asserts no errors from `Validate` and `ScanWorkflowSecrets`, and that `docs/ci/coverage.md` equals `RenderCoverage` output byte for byte (message: run `make coverage-doc`). Run all four: FAIL (no implementation).
- [ ] **Step 5: Implement** the package; `SourceIndex` uses `go/parser` with `parser.ParseComments` and reads the `//go:build` constraint via `go/build/constraint`.
- [ ] **Step 6: Write `catalog.yaml`** from the CI spec's Features table and Journeys-and-checks table, statuses as at Slice 7: `J1.3` and `P3.1` are `planned`, `until: Slice 8`, tests `TestManagementOnNebari` and `TestChartConvergesOnNebari`; every `covered` check names the existing test functions (for example J1.1 `TestManagementCreateList`, J7.1 `TestCrossUserIsolation`, J7.2 and J15.1 `run.sh:<section labels>`, J9.1 `TestDurabilityAcrossRestart` and `TestDurabilityThroughResolve`). `make coverage-doc` runs `go run ./test/journeys/cmd/coverage > docs/ci/coverage.md` (a 10-line `main` calling `RenderCoverage`; add the file). Generate the doc.
- [ ] **Step 7: Run** `go test ./test/journeys/... -race -v`: PASS. Temporarily rename `TestCrossUserIsolation` and confirm `TestRepoCatalog` fails naming `J7.1`; restore.

### Task 24: Real Keycloak in the kind tier

**Files:**
- Create: `test/e2e/fixtures/keycloak/realm.json`, `test/e2e/fixtures/keycloak/keycloak.yaml`
- Delete: `test/e2e/fixtures/jwks.yaml`
- Modify: `ci/pins.env` (`KEYCLOAK_IMAGE`), `test/e2e/setup.sh`, `test/e2e/fixtures/values.yaml`, `test/e2e/helpers_test.go`, `test/e2e/e2e_test.go`, `test/journeys/catalog.yaml` if a test name changes

**Interfaces:**
- Consumes: pins (Task 22).
- Produces: e2e helper `func userToken(t *testing.T, user, client string) string` (password grant), replacing the local-key token minter; users `alice` and `bob`, clients `user-secrets-e2e` (public, direct grants, the service's `clientID`) and `other-client` (direct grants) in realm `nebari`.

- [ ] **Step 1: Pin `KEYCLOAK_IMAGE`** to the Keycloak version NIC v0.18.0 deploys (read `pkg/argocd/templates/apps/keycloak*.yaml` at tag `v0.18.0` with `gh api`), as `quay.io/keycloak/keycloak:<tag>@sha256:<digest>`; the comment names the file read.
- [ ] **Step 2: Fixtures.** `realm.json` (import at start, `--import-realm`); `keycloak.yaml`: Deployment in `e2e-keycloak` (`start-dev` with `KC_HOSTNAME=https://keycloak.e2e-keycloak.svc:8443` and `KC_HOSTNAME_STRICT=true` so `iss` is the in-cluster URL however the token is fetched), Service on 8443, and a cert-manager `Certificate` from NIC's CA issuer, so the service trusts Keycloak through the trust bundle as in production. Test passwords live in `realm.json`; they are fixture values, not secrets.
- [ ] **Step 3: `setup.sh`** replaces `gen_key` and `install_jwks` with `install_keycloak` (apply, wait for Ready, then poll the realm's `.well-known/openid-configuration` from a pod until it answers). `values.yaml`: issuer `https://keycloak.e2e-keycloak.svc:8443/realms/nebari`, JWKS URL that realm's `protocol/openid-connect/certs`, `clientID: user-secrets-e2e`.
- [ ] **Step 4: Helpers.** `userToken` requests `grant_type=password` from inside the cluster, using the same in-cluster exec method the management tests already use to reach the service. Every caller of the old minter moves to it: `TestManagementRejectsOtherClient` uses `other-client`, and `TestCrossUserIsolation` uses `alice` and `bob`. The network test's control target becomes `keycloak.e2e-keycloak.svc:8443`.
- [ ] **Step 5: Run** `make e2e-up && make e2e-test`: all pass. `grep -rn 'jwks\|KID=' test/e2e` returns nothing. `go test ./test/journeys/...` passes.

### Task 25: Tier workflows and job summaries

**Files:**
- Create: `test/journeys/catalog/summary.go`, `test/journeys/catalog/summary_test.go`, `test/journeys/cmd/summary/main.go`
- Modify: `.github/workflows/ci.yml`, `internal/testkube/testkube.go`, `test/policy/run.sh`, `test/policy/run-all.sh`, `docs/architecture/contracts.md`, `docs/architecture/patterns.md`

**Interfaces:**
- Consumes: `Catalog`, `Pins` (Tasks 22-23).
- Produces: `type Results map[string]string` (test name -> `pass`|`fail`|`skip`); `func ParseTestJSON(r io.Reader) (Results, error)` (top-level tests only, from `go test -json`); `type NICInfo struct{ Tag, Commit string; Blocking bool }`; `type SummaryInput struct{ Tier int; Commit, QueueHead, QueueBase string; Results Results; NIC *NICInfo; Timing, Resources, Note string }`; `func RenderSummary(c *Catalog, pins Pins, in SummaryInput, w io.Writer) error`. `cmd/summary` flags `--tier --commit --queue-head --queue-base --results --nic-tag --nic-commit --blocking --timing --resources --note`, appends to `$GITHUB_STEP_SUMMARY`.

- [ ] **Step 1: Write `TestRenderSummary`** (table): output contains the commit, and for `merge_group` input the queue head and base; a row for every pin key with its value; for the tier, each covered check with `pass`/`fail` from Results, and `not run` when its test is absent from Results; every `planned` and `not-covered` check of that tier with its reason; tier 3 input adds the NIC tag and commit and `BLOCKING` or `NON-BLOCKING`, and the timing and resource text verbatim; a `Note` (the `merge_group` skip line) is printed verbatim at the top. `TestParseTestJSON`: pass, fail, skip, and subtests ignored.
- [ ] **Step 2: Run:** FAIL. **Step 3: Implement.** Markdown tables; nothing from the environment is read inside `RenderSummary`.
- [ ] **Step 4: `ci.yml`.** Triggers `pull_request`, `merge_group`, `push: tags: ['v*']`, `workflow_dispatch`. Jobs: `pins` (outputs `k8s` = `POLICY_K8S_VERSIONS` as a JSON array); `tier1` (load pins, lint with `install-mode: goinstall`, `make test`, summary); `tier2-e2e` (`make e2e-up`, `go test -tags e2e ./test/e2e/... -json -count=1 -timeout 30m | tee e2e.json`, then `go test -tags integration ./internal/... -json -count=1 | tee integration.json` against the same cluster (`internal/testkube` reads the kubeconfig path from `USER_SECRETS_TEST_KUBECONFIG` when set, default `.kube/kind` unchanged; the job sets it to `.kube/e2e`), the existing failure dump, summary with `--results` given both files, merged); `tier2-policy` with `name: tier2-policy (${{ matrix.k8s }})`, matrix `fromJSON(needs.pins.outputs.k8s)`, `make policy-test K8S_VERSION=${{ matrix.k8s }}`, summary. Every summary step is `if: always()`. `permissions: contents: read`; no `secrets.` anywhere.
- [ ] **Step 4b: Make the policy matrix fail.** Today it cannot: `run.sh` ends with `echo "RESULT: ..."` and exits 0 whatever `FAIL` is, and `run-all.sh` pipes each run into `tail` (losing its status) and `continue`s past a failed cluster create. `run.sh` ends with `exit $(( FAIL > 0 ))`; `run-all.sh` uses `set -o pipefail` for the run pipeline, records a failure for a failed cluster create or a non-zero run, still deletes the cluster and runs the remaining versions, and exits 1 at the end if any version failed. Prove it: temporarily invert one `expect` in `run.sh`, run `make policy-test K8S_VERSION=v1.34.3`, see exit 2 from make and `RESULT: 41 passed, 1 failed`; restore and see exit 0.
- [ ] **Step 5: Docs.** `contracts.md` gets entries for Pins file `ci/pins.env`, Journey catalog `test/journeys/catalog.yaml`, Required check names (the five names, and that renaming one is a contract change) and the Make targets' `K8S_VERSION`. `patterns.md` gets the three promoted patterns with the CI spec's promoted wording, `Confirmed: 2026-11-24`.
- [ ] **Step 6: Run** `go test ./test/journeys/... -race -v` and `GOTOOLCHAIN=go1.26.11 make lint`: PASS. The workflow itself is proven by the slice's CI validation row.

**Evidence (2026-11-25, Go 1.26.11 toolchain; pins from `ci/pins.env`: kind us-e2e created fresh on kindest/node:v1.34.3, Calico v3.32.3, cert-manager v1.17.2, trust-manager v0.22.1, Keycloak 26.8.1 by digest, NIC templates at `de81b11`):**
```
$ go test ./... -race -cover          -> every package ok (test/journeys/catalog 95.7%), exit 0
$ GOTOOLCHAIN=go1.26.11 make lint     -> 0 issues.
$ go test ./test/journeys/catalog -run 'TestValidate|TestPinsMatchSources|TestScanWorkflowSecrets' -v
--- PASS: TestValidate (0.00s)
--- PASS: TestScanWorkflowSecrets (0.00s)
--- PASS: TestPinsMatchSources (0.05s)
  (36 PASS lines including every table row; 0 FAIL)
$ make coverage-doc && git diff --exit-code docs/ci/coverage.md   -> no diff
$ make e2e-down && make e2e-up        -> "creating kind cluster us-e2e (kindest/node:v1.34.3, no default CNI)" ...
  "deploying Keycloak (quay.io/keycloak/keycloak:26.8.1@sha256:3f3c5f8e...) with the nebari test realm"
  "waiting for the realm's discovery document from kc-client" ... "ready: KUBECONFIG=.../.kube/e2e", exit 0
$ make e2e-test                        -> 15/15 top-level PASS, 0 FAIL, ok test/e2e 127.8s; 0 "lost connection to pod"
$ grep -rn 'jwks\|KID=' test/e2e       -> only test/e2e/fixtures/values.yaml:12 keycloak.jwksURL (the chart key, pointing at Keycloak's certs endpoint)
$ sed CALICO_VERSION=v3.32.2 in ci/pins.env only; make e2e-up   -> "==> installing Calico v3.32.2", exit 0; reverted, git diff ci/pins.env empty
$ make policy-test K8S_VERSION=v1.30.13 -> RESULT: 42 passed, 0 failed (exit 0)
$ make policy-test K8S_VERSION=v1.32.11 -> RESULT: 42 passed, 0 failed (exit 0)
$ make policy-test K8S_VERSION=v1.34.3  -> RESULT: 42 passed, 0 failed (exit 0); all three transcripts in test/policy/results refreshed
Task 25 Step 4b (implementer run): one expect inverted -> RESULT: 41 passed, 1 failed, make exit 2; restored -> 42 passed, exit 0
$ go test -tags integration ./internal/... with USER_SECRETS_TEST_KUBECONFIG=.kube/e2e (implementer run) -> 144 pass, 0 fail
CI (PR #8, run https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45629281918, commit 1c3d13a): pins pass 4s; tier1 pass 3m25s; tier2-e2e pass 8m03s (setup logged "deploying Keycloak" and "ready";
  15 e2e + 144 integration top-level tests pass, 0 fail); tier2-policy (v1.30.13) pass 1m39s, (v1.32.11) pass 1m28s, (v1.34.3) pass 1m46s,
  each log "Server Version: <version>" and "RESULT: 42 passed, 0 failed"; each policy job ran "Drop committed transcript" first.
```
Found during the slice: the guard e2e tests' port-forwards failed about 1 run in 12 with "lost connection to pod", already on Slice 6. With keep-alives off, each 500 ms poll's TLS close_notify reached the pod after the server had closed, so the pod sent a TCP reset; containerd v2.2.0 reports such a reset as a forward error, and client-go then closes the whole forward. The pod-pinned guard forwards now reuse one connection (0 failures in 12 runs on the investigation's loop, 6 of 6 after the fix, and the fresh-cluster run above); the management client through the Service keeps one connection per request. The policy matrix could never fail before Task 25 Step 4b (`run.sh` always exited 0 and `run-all.sh` piped into `tail`).
Task reviews: Task 22 approved (0 Critical/Important). Task 23 approved; the catalog found the CI spec over-claiming coverage (J17, J20, J21 and integration tests no tier ran), corrected by ruling. Task 24 approved, plus fix round 1 (port-forward keep-alive). Task 25 approved, 7 Minor parked for the final review.

**Checkpoint (controller, after the last task; implementers ignore):** run validation, paste evidence, open PR(s), STOP for go-ahead.

---

## Slice 8: Tier 3 on a real Nebari and the turn-on report
**Goal:** Merge-queue, tag and manual runs install the chart through Argo CD on the latest released NIC and run the Nebari journeys, non-blocking until a NIC release contains #787 and blocking by itself after, and the user has a measured report before changing the ruleset.
**Repos / branches:** nebari-user-secrets: `feat/us-08-tier3` (base: `feat/us-07-ci`)
**PRs:** nebari-user-secrets#9 "Tier 3 journeys on Nebari and turn-on report" (links both specs + plan)
**Depends on:** Slice 7
**Contracts touched:** Required check names, Journey catalog `test/journeys/catalog.yaml`, Consumed: deploy-nebari-action v0.3.0 inputs and outputs, Consumed: NIC root App-of-Apps reads `apps/*.yaml` in the GitOps dir, Consumed: NIC cluster CA and trust bundle
**Docs updated:** docs/architecture/contracts.md, docs/ci/coverage.md, docs/ci/turn-on-report.md
**Advances journeys:** 1
**Advances CI journeys:** C1 (fork PR), C2 (tier 3), C6, C7, C8
**Validation:**
| Step | Command / action | Expected |
|---|---|---|
| unit | `go test ./... -race -cover` | pass, including `test/journeys/gate` |
| lint | `GOTOOLCHAIN=go1.26.11 make lint` | 0 issues |
| PR checks | push and open PR #9 | `tier3` reports skipped; Slice 7's checks pass |
| proof run (C6) | `gh workflow run journeys.yml --ref ci/tier3-proof-787` on the scratch branch of Task 28 | `TestChartConvergesOnNebari` and `TestManagementOnNebari` pass; summary shows `nebari-ca-issuer`, Application `Synced`/`Healthy`, timing and resource reports |
| release run (C6, C7) | `gh workflow run journeys.yml --ref feat/us-08-tier3` | summary reads `NON-BLOCKING`, NIC tag `v0.18.0` (or later) and its commit; job exits 0 |
| fork PR (C1) | with the user's approval, a PR from a fork against `feat/us-08-tier3` | every required check reports without secrets; `tier3` skipped |
| ruleset (C8) | `gh api repos/nebari-dev/nebari-user-secrets/rulesets` before and after the slice | identical |
| report (C8) | read `docs/ci/turn-on-report.md` | every section the CI spec lists, with measured numbers labelled by run |

### Task 26: NIC release gate

**Files:**
- Create: `test/journeys/gate/gate.go`, `test/journeys/gate/gate_test.go`, `test/journeys/cmd/nicgate/main.go`

**Interfaces:**
- Produces: `type ReleaseAPI interface { LatestRelease(ctx context.Context) (tag, commit string, err error); Contains(ctx context.Context, tag, commit string) (bool, error) }`; `func NewGitHubAPI(c *http.Client, baseURL, repo, token string) *GitHubAPI`; `type Decision struct{ Tag, Commit string; Blocking bool }`; `func Decide(ctx context.Context, api ReleaseAPI, required string, attempts int, backoff time.Duration) (Decision, error)`. `cmd/nicgate` reads `NIC_REQUIRED_COMMIT`, `GITHUB_TOKEN` and writes `blocking`, `nic-tag`, `nic-commit` to `$GITHUB_OUTPUT`; exit 1 when `Decide` errors.

- [ ] **Step 1: Write `TestDecide`** (table, fake API): compare `behind` gives non-blocking with the tag; `ahead` and `identical` give blocking; `diverged` gives non-blocking; two transient errors then success decides with 3 attempts; three errors return an error (no guess either way). **`TestGitHubAPI`** with `httptest`: `GET /repos/<repo>/releases/latest` then `GET /repos/<repo>/commits/<tag>` for the commit; `GET /repos/<repo>/compare/<required>...<tag>` maps `status`; the `Authorization: Bearer <token>` header is sent (unauthenticated calls hit the 60/hour limit); a 403 or 5xx is an error.
- [ ] **Step 2: Run:** FAIL. **Step 3: Implement** with `net/http` and `encoding/json`; `Contains` is true for `ahead` or `identical`. **Step 4: Run** `go test ./test/journeys/gate -race -v`: PASS.

### Task 27: Tier 3 workflow and the first Nebari journeys

**Files:**
- Create: `.github/workflows/journeys.yml`, `test/journeys/gitops/user-secrets.yaml`, `test/journeys/gitops/user-secrets-cluster.yaml`, `test/journeys/gitops/values-nebari.yaml`, `test/journeys/seed-keycloak.sh`, `test/journeys/nebari_test.go`, `test/journeys/helpers_test.go`
- Modify: `test/journeys/catalog.yaml` (test names exist now; status stays `planned` until Task 28), `docs/ci/coverage.md`, `Makefile` (`journeys-test`), `docs/architecture/contracts.md`

**Interfaces:**
- Consumes: `cmd/nicgate` (Task 26), `cmd/summary` (Task 25), pins `SANDBOX_ACTION_REF`.
- Produces: tests `TestChartConvergesOnNebari` (P3.1) and `TestManagementOnNebari` (J1.3) under `//go:build journeys`, reading `KUBECONFIG`, `NEBARI_DOMAIN`, `KEYCLOAK_ISSUER` and `JOURNEY_USER`/`JOURNEY_PASSWORD` from env.

- [ ] **Step 1: Tests.** `TestChartConvergesOnNebari`: Applications `user-secrets` and `user-secrets-cluster` are `Synced` and `Healthy`; the Deployment is Available; the serving `Certificate` is Ready with `issuerRef` `ClusterIssuer/nebari-ca-issuer`; its `ca.crt` chains to the trust bundle ConfigMap's root; `user-secrets-guard-state` reads `verified` within 2 minutes. `TestManagementOnNebari`: the seeded user's password-grant token for client `user-secrets-journeys` stores and lists `vendor_key` with its binding, through a pod in the landing namespace carrying the frontend labels (the same reach method as `test/e2e`).
- [ ] **Step 2: GitOps.** `user-secrets.yaml` is an Argo CD Application in the form the sandbox's README documents for `add-software-pack` (`repoURL` from `${GITOPS_DIR}`), Helm values from `values-nebari.yaml` plus `image.tag` set to `ci-${GITHUB_SHA}` with `pullPolicy: IfNotPresent`, issuer from the sandbox's `keycloak-issuer-url`, `clientID: user-secrets-journeys`, registry app `test-consumer`. `user-secrets-cluster.yaml` deploys `cluster/` with kustomize, sync-wave after the chart.
- [ ] **Step 3: `seed-keycloak.sh`.** Uses the `keycloak-realm-admin-password` output to create client `user-secrets-journeys` (public, direct grants) and one user with a random password generated in the job and masked with `::add-mask::`. It writes `JOURNEY_USER` and `JOURNEY_PASSWORD` to `$GITHUB_ENV`.
- [ ] **Step 4: `journeys.yml`.** Same four triggers as `ci.yml`, plus job `tier3` with `if: github.event_name != 'pull_request'` and `timeout-minutes: 90`. Steps:
  1. Load pins.
  2. `nicgate` (id `gate`).
  3. Define `run` as `steps.gate.outputs.blocking == 'true' || github.event_name != 'merge_group'`.
  4. Behind `if: run`: sandbox `nebari-dev/action-nebari-sandbox@<SANDBOX_ACTION_REF>` with `nic-version: ${{ steps.gate.outputs.nic-tag }}`, `in-cluster-dns: true`, `timing-report: true`, `resource-summary: true`; `docker build` with the pinned builder and `kind load docker-image` into `kind-<cluster-name>`; seed; `add-software-pack` twice; a convergence step (every Application `Synced`/`Healthy`, 10-minute bound); then `go test -tags journeys ./test/journeys/... -json | tee journeys.json`.
  5. Each of those steps has `continue-on-error: ${{ steps.gate.outputs.blocking != 'true' }}`.
  6. A summary step (`if: always()`) passes the NIC outputs, `--blocking`, the timing and resource reports, and, when skipped in `merge_group`, `--note` with the line `Tier 3 skipped in the merge queue: NIC <tag> does not contain #787 (non-blocking)`.
  7. A last step fails the job when blocking and any earlier step failed.
- [ ] **Step 5: Run** `go vet -tags journeys ./test/journeys/...` and `go test ./test/journeys/... -race`: PASS. `TestRepoCatalog` passes with the new test names and the sandbox ref cross-check. Update `contracts.md` with the two consumed sandbox and App-of-Apps entries as used.

#### Task 27 rework: move Tier 3 to deploy-nebari-action (user decision 2026-11-25)

The first proof runs showed `action-nebari-sandbox` v3.0.0 cannot deploy NIC v0.15.0 or later: its `wait-platform.sh` requires namespace `metallb-system`, which NIC removed in #640 (first in v0.15.0), and its `git clone --branch=<ref>` (`scripts/install-nic.sh:189`) cannot fetch a commit sha. The sandbox is deprecated in favour of `deploy-nebari-action` (sandbox issue #102), whose v0.3.0 CI deploys NIC v0.18.0 on kind daily.

**Files:**
- Create: `test/journeys/nic-config.yaml`, `test/journeys/register-app.sh`
- Modify: `ci/pins.env` (`SANDBOX_ACTION_REF` becomes `DEPLOY_ACTION_REF=v0.3.0`), `test/journeys/catalog/pins_test.go` (the ref cross-check follows the new key and action), `.github/workflows/journeys.yml`, `test/journeys/gitops/*.yaml`, `test/journeys/seed-keycloak.sh`, `docs/architecture/contracts.md`, the CI spec and this plan's copied CI sections (deploy action, pins table, Tier 3 job outline, contracts row, call stack)

**Interfaces:**
- Consumes: `nebari-dev/deploy-nebari-action@v0.3.0` inputs `config`, `nic-version`, `wait`, `destroy`; outputs `kubeconfig`, `domain`, `keycloak-issuer-url`, `keycloak-admin-password` (`action.yml:20-149` at v0.3.0). NIC's local repository provider keeps the GitOps repo at `~/.nic/gitops/<project_name>` (`default-config.yaml:5-6`) and the root App-of-Apps reads `apps/*.yaml` there.
- Produces: `register-app.sh <app-name> <chart-source-dir> <application.yaml>` copies the chart into `<gitops>/<app-name>/`, renders the Application with `envsubst` (`${GITOPS_DIR}`) into `<gitops>/apps/<app-name>.yaml`, commits, requests a refresh of `nebari-root`, and waits for the Application to exist (bounded).

- [ ] **Step 1:** `nic-config.yaml`: `project_name` fixed, `domain: nebari.local`, `certificate.type: selfsigned`, `cluster.local`, `repository.local` (the action's default config plus a fixed project name the workflow uses for the kind cluster and GitOps path).
- [ ] **Step 2:** `journeys.yml`: the deploy action replaces the sandbox, with `nic-version` from the gate's `nic-tag` and `wait: true`; image load with the pinned kind into cluster `<project_name>`; seeding from `keycloak-admin-password`; `register-app.sh` twice in place of `add-software-pack`; the convergence step and the journeys as before. The timing and resource reports come from a step of our own (step durations, `free`, `df`, pod requests against node allocatable) appended to the summary, since the deploy action has none.
- [ ] **Step 3:** `go test ./test/journeys/... -race`, `go test ./... -race`, `GOTOOLCHAIN=go1.26.11 make lint`, actionlint, shellcheck: pass. `TestPinsMatchSources` checks `DEPLOY_ACTION_REF` against every `nebari-dev/deploy-nebari-action@` ref.

Task 28 Step 2 changes accordingly: the scratch branch adds a `push` trigger for itself (a workflow not on the default branch cannot be dispatched before its first run) and fixes the gate outputs; the deploy action fetches the sha itself.

### Task 28: Proof run and turn-on report

**Files:**
- Create: `docs/ci/turn-on-report.md`
- Modify: `test/journeys/catalog.yaml` (`J1.3`, `P3.1` to `covered`), `docs/ci/coverage.md`

- [ ] **Step 1: Ruleset before.** Save `gh api repos/nebari-dev/nebari-user-secrets/rulesets` and each ruleset's detail to the report's appendix.
- [ ] **Step 2: Proof run (controller only; user-approved).** Create scratch branch `ci/tier3-proof-787` from `feat/us-08-tier3`. On it, edit `journeys.yml` only: the gate step is replaced by fixed outputs `nic-tag: de81b1131fbe26fca289f841347d84af727f692f`, `blocking: true`. Push, `gh workflow run journeys.yml --ref ci/tier3-proof-787`, wait, save the summary, `timing-report` and `resource-summary`. Delete the branch afterwards. It is never merged or opened as a PR.
- [ ] **Step 3: Release run.** `gh workflow run journeys.yml --ref feat/us-08-tier3`; save the summary (`NON-BLOCKING`, bring-up timing up to our install).
- [ ] **Step 4: Flip** `J1.3` and `P3.1` to `covered` only if Step 2 passed both tests; regenerate `coverage.md`.
- [ ] **Step 5: Write the report.** Sections exactly as the CI spec's "Report before turning anything on":
  - **Merge queue:** the proposed ruleset JSON, with the five required checks plus `tier3`, squash, and build concurrency and batch size from the numbers.
  - **Stacking:** the retarget behaviour, with a GitHub docs link, marked "to be observed at the first stack merge".
  - **Tier 3 time and size:** from both runs, labelled by run.
  - **Queue throughput:** the formula with the measured numbers.
  - **Runner fit:** memory and disk against 16 GB and 14 GB, from the workflow's own resource step (a snapshot after the journeys, not a peak).
  - **Appendix:** the unchanged ruleset.
- [ ] **Step 6: Ruleset after.** The same `gh api` output is identical to Step 1.

**Evidence (2026-11-26, Go 1.26.11 toolchain; Tier 3 on `ubuntu-latest` with `nebari-dev/deploy-nebari-action@v0.3.0`):**
```
$ go test ./... -race -cover -count=1  -> every package ok, exit 0 (test/journeys/gate included)
$ GOTOOLCHAIN=go1.26.11 make lint       -> 0 issues (build tags e2e and journeys)
$ go vet -tags journeys ./test/journeys/... ; actionlint .github/workflows/*.yml ; shellcheck test/journeys/*.sh -> clean
$ make coverage-doc && git diff --exit-code docs/ci/coverage.md -> no diff (19 of 37 journey checks covered; J1.3, P3.1 covered)
$ go test ./internal/httpapi -run TestResolveBodyEndsBeforeStatusWrite -count=1000 -race -cpu 1,2,4 -> ok (was 6 of 9000 subtests failing)
Proof run (C6), NIC de81b11, scratch branch ci/tier3-proof-787 (push trigger + fixed gate outputs, deleted after):
  https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45651421474 attempt 2: every step success, job 11m26s; deploy 489s; journeys:
  --- PASS: TestChartConvergesOnNebari (Applications user-secrets and user-secrets-cluster Synced/Healthy, Deployment Available,
      Certificate Ready from nebari-ca-issuer, serving cert chains to the trust bundle, guard verified)
  --- PASS: TestManagementOnNebari
Release run (C6, C7), scratch branch ci/tier3-release-run (push trigger only, deleted after):
  https://github.com/nebari-dev/nebari-user-secrets/actions/runs/45796258597: gate NIC_TAG v0.18.0, NIC_COMMIT dfae9f2, BLOCKING false; user-secrets Synced/Degraded (no nebari-ca-issuer);
  "##[warning]Tier 3 failed (NON-BLOCKING until a NIC release contains #787): converge journeys"; job success (exit 0); JOURNEY_PASSWORD shown as ***
Ruleset (C8): gh api .../rulesets and .../rulesets/27031502 on 2026-11-25 and 2026-11-26 -> identical (jq -S diff empty)
Report (C8): docs/ci/turn-on-report.md, every section of the CI spec's list, numbers labelled by run
PR checks, PR #9 (run 45801006121): tier1 pass 4m51s, tier2-e2e pass 6m31s, tier2-policy (v1.30.13/v1.32.11/v1.34.3) pass 1m34s/1m35s/1m28s, tier3 skipping
Fork PR (C1), throwaway draft #10 from dcmcand/nebari-user-secrets (empty commit), run 45801081036: tier1 pass 4m44s, tier2-e2e pass 7m43s,
  tier2-policy pass 1m23s/1m22s/1m26s, tier3 skipping; no repository secrets; PR closed unmerged and the fork branch deleted
```
Found during the slice: `action-nebari-sandbox` v3.0.0 cannot deploy NIC v0.15.0 or later (its readiness wait requires a `metallb-system` namespace NIC removed in #640) and cannot clone a commit sha (`scripts/install-nic.sh:189`); it is deprecated in favour of `deploy-nebari-action` (sandbox #102). By user decision Tier 3 moved to `deploy-nebari-action@v0.3.0` (Task 27 rework). NIC leaves `gateway-config`, `httproutes` and `nebari-root` OutOfSync while Healthy, so convergence requires Synced only for our Applications. One of five deploys failed inside NIC's Argo CD install (attempt 1 of 45651421474). `TestResolveBodyEndsBeforeStatusWrite` (Slice 6) raced on a non-blocking check; with user approval it waits up to 3 s. Job summaries cannot be read through the API, so the timing and resource tables are also printed to the job log.
Task reviews: Task 26 approved after fix round 1 (GITHUB_OUTPUT validation). Task 27 approved after fix round 1 (lint tag, pins row, contracts, pinned kind). Task 27 rework approved after fix round 1 (convergence rule, flake test). Fresh-eyes over the slice: 1 Important (gate failure fails tier3 in every mode: retries hardened to about 2 minutes and the risk documented in the report), 6 Minor fixed (including an envsubst allowlist in register-app.sh), 4 parked.

**Checkpoint (controller, after the last task; implementers ignore):** run validation, paste evidence, open PR(s), STOP for go-ahead.

---

## Slice 9: Init container and env wrapper
**Goal:** A pod with the init container gets its secrets as exact-byte files, optionally as environment variables, and a readable reason when delivery fails.
**Repos / branches:** nebari-user-secrets: `feat/us-09-init` (base: `feat/us-08-tier3`)
**PRs:** nebari-user-secrets#10 "user-secrets-init and user-secrets-env" (links spec + plan)
**Depends on:** Slice 8
**Contracts touched:** File layout under `/var/run/nebari/secrets`, `user-secrets-env -- <cmd>` wrapper behaviour
**Docs updated:** docs/architecture/contracts.md
**Advances journeys:** 13, 17
**Validation:**
| Step | Command / action | Expected |
|---|---|---|
| unit | `go test ./... -race -cover` | pass, `internal/initfiles` coverage at least 90% |
| e2e | `go test -tags e2e ./test/e2e/... -run TestInit -v` | pass |

### Task 29: File writer

**Files:** Create `internal/initfiles/files.go`, `internal/initfiles/files_test.go`

**Interfaces:**
- Produces: `NewFileWriter(dir string) *FileWriter`, `WriteAll([]model.ResolvedSecret) error`, `WriteStatus(string) error` per the spec.

- [ ] **Step 1: Failing tests:** `TestWriteAllExactBytes` (journey 13 bytes `{"k":"a$$b$(HOME){username}"}` + `\n` + `0xff` → identical file, mode `0440`); `TestWriteAllRejectsBadNames` (`LD_PRELOAD`, `NEBARI_SECRET_a`, `NEBARI_SECRET_../x` → not written, error); `TestWriteAllRemovesStale` (Review Focus 4: second run without `NEBARI_SECRET_OLD` removes it, leaves `.status`); `TestWriteIsAtomic` (temp file + rename in the same directory).
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement.** **Step 4: Run**: PASS.

### Task 30: Fetch and the init binary

**Files:** Create `internal/initfiles/fetch.go`, `internal/initfiles/client.go`, `internal/initfiles/fetch_test.go`; Modify `cmd/user-secrets-init/main.go`

**Interfaces:**
- Produces: `Fetch(ctx, c ResolveClient, tokenPath string, w *FileWriter, budget time.Duration) (status string, ok bool)`; `NewHTTPResolveClient(url, caFile string) (*HTTPResolveClient, error)` (TLS 1.2+, verifies against `caFile` and the URL host); `user-secrets-init fetch --url --ca --token --dir --bin-dir --mode soft|strict` copies `/proc/self/exe` to `--bin-dir/user-secrets-env` (mode `0550`) and exits 0, or 1 in strict mode on failure.

- [ ] **Step 1: Failing tests:** `TestFetch` table: 200 → files and `ok <n>`; 503 then 200 → retried with backoff within budget; connection refused until budget → `error unreachable`; 403 `pod_predates_guard` → `error pod_predates_guard` no retry; CA file missing → `error ca_missing`; strict vs soft exit codes in `TestInitMain` (via `exec` of the test binary).
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement** (exponential backoff from 500 ms, cap 5 s, total `budget` 30 s). **Step 4: Run**: PASS.

### Task 31: Env wrapper

**Files:** Create `internal/initfiles/env.go`, `internal/initfiles/env_test.go`; Modify `cmd/user-secrets-init/main.go` (dispatch when `argv[0]` base is `user-secrets-env`)

**Interfaces:**
- Produces: `ExecWithEnv(dir string, argv []string, environ []string, stderr io.Writer) error` per the spec; `syscall.Exec` at the end.

- [ ] **Step 1: Failing tests** (use a `exec` seam variable, table-driven): exports each valid file; never replaces an existing variable; skips a value with a NUL byte and names it on stderr; prints one warning when `.status` starts with `error`; argv after `--` passed unchanged.
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement.** **Step 4: Run**: PASS.
- [ ] **Step 5: e2e** `TestInitDeliversFiles` in `test/e2e/init_test.go`: the Slice 6 hand-built pod now uses the real init image; `sha256sum` in the main container matches the uploaded journey-13 bytes; with the NetworkPolicy blocking `test-consumer`, `.status` reads `error unreachable` and the wrapper prints its warning (journey 17). Update `docs/architecture/contracts.md`.

**Checkpoint (controller, after the last task; implementers ignore):** run validation, paste evidence, open PR(s), STOP for go-ahead.

---

## Slice 10: Injector
**Goal:** A pack that sets only the ServiceAccount, label and annotations gets secrets delivered, and its failure mode decides what happens while the injector is down.
**Repos / branches:** nebari-user-secrets: `feat/us-10-injector` (base: `feat/us-09-init`)
**PRs:** nebari-user-secrets#11 "Injector webhook" (links spec + plan)
**Depends on:** Slice 9
**Contracts touched:** Injector `MutatingWebhookConfiguration` `user-secrets-injector` and its patch, Optional pod metadata (label `nebari.dev/user-secrets-failure`; annotations `nebari.dev/user-secrets-export-env` and `-containers`), Consumer contract (`docs/architecture/contracts.md`), Cluster bundle (`cluster/` with `cluster/REVIEW.md`)
**Docs updated:** docs/architecture/contracts.md, cluster/REVIEW.md
**Advances journeys:** 14, 22, 7, 6
**Validation:**
| Step | Command / action | Expected |
|---|---|---|
| unit | `go test ./... -race -cover` | pass, `internal/inject` table |
| policy | `make policy-test` | all pass with the webhook in the bundle; transcripts refreshed |
| e2e | `go test -tags e2e ./test/e2e/... -run 'TestNewConsumerByValuesOnly|TestInjectorFailureModes|TestCrossUserIsolation' -v` | pass (journeys 14, 22, 7) |

### Task 32: Mutate

**Files:** Create `internal/inject/inject.go`, `internal/inject/inject_test.go`

**Interfaces:**
- Produces: `type Config struct{ InitImage, ResolveURL string; TokenSeconds int64; DefaultFSGroup int64 /*65532*/ }`; `func NewInjector(cfg Config) *Injector`; `(*Injector).Mutate(pod *corev1.Pod) (*corev1.Pod, error)` (input unchanged; returns a deep copy). Volume names `user-secrets-files`, `user-secrets-bin`, `user-secrets-token`, `user-secrets-trust`; init container `user-secrets-init` with `--mode strict` iff the pod has label `nebari.dev/user-secrets-failure: strict`.

- [ ] **Step 1: Failing tests** (`TestMutate` table on real `corev1.Pod` values): unlabelled pod → returned unchanged; KubeSpawner-shaped pod → init container, four volumes, token and trust mounts only in the init container, read-only files and bin mounts in container 0 only; existing `fsGroup: 100` kept, absent → 65532; `user-secrets-containers: "a,c"` mounts into `a` and `c` only, unknown names ignored; export-env with `args` → `args` = wrapper path, `--`, old args (journey 6 half); with `command` set → prepended to `command`; pre-existing `user-secrets-files` volume of another type → replaced; second `Mutate` on the output → deep-equal (idempotent); SA, labels and annotations never change; `TestMutatedPodRestricted` (a restricted-compliant input stays restricted after `Mutate`, pod-security-admission v0.35.0).
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement.** **Step 4: Run**: PASS.

### Task 33: Webhook server and configuration

**Files:** Create `internal/httpapi/webhook.go`, `internal/httpapi/webhook_test.go`, `cluster/webhook.yaml`; Modify `cluster/kustomization.yaml` (resource + replacement for `metadata.annotations.[cert-manager.io/inject-ca-from]` and `webhooks.*.clientConfig.service.namespace`), `cluster/embed.go`, `cmd/user-secrets/serve.go` (`:9443`), `chart/templates/networkpolicy.yaml` (9443 from any source), `cluster/REVIEW.md`

**Interfaces:**
- Produces: `func NewWebhookHandler(i *inject.Injector, log *slog.Logger) http.Handler` wrapping `&admission.Webhook{Handler: admission.HandlerFunc(...)}` (controller-runtime v0.23.1 `pkg/webhook/admission/http.go:64`), decoding the pod, calling `Mutate`, returning `admission.PatchResponseFromRaw(req.Object.Raw, mutatedJSON)` or `admission.Allowed("")`; never a denial (an internal error returns `Allowed` with a warning and is logged). `cluster/webhook.yaml` exactly as the spec's injector configuration table.

- [ ] **Step 1: Failing tests:** `TestWebhookAlwaysAllows` (malformed object → allowed, no patch); `TestWebhookPatch` (labelled pod → patch whose application equals `Mutate`'s output); `TestWebhookYAML` (parsed `cluster/webhook.yaml`: two entries, selectors, failure policies, `sideEffects: None`, `reinvocationPolicy: IfNeeded`, `timeoutSeconds: 5`, rules `pods` `CREATE` only).
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement.** **Step 4: Run** unit and `make policy-test`: PASS; commit refreshed transcripts.

### Task 34: Consumer journeys on kind

**Files:** Create `test/e2e/consumer_test.go`; Modify `test/e2e/fixtures/consumer.yaml` (pods carry only SA, label and annotations now)

- [ ] **Step 1: Write** `TestNewConsumerByValuesOnly` (journey 14: install with `values-consumer.yaml`; a `busybox` pod with only SA, label, annotations and `export-env` created by `tc-creator` prints the expected file and env var; assert `git diff --exit-code -- internal cmd cluster` is empty in CI); `TestInjectorFailureModes` (journey 22: scale the Deployment to 0; a soft pod starts with no `/var/run/nebari/secrets`; a strict pod create is refused; an unlabelled pod starts; scale back); `TestCrossUserIsolation` extended to injected pods.
- [ ] **Step 2: Run** e2e: PASS. Write the consumer contract (ten rules, from the spec) and the injector entries into `docs/architecture/contracts.md`; update `cluster/REVIEW.md` (the webhook YAML now ships).

**Checkpoint (controller, after the last task; implementers ignore):** run validation, paste evidence, open PR(s), STOP for go-ahead.

---

## Slice 11: Release and operations
**Goal:** Operators can install a released version, back up and rotate the master key, and roll the guard out from `[Warn, Audit]` to `[Deny]` by following written steps.
**Repos / branches:** nebari-user-secrets: `feat/us-11-release` (base: `feat/us-10-injector`)
**PRs:** nebari-user-secrets#12 "Release workflow and operations guide" (links spec + plan)
**Depends on:** Slice 10
**Contracts touched:** Master-key Secret `user-secrets-kek` and the `user-secrets admin` commands
**Docs updated:** docs/architecture/contracts.md, docs/operations.md, README.md
**Advances journeys:** 21
**Validation:**
| Step | Command / action | Expected |
|---|---|---|
| release dry run | `goreleaser release --snapshot --clean` | images for both arches and a packaged chart under `dist/` |
| docs | follow `docs/operations.md` "Rotate the master key" on the e2e cluster | `rotate-kek` Job completes; journey 21 e2e `TestKEKRotationDuringStarts` passes |

### Task 35: Release workflow

**Files:** Create `.goreleaser.yml`, `.github/workflows/release.yml`, `.github/workflows/vulncheck.yml`

- [ ] **Step 1:** Mirror nebari-operator's release shape: on tag `v*`, build both binaries for `linux/amd64,arm64`, push `ghcr.io/nebari-dev/nebari-user-secrets:<tag>`, package and push the chart as an OCI artifact, attach `cluster/` as a tarball. `vulncheck.yml` runs `govulncheck ./...` on PRs.
- [ ] **Step 2: Run** `goreleaser release --snapshot --clean`: Expected: `dist/` holds both images' binaries and the chart.

### Task 36: Operations guide and rotation journey

**Files:** Create `docs/operations.md`, `test/e2e/fixtures/rotate-kek-job.yaml`, `test/e2e/rotation_test.go`; Modify `README.md`

- [ ] **Step 1: Write** `docs/operations.md`: install order (chart, then `cluster/` at `[Warn, Audit]`, then `[Deny]`), backing up `user-secrets-kek` apart from the records, `rotate-kek` / `retire-kek` / `rotate-dek` as Jobs (the fixture is the example), the `503 kek_unavailable` recovery (restore the Secret; never delete records), guard override and its meaning, removal order.
- [ ] **Step 2: Write** `TestKEKRotationDuringStarts` (journey 21 end to end: while 5 injected pods start one after another, run the Job; all 5 get `.status ok`; every record names the new id; `retire-kek` Job succeeds) and `TestKEKMissingFailsClosedE2E` (delete the Secret, restart the Deployment; management and resolve return `503 kek_unavailable`; no new `user-secrets-kek` appears).
- [ ] **Step 3: Run** e2e: PASS. Update README status and `docs/architecture/contracts.md`.

**Checkpoint (controller, after the last task; implementers ignore):** run validation, paste evidence, open PR(s), STOP for go-ahead.

---

## Lint result

`python3 -I ~/.claude/skills/program-design-slices/lint-slices.py docs/superpowers/plans/2026-11-20-user-secrets-service.md --spec docs/design/user-secrets-spec.md` exits 1 with exactly five problems, all contracts owned by other repos and out of this plan's scope by decision (2026-11-20). Each is touched by that repo's own plan:

| Contract | Owner repo | Plan that touches it |
|---|---|---|
| Landing nginx `location /api/user-secrets/` → management API | nebari-landing | nebari-landing#236 plan |
| `GET /hub/api/user-secrets/identity` | data-science-pack | data-science-pack consumer plan |
| `c.KubeSpawner.modify_pod_hook` | data-science-pack | data-science-pack consumer plan |
| `server` role scopes | data-science-pack | data-science-pack consumer plan |
| dask-gateway-pack DaskCluster policy | dask-gateway-pack | dask-gateway-pack consumer plan |

Slices 7 and 8 (added 2026-11-24): `python3 -I ~/.claude/skills/program-design-slices/lint-slices.py docs/superpowers/plans/2026-11-20-user-secrets-service.md --spec docs/superpowers/specs/2026-11-24-ci-tiers-design.md` exits 1 with exactly one problem, accepted by decision: `Static JWKS server in e2e-keycloak` is `changed-breaking` but is not split into expand, migrate and contract slices. The producer (`setup.sh`, `fixtures/jwks.yaml`) and every consumer (`fixtures/values.yaml`, `helpers_test.go`, `e2e_test.go`) are test files in this repo that change together in Task 24's single PR, so no intermediate state exists in which a consumer breaks; the slice lists all three phases on Slice 7.
