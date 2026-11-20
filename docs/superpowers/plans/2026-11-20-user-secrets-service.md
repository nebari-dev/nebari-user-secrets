# nebari-user-secrets Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Implementers never commit, push or open PRs; the controller does that at each slice's Checkpoint.

**Goal:** Build the nebari-user-secrets service, init binary, injector, chart and cluster bundle, and prove them end to end on kind with a test consumer.

**Architecture:** One Go module with two binaries (`user-secrets`: management API, resolve API, injector webhook, guard, admin commands; `user-secrets-init`: fetch and env wrapper), `internal/` packages behind interfaces, a Helm chart for the namespaced objects and `cluster/` for the cluster-scoped ones. Delivered as nine stacked slices, each a PR against the previous slice's branch, starting from `docs/user-secrets-design` (nebari-user-secrets#1).

**Tech Stack:** Go 1.26; `k8s.io/{api,apimachinery,client-go}` v0.35.0; `sigs.k8s.io/controller-runtime` v0.23.1 (admission webhook helpers only); `github.com/coreos/go-oidc/v3` v3.21.0; `k8s.io/pod-security-admission` v0.35.0 (tests); `go.opentelemetry.io/otel` v1.45.0; standard library `crypto/aes` and `crypto/cipher`; Helm 3 chart; kind for integration and e2e.

**Spec:** `docs/design/user-secrets-spec.md` (detailed spec, with Program Design) and `docs/design/user-secrets.md` (design), both in nebari-user-secrets.

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
4. **An init container that runs again** (pod sandbox restart) after a secret was deleted. The deleted file must disappear, not linger from the first run. Test `TestWriteAllRemovesStale` in Task 22.
5. **A record at the size limit.** Values of 32768 bytes grow to about 43.7 KB once sealed and base64-encoded, so about 11 fit; acceptance must follow the encoded size, never a plaintext estimate, and the stored record must never exceed 524288 bytes. Test `TestLimitCountsEncodedSize` in Task 9.

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
| 7 | Init container and env wrapper | nebari-user-secrets | nebari-user-secrets#8 | Slice 6 | 13, 17 |
| 8 | Injector | nebari-user-secrets | nebari-user-secrets#9 | Slice 7 | 14, 22, 7, 6 |
| 9 | Release and operations | nebari-user-secrets | nebari-user-secrets#10 | Slice 8 | 21 |

Merge order: nebari-user-secrets#1 (design) -> #2 -> #3 -> #4 -> #5 -> #6 -> #7 -> #8 -> #9 -> #10. Each PR's base is the previous slice's branch.

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
**Contracts touched:** Management API on `:8444` (`/api/v1/secrets`; `/api/v1/apps`; `/api/v1/status`), Creator registry and `user-secrets-creators` ConfigMap, `ClusterIssuer` `nebari-ca-issuer` and ConfigMap `nebari-trust-bundle` (key `ca-certificates.crt`)
**Docs updated:** docs/architecture/contracts.md, docs/architecture/patterns.md (Render-time chart guardrails in a `validate.yaml` template that `fail`s on unsafe values)
**Advances journeys:** 1, 9, 19
**Validation:**
| Step | Command / action | Expected |
|---|---|---|
| unit | `go test ./... -race -cover` | pass |
| chart | `helm lint chart && go test ./test/chart/...` | pass; `TestNoExternalSurface`, `TestNetworkPolicyPorts`, `TestValidateFails` |
| image | `make image` | builds `linux/amd64` and `linux/arm64` |
| e2e | `make e2e-up && go test -tags e2e ./test/e2e/... -run 'TestManagement|TestDurability|TestNetworkExposure' -v` | pass (journeys 1, 9, 19) |

### Task 11: Serve command

**Files:** Create `cmd/user-secrets/serve.go`, `internal/config/config.go`, `internal/config/config_test.go`, `internal/telemetry/telemetry.go`

**Interfaces:**
- Consumes: everything above.
- Produces: `user-secrets serve --config /etc/user-secrets/config.yaml`; `config.Config{ Namespace string; Registry registry.Config; Keycloak struct{ JWKSURL string; Issuers []string; ClientID string }; TLS struct{ CertFile, KeyFile string }; Guard struct{ Mode string /*enforced|unverified*/ }; Limits service.Limits; InitImage string }` loaded and validated by `config.Load(path) (*Config, error)`; `telemetry.Setup(ctx) (shutdown func(context.Context) error, err error)` honouring `OTEL_EXPORTER` (`none` default in-cluster, `otlp`, `console`) like NIC.

- [ ] **Step 1: Failing tests** `TestLoadConfig` table (missing issuer, unknown guard mode, `unverified` logged as warning field, limits default when absent).
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement** `serve`: build the dependency graph per the spec's "Component trees and DI" (only the parts that exist so far), `KubernetesKEK.Bootstrap` before listening (on `ErrKEKUnavailable` serve 503 `kek_unavailable` instead of exiting), TLS server on `:8444` reloading the cert files on change (`tls.Config.GetCertificate` with a file-mtime cache), `/healthz` and `/readyz` on plain `:8080`, graceful shutdown on SIGTERM. **Step 4: Run**: PASS.

### Task 12: Image

**Files:** Create `Dockerfile`, `.dockerignore`; Modify `Makefile` (`image`, `IMG ?= ghcr.io/nebari-dev/nebari-user-secrets:dev`)

- [ ] **Step 1:** Multi-stage like nebari-operator's `Dockerfile` (`golang:1.26` builder, `CGO_ENABLED=0`, both binaries to `/`, `gcr.io/distroless/static:nonroot`, `USER 65532:65532`, `ENTRYPOINT ["/user-secrets"]`). `cmd/user-secrets-init` is a stub `main` printing usage until Slice 7.
- [ ] **Step 2: Run** `make image`: Expected: image builds; `docker run --rm $IMG --help` prints usage.

### Task 13: Helm chart

**Files:** Create `chart/Chart.yaml`, `chart/values.yaml`, `chart/templates/{_helpers.tpl,deployment.yaml,service.yaml,certificate.yaml,configmap.yaml,creators-configmap.yaml,rbac.yaml,networkpolicy.yaml,pdb.yaml,serviceaccount.yaml,validate.yaml}`, `test/chart/chart_test.go`

**Interfaces:**
- Produces values: `registry` (as `registry.Config`), `keycloak.{jwksURL,issuers,clientID}`, `landing.{namespace,podSelector}`, `guard.mode`, `guard.allowSharedNamespace`, `limits`, `image`, `initImage`, `replicas: 2`. Certificate `user-secrets-tls` from `ClusterIssuer nebari-ca-issuer`, `dnsNames` `user-secrets.<ns>.svc` and `.svc.cluster.local`. Service ports `resolve 8443`, `management 8444`, `injector 9443` (target ports declared now; servers added in later slices). NetworkPolicy in this slice: ingress `8444` only from `landing.namespace` + `landing.podSelector`; nothing else. `creators-configmap.yaml` renders `user-secrets-creators` from `registry` with the same key/value encoding as `CreatorsConfigMapData`.

- [ ] **Step 1: Failing tests** in `test/chart` (run `helm template` via `os/exec`, parse with `sigs.k8s.io/yaml`): `TestNoExternalSurface` (no `NebariApp`, `HTTPRoute`, `Ingress`, no `LoadBalancer`/`NodePort` Service); `TestNetworkPolicyPorts` (8444 from the landing selector only); `TestCreatorsConfigMapMatchesGo` (chart output data equals `registry.CreatorsConfigMapData()` for the same values file); `TestValidateFails` table (`helm template` fails when the service namespace is a registered workload or creator namespace without `guard.allowSharedNamespace`; when `allowSharedNamespace` is set without `guard.mode: unverified`; when `keycloak.clientID` is empty); `TestPodSecurityRestricted` (the Deployment's pod passes `policy.NewEvaluator(policy.DefaultChecks(), nil).EvaluatePod` at `restricted`, pod-security-admission v0.35.0 `policy/registry.go:49`, `:67`).
- [ ] **Step 2: Run** `go test ./test/chart/...`: FAIL. **Step 3: Implement** the chart. RBAC per the spec's program layout for what exists now: Role in the service namespace on `secrets` (`get`, `list`, `create`, `update`, `delete`). **Step 4: Run** `helm lint chart && go test ./test/chart/...`: PASS. Write the promoted `validate.yaml` pattern to `docs/architecture/patterns.md`.

### Task 14: End-to-end harness and management journeys

**Files:** Create `test/e2e/setup.sh`, `test/e2e/fixtures/nic-ca.yaml`, `test/e2e/fixtures/jwks.yaml`, `test/e2e/e2e_test.go`, `test/e2e/helpers_test.go` (build tag `e2e`); Modify `Makefile` (`e2e-up`, `e2e-down`), `.github/workflows/ci.yml` (e2e job on kind)

**Interfaces:**
- Produces: `setup.sh` creates kind `us-e2e` (v1.34.3, Calico so NetworkPolicy is enforced), installs cert-manager v1.17.2 and trust-manager v0.22.1, applies `nic-ca.yaml` (a stand-in for #787 until it merges: self-signed `ClusterIssuer`, root CA `Certificate` `nebari-root-ca` in `cert-manager`, `ClusterIssuer nebari-ca-issuer`, `Bundle nebari-trust-bundle` with the root and `useDefaultCAs: false`, matching #787's names), deploys a static JWKS server (`jwks.yaml`, an nginx serving a test key the tests sign with) and installs the chart with `keycloak.jwksURL` pointing at it. Helpers: `signToken(t, sub, azp string) string`, `mgmtClient(t)` (port-forward through a pod in the landing namespace carrying the frontend labels, TLS verified with the trust bundle).

- [ ] **Step 1: Write** `TestManagementCreateList` (journey 1: PUT `vendor_key` → 201, GET lists it with bindings), `TestManagementRejectsOtherClient` (journey 8d: `azp` other → 401), `TestDurabilityAcrossRestart` (journey 9: store, `kubectl rollout restart`, `helm upgrade --reuse-values`, value still resolves through the store and at least one replica answered `/readyz` throughout, polled every 500 ms), `TestNetworkExposure` (journey 19: a pod in a workload namespace cannot connect to 8444 within 3 s; the landing-labelled pod can).
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

### Task 15: Embedded expectation and reader RBAC

**Files:** Create `cluster/embed.go`, `cluster/rbac.yaml`, `internal/guard/expect.go`, `internal/guard/expect_test.go`; Modify `cluster/kustomization.yaml`, `cluster/REVIEW.md`

**Interfaces:**
- Produces: `package cluster` with `//go:embed policies.yaml` → `var Policies []byte`; `type Expectation struct{...}`; `func NewExpectation(namespace string) (Expectation, error)` (applies the same two substitutions as the kustomization); `(Expectation).Compare(p Policies, b Bindings, cm *corev1.ConfigMap, wantCM map[string]string) (ok bool, reason string)`. `cluster/rbac.yaml`: `ClusterRoleBinding` to `system:auth-delegator` and `ClusterRole`/`ClusterRoleBinding` `user-secrets-guard-reader` (`get`, `list`, `watch` on the two policies and two bindings by `resourceNames`), service account namespace substituted by kustomize.

- [ ] **Step 1: Failing tests** `TestCompare` table, one row per confirmed-bad case in the spec's guard bullets (policy spec edited; binding A gains `paramRef`; binding A `matchResources` set; binding B `paramRef` name, namespace or `parameterNotFoundAction` changed; binding B `objectSelector` changed; `validationActions` `[Warn]`, `[Audit]`, `[Warn, Audit]` fail; `[Deny, Audit]` passes; ConfigMap data drift; ConfigMap missing) plus the matching good row; `TestExpectationMatchesKustomize` (runs `kubectl kustomize cluster/` with namespace `us-test` and compares to `NewExpectation("us-test")`).
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement.** **Step 4: Run**: PASS.

### Task 16: Watcher and prober

**Files:** Create `internal/guard/watch.go`, `internal/guard/probe.go`, `internal/guard/probe_test.go`

**Interfaces:**
- Produces: `func NewInformerWatcher(c kubernetes.Interface, namespace string) *InformerWatcher` implementing the spec's `AdmissionWatcher` (field-selector informers by name); `func NewDryRunProber(c kubernetes.Interface, namespace, pauseImage string) *DryRunProber` implementing `Prober`; `type ProbeResult struct{ LabelledDeniedByB, UnlabelledDeniedByA, CanaryAdmitted, Inconclusive bool; Detail string }`. Probe pods are `restricted`-compliant with the pause image pinned by digest (`registry.k8s.io/pause:3.10@sha256:…`, digest filled at implementation time from `crane digest`), and are recognised by the policies' exact messages from `cluster/policies.yaml`.

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

**Checkpoint (controller, after the last task; implementers ignore):** run validation, paste evidence, open PR(s), STOP for go-ahead.

---

## Slice 7: Init container and env wrapper
**Goal:** A pod with the init container gets its secrets as exact-byte files, optionally as environment variables, and a readable reason when delivery fails.
**Repos / branches:** nebari-user-secrets: `feat/us-07-init` (base: `feat/us-06-resolve`)
**PRs:** nebari-user-secrets#8 "user-secrets-init and user-secrets-env" (links spec + plan)
**Depends on:** Slice 6
**Contracts touched:** File layout under `/var/run/nebari/secrets`, `user-secrets-env -- <cmd>` wrapper behaviour
**Docs updated:** docs/architecture/contracts.md
**Advances journeys:** 13, 17
**Validation:**
| Step | Command / action | Expected |
|---|---|---|
| unit | `go test ./... -race -cover` | pass, `internal/initfiles` coverage at least 90% |
| e2e | `go test -tags e2e ./test/e2e/... -run TestInit -v` | pass |

### Task 22: File writer

**Files:** Create `internal/initfiles/files.go`, `internal/initfiles/files_test.go`

**Interfaces:**
- Produces: `NewFileWriter(dir string) *FileWriter`, `WriteAll([]model.ResolvedSecret) error`, `WriteStatus(string) error` per the spec.

- [ ] **Step 1: Failing tests:** `TestWriteAllExactBytes` (journey 13 bytes `{"k":"a$$b$(HOME){username}"}` + `\n` + `0xff` → identical file, mode `0440`); `TestWriteAllRejectsBadNames` (`LD_PRELOAD`, `NEBARI_SECRET_a`, `NEBARI_SECRET_../x` → not written, error); `TestWriteAllRemovesStale` (Review Focus 4: second run without `NEBARI_SECRET_OLD` removes it, leaves `.status`); `TestWriteIsAtomic` (temp file + rename in the same directory).
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement.** **Step 4: Run**: PASS.

### Task 23: Fetch and the init binary

**Files:** Create `internal/initfiles/fetch.go`, `internal/initfiles/client.go`, `internal/initfiles/fetch_test.go`; Modify `cmd/user-secrets-init/main.go`

**Interfaces:**
- Produces: `Fetch(ctx, c ResolveClient, tokenPath string, w *FileWriter, budget time.Duration) (status string, ok bool)`; `NewHTTPResolveClient(url, caFile string) (*HTTPResolveClient, error)` (TLS 1.2+, verifies against `caFile` and the URL host); `user-secrets-init fetch --url --ca --token --dir --bin-dir --mode soft|strict` copies `/proc/self/exe` to `--bin-dir/user-secrets-env` (mode `0550`) and exits 0, or 1 in strict mode on failure.

- [ ] **Step 1: Failing tests:** `TestFetch` table: 200 → files and `ok <n>`; 503 then 200 → retried with backoff within budget; connection refused until budget → `error unreachable`; 403 `pod_predates_guard` → `error pod_predates_guard` no retry; CA file missing → `error ca_missing`; strict vs soft exit codes in `TestInitMain` (via `exec` of the test binary).
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement** (exponential backoff from 500 ms, cap 5 s, total `budget` 30 s). **Step 4: Run**: PASS.

### Task 24: Env wrapper

**Files:** Create `internal/initfiles/env.go`, `internal/initfiles/env_test.go`; Modify `cmd/user-secrets-init/main.go` (dispatch when `argv[0]` base is `user-secrets-env`)

**Interfaces:**
- Produces: `ExecWithEnv(dir string, argv []string, environ []string, stderr io.Writer) error` per the spec; `syscall.Exec` at the end.

- [ ] **Step 1: Failing tests** (use a `exec` seam variable, table-driven): exports each valid file; never replaces an existing variable; skips a value with a NUL byte and names it on stderr; prints one warning when `.status` starts with `error`; argv after `--` passed unchanged.
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement.** **Step 4: Run**: PASS.
- [ ] **Step 5: e2e** `TestInitDeliversFiles` in `test/e2e/init_test.go`: the Slice 6 hand-built pod now uses the real init image; `sha256sum` in the main container matches the uploaded journey-13 bytes; with the NetworkPolicy blocking `test-consumer`, `.status` reads `error unreachable` and the wrapper prints its warning (journey 17). Update `docs/architecture/contracts.md`.

**Checkpoint (controller, after the last task; implementers ignore):** run validation, paste evidence, open PR(s), STOP for go-ahead.

---

## Slice 8: Injector
**Goal:** A pack that sets only the ServiceAccount, label and annotations gets secrets delivered, and its failure mode decides what happens while the injector is down.
**Repos / branches:** nebari-user-secrets: `feat/us-08-injector` (base: `feat/us-07-init`)
**PRs:** nebari-user-secrets#9 "Injector webhook" (links spec + plan)
**Depends on:** Slice 7
**Contracts touched:** Injector `MutatingWebhookConfiguration` `user-secrets-injector` and its patch, Optional pod metadata (label `nebari.dev/user-secrets-failure`; annotations `nebari.dev/user-secrets-export-env` and `-containers`), Consumer contract (`docs/architecture/contracts.md`), Cluster bundle (`cluster/` with `cluster/REVIEW.md`)
**Docs updated:** docs/architecture/contracts.md, cluster/REVIEW.md
**Advances journeys:** 14, 22, 7, 6
**Validation:**
| Step | Command / action | Expected |
|---|---|---|
| unit | `go test ./... -race -cover` | pass, `internal/inject` table |
| policy | `make policy-test` | all pass with the webhook in the bundle; transcripts refreshed |
| e2e | `go test -tags e2e ./test/e2e/... -run 'TestNewConsumerByValuesOnly|TestInjectorFailureModes|TestCrossUserIsolation' -v` | pass (journeys 14, 22, 7) |

### Task 25: Mutate

**Files:** Create `internal/inject/inject.go`, `internal/inject/inject_test.go`

**Interfaces:**
- Produces: `type Config struct{ InitImage, ResolveURL string; TokenSeconds int64; DefaultFSGroup int64 /*65532*/ }`; `func NewInjector(cfg Config) *Injector`; `(*Injector).Mutate(pod *corev1.Pod) (*corev1.Pod, error)` (input unchanged; returns a deep copy). Volume names `user-secrets-files`, `user-secrets-bin`, `user-secrets-token`, `user-secrets-trust`; init container `user-secrets-init` with `--mode strict` iff the pod has label `nebari.dev/user-secrets-failure: strict`.

- [ ] **Step 1: Failing tests** (`TestMutate` table on real `corev1.Pod` values): unlabelled pod → returned unchanged; KubeSpawner-shaped pod → init container, four volumes, token and trust mounts only in the init container, read-only files and bin mounts in container 0 only; existing `fsGroup: 100` kept, absent → 65532; `user-secrets-containers: "a,c"` mounts into `a` and `c` only, unknown names ignored; export-env with `args` → `args` = wrapper path, `--`, old args (journey 6 half); with `command` set → prepended to `command`; pre-existing `user-secrets-files` volume of another type → replaced; second `Mutate` on the output → deep-equal (idempotent); SA, labels and annotations never change; `TestMutatedPodRestricted` (a restricted-compliant input stays restricted after `Mutate`, pod-security-admission v0.35.0).
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement.** **Step 4: Run**: PASS.

### Task 26: Webhook server and configuration

**Files:** Create `internal/httpapi/webhook.go`, `internal/httpapi/webhook_test.go`, `cluster/webhook.yaml`; Modify `cluster/kustomization.yaml` (resource + replacement for `metadata.annotations.[cert-manager.io/inject-ca-from]` and `webhooks.*.clientConfig.service.namespace`), `cluster/embed.go`, `cmd/user-secrets/serve.go` (`:9443`), `chart/templates/networkpolicy.yaml` (9443 from any source), `cluster/REVIEW.md`

**Interfaces:**
- Produces: `func NewWebhookHandler(i *inject.Injector, log *slog.Logger) http.Handler` wrapping `&admission.Webhook{Handler: admission.HandlerFunc(...)}` (controller-runtime v0.23.1 `pkg/webhook/admission/http.go:64`), decoding the pod, calling `Mutate`, returning `admission.PatchResponseFromRaw(req.Object.Raw, mutatedJSON)` or `admission.Allowed("")`; never a denial (an internal error returns `Allowed` with a warning and is logged). `cluster/webhook.yaml` exactly as the spec's injector configuration table.

- [ ] **Step 1: Failing tests:** `TestWebhookAlwaysAllows` (malformed object → allowed, no patch); `TestWebhookPatch` (labelled pod → patch whose application equals `Mutate`'s output); `TestWebhookYAML` (parsed `cluster/webhook.yaml`: two entries, selectors, failure policies, `sideEffects: None`, `reinvocationPolicy: IfNeeded`, `timeoutSeconds: 5`, rules `pods` `CREATE` only).
- [ ] **Step 2: Run**: FAIL. **Step 3: Implement.** **Step 4: Run** unit and `make policy-test`: PASS; commit refreshed transcripts.

### Task 27: Consumer journeys on kind

**Files:** Create `test/e2e/consumer_test.go`; Modify `test/e2e/fixtures/consumer.yaml` (pods carry only SA, label and annotations now)

- [ ] **Step 1: Write** `TestNewConsumerByValuesOnly` (journey 14: install with `values-consumer.yaml`; a `busybox` pod with only SA, label, annotations and `export-env` created by `tc-creator` prints the expected file and env var; assert `git diff --exit-code -- internal cmd cluster` is empty in CI); `TestInjectorFailureModes` (journey 22: scale the Deployment to 0; a soft pod starts with no `/var/run/nebari/secrets`; a strict pod create is refused; an unlabelled pod starts; scale back); `TestCrossUserIsolation` extended to injected pods.
- [ ] **Step 2: Run** e2e: PASS. Write the consumer contract (ten rules, from the spec) and the injector entries into `docs/architecture/contracts.md`; update `cluster/REVIEW.md` (the webhook YAML now ships).

**Checkpoint (controller, after the last task; implementers ignore):** run validation, paste evidence, open PR(s), STOP for go-ahead.

---

## Slice 9: Release and operations
**Goal:** Operators can install a released version, back up and rotate the master key, and roll the guard out from `[Warn, Audit]` to `[Deny]` by following written steps.
**Repos / branches:** nebari-user-secrets: `feat/us-09-release` (base: `feat/us-08-injector`)
**PRs:** nebari-user-secrets#10 "Release workflow and operations guide" (links spec + plan)
**Depends on:** Slice 8
**Contracts touched:** Master-key Secret `user-secrets-kek` and the `user-secrets admin` commands
**Docs updated:** docs/architecture/contracts.md, docs/operations.md, README.md
**Advances journeys:** 21
**Validation:**
| Step | Command / action | Expected |
|---|---|---|
| release dry run | `goreleaser release --snapshot --clean` | images for both arches and a packaged chart under `dist/` |
| docs | follow `docs/operations.md` "Rotate the master key" on the e2e cluster | `rotate-kek` Job completes; journey 21 e2e `TestKEKRotationDuringStarts` passes |

### Task 28: Release workflow

**Files:** Create `.goreleaser.yml`, `.github/workflows/release.yml`, `.github/workflows/vulncheck.yml`

- [ ] **Step 1:** Mirror nebari-operator's release shape: on tag `v*`, build both binaries for `linux/amd64,arm64`, push `ghcr.io/nebari-dev/nebari-user-secrets:<tag>`, package and push the chart as an OCI artifact, attach `cluster/` as a tarball. `vulncheck.yml` runs `govulncheck ./...` on PRs.
- [ ] **Step 2: Run** `goreleaser release --snapshot --clean`: Expected: `dist/` holds both images' binaries and the chart.

### Task 29: Operations guide and rotation journey

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
