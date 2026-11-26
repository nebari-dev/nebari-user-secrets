# CI journey coverage

<!-- Generated from test/journeys/catalog.yaml by `make coverage-doc`. Do not edit by hand. -->

Journey checks covered in CI: 22 of 37. `planned` and `not-covered` checks count as not covered. Tier 1 runs unit and chart tests, Tier 2 the kind suite (build tags `e2e` and `integration`) and the policy matrix (`run.sh:<section>`), Tier 3 real Nebari (build tag `journeys`). Platform checks are not journeys and are listed apart.

## Features

| ID | Feature | Source | Status |
|---|---|---|---|
| F1 | A user stores, rotates and deletes their own secrets through the management API, and never reads a value back | docs/design/user-secrets.md#goals (1) | active |
| F2 | Per-secret, per-app bindings; delivered names are always `NEBARI_SECRET_<SUFFIX>` | docs/design/user-secrets.md#goals (2) | active |
| F3 | Enabled secrets arrive at pod start as files, and optionally env vars, in notebooks, jhub-apps apps and Dask clusters | docs/design/user-secrets.md#goals (3), docs/design/user-secrets.md#delivery | active |
| F4 | Pod identity comes only from a registered creator, enforced by the API server; the service delivers nothing when it cannot confirm that | docs/design/user-secrets.md#goals (4), docs/design/user-secrets.md#pod-identity-and-the-admission-guard | active |
| F5 | A user can see per app when delivery last happened and why it last failed | docs/design/user-secrets.md#goals (5) | active |
| F6 | Values are encrypted per user under a rotatable master key; a lost master key stops delivery | docs/design/user-secrets.md#goals (6), docs/design/user-secrets.md#storage-and-encryption | active |
| F7 | Every value read and every denial is audited | docs/design/user-secrets.md#goals (7) | active |
| F8 | Any pack can consume secrets by meeting the consumer contract, with values only | docs/design/user-secrets.md#goals (8), docs/design/user-secrets.md#consumer-contract | active |
| F9 | Installing the service changes no existing workload | docs/design/user-secrets.md#goals (9) | active |
| F10 | The management API is reachable only from the landing page, inside the cluster | docs/design/user-secrets.md#threat-model, docs/design/user-secrets.md#architecture | active |
| F11 | Secrets survive restarts and upgrades of the service | docs/design/user-secrets.md#architecture | active |
| F12 | Sharing consequences are stated where the user shares | docs/design/user-secrets.md#threat-model | active |

## Journey checks

| Check | Feature | Tier | Status | Tests | Reason | Until |
|---|---|---|---|---|---|---|
| J1.1 | F1 | 2 | covered | `TestManagementCreateList` | - | - |
| J1.2 | F1 | 3 | not-covered | - | Needs a browser login against the landing SPA client; landing has no userSecrets screens yet (nebari-landing#236) | landing ships the userSecrets screens and Tier 3 can drive a browser login |
| J1.3 | F1 | 3 | covered | `TestManagementOnNebari` | - | - |
| J2.1 | F1 | 1 | covered | `TestValueNeverReturned` | - | - |
| J3.1 | F2 | 1 | covered | `TestBindings`, `TestEnvNameAlwaysPrefixed`, `TestResolveNeverUnprefixed`, `TestDeliveredName` | - | - |
| J4.1 | F3 | 3 | not-covered | - | data-science-pack has no userSecrets integration released | a data-science-pack release with the userSecrets integration |
| J5.1 | F3 | 3 | not-covered | - | dask-gateway-pack userSecrets integration is not released | a dask-gateway-pack release with the userSecrets integration |
| J6.1 | F3 | 3 | not-covered | - | data-science-pack userSecrets integration (jhub-apps) is not released | a data-science-pack release with the userSecrets integration |
| J7.1 | F4 | 2 | covered | `TestCrossUserIsolation` | - | - |
| J7.2 | F4 | 2 | covered | `run.sh:policy B: creator allowlist`, `run.sh:policy A: shape and immutability`, `run.sh:pods/binding`, `run.sh:token minting`, `run.sh:kubelet-minted projected token (pod must start)`, `run.sh:service account: dry-run only, and the probe`, `run.sh:label changes through subresources` | - | - |
| J7.3 | F4 | - | not-covered | - | The DaskCluster admission policy lives in dask-gateway-pack and is tested there | never in this repo |
| J8.1 | F4 | 1 | covered | `TestPodVerifier`, `TestResolveFiltersByApp`, `TestResolveHandler`, `TestVerify`, `TestRoutes` | - | - |
| J9.1 | F11 | 2 | covered | `TestDurabilityAcrossRestart`, `TestDurabilityThroughResolve` | - | - |
| J10.1 | F1 | 3 | planned | - | The init container delivers since Slice 9; the rotation journey (rotate, then a new pod gets the new value; delete removes it) is Task 36 | Slice 11 (Task 36) |
| J11.1 | F7 | 1 | covered | `TestAuditLines`, `TestAuditNeverLogsSecrets`, `TestResolveHandler` | - | - |
| J11.2 | F7 | 2 | covered | `TestResolveDeniedAudit` | - | - |
| J12.1 | F4 | 1 | covered | `TestCompare`, `TestGuard` | - | - |
| J12.2 | F4 | 2 | covered | `TestGuardFailClosed`, `TestGuardVerifiedSinceMoves`, `TestResolveGuard` | - | - |
| J13.1 | F3 | 2 | covered | `TestInitDeliversFiles` | - | - |
| J13.2 | F3 | 3 | not-covered | - | data-science-pack and dask-gateway-pack userSecrets integrations are not released | releases of both packs with the userSecrets integration |
| J14.1 | F8 | 2 | planned | - | A consumer by values only needs the injector | Slice 10 (injector) |
| J14.2 | F8 | 3 | planned | - | A consumer pack installed by Argo CD on real Nebari needs the injector | Slice 10 (injector) |
| J15.1 | F9 | 2 | covered | `run.sh:missing ConfigMap (P1)`, `TestMissingConfigMapLeavesClusterWorking` | - | - |
| J15.2 | F9 | - | not-covered | - | The data-science-pack and dask-gateway-pack golden files live in those repos | never in this repo |
| J16.1 | F3 | - | not-covered | - | dask-gateway-pack userSecrets integration is not released | a dask-gateway-pack release with the userSecrets integration |
| J17.1 | F5 | 1 | covered | `TestResolveHandler`, `TestServiceRecordDelivery`, `TestRecordDeliveryKeepsOtherOutcome` | - | - |
| J17.2 | F5 | 1 | covered | `TestInitMain`, `TestExecWithEnv` | - | - |
| J17.3 | F5 | 2 | covered | `TestInitDeliversFiles` | - | - |
| J18.1 | F12 | - | not-covered | - | The sharing warning is data-science-pack share dialog UI, not in this repo | never in this repo |
| J19.1 | F10 | 1 | covered | `TestNoExternalSurface`, `TestNetworkPolicyPorts` | - | - |
| J19.2 | F10 | 2 | covered | `TestNetworkExposure` | - | - |
| J20.1 | F6 | 1 | covered | `TestSealedBoundToOwnerAndName`, `TestWrappedKeyBoundToOwner`, `TestSealOpenRoundTrip` | - | - |
| J20.2 | F6 | 2 | covered | `TestDecryptFailedOnKind`, `TestRecordsHoldNoPlaintext` | - | - |
| J21.1 | F6 | 2 | covered | `TestKEKRotationOnKind`, `TestKEKMissingFailsClosed` | - | - |
| J21.2 | F6 | 2 | planned | `TestKEKRotationDuringStarts` | KEK rotation while pods start needs injected pods; the e2e tests come with the operations guide | Slice 11 (release and operations) |
| J22.1 | F8 | 2 | planned | - | The injector does not exist yet | Slice 10 (injector) |
| J22.2 | F8 | 3 | planned | - | The injector does not exist yet | Slice 10 (injector) |

## Platform checks

| Check | Tier | Status | Tests | Reason | Until |
|---|---|---|---|---|---|
| P3.1 | 3 | covered | `TestChartConvergesOnNebari` | - | - |
