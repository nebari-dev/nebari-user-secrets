# User Secrets Pack - Design

**Date:** 2026-11-10
**Status:** Draft for review
**Primary repo:** `nebari-dev/nebari-user-secrets` (new; deployed by NIC as foundational software, like nebari-operator, per NIC ADR-0022)
**Other repos (reference consumers for the MVP):** `nebari-dev/data-science-pack` (pod hook + hub identity endpoint), `nebari-dev/dask-gateway-pack` (gateway config hook + its own DaskCluster policy). `nebari-dev/nebari-landing` provides the secrets screens on the landing page and proxies to the management API ([nebari-dev/nebari-landing#236](https://github.com/nebari-dev/nebari-landing/issues/236)). The service has no `NebariApp`, so it does not depend on `nebari-dev/nebari-operator`. Later consumers (for example `nebari-dev/javo`, Ray) integrate through the same consumer contract and the helper.
**Supersedes:** `nebari-dev/external-auth-pack` (private, experimental; to be archived after this repo lands its first slice)

Versions this design is written against: data-science-pack `77531a4`, dask-gateway-pack `c9c2bd6`, nebari-operator `ccbc217`, external-auth-pack `568ee68`, software-pack-template `dbc89fa`, nebari-landing `6f9b9f9`, dask-gateway `2026.3.0` (upstream), JupyterHub `5.5.0` (upstream), KubeSpawner `7.0.0` (upstream, pinned by dsp `images/jupyterhub/pixi.toml:15`), jhub-apps `2026.8.1` (read by the reviewer).

## Intent

A data scientist has an API key (a data vendor token, an OpenAI key, a fine-grained GitHub PAT). Today they paste it into a notebook cell or a `.env` file in their home directory, and it does not reach the Dask clusters they launch. This component gives every Nebari user a place to store their own secrets, tied to their durable Keycloak identity, and delivers them as files at a well-known path in the workloads they choose: in the MVP, their notebook server, their jhub-apps apps, and their Dask clusters. Each consuming pack decides whether to also export them as environment variables.

**The service is independent of any software pack.** It is a platform component that owns the secrets; JupyterHub (data-science-pack), Dask (dask-gateway-pack), and later Javo, Ray or a job scheduler are consumers that meet one written consumer contract, using the shipped helper. No part of the service names or depends on a particular consumer. Javo (`nebari-dev/javo`) currently ships its own per-user secret store; with this decision Javo becomes a consumer, which needs agreement with its maintainer. Until then Nebari has two stores.

**Backward compatible, opt in.** NIC installs this component on every cluster, and that changes no existing workload. Every consuming pack's integration is off by default, and when it is off the pack's rendered manifests and the pods it creates are identical to the previous release, checked against committed golden files.

The threat this protects against is **other users**. Platform admins may see secret values (they can read the store's Kubernetes Secrets and exec into pods). The owner may see their own values (they already have them). Another user must never obtain them, except as a direct consequence of something the owner chose to share (see below).

**Who counts as an admin:** the target is platform admins only, meaning people with Kubernetes RBAC over the cluster. **For the MVP, JupyterHub admins (the `/admin` Keycloak group, `00-gateway-auth.py:587`) are also accepted as able to see values**, because the JupyterHub 5.5.0 admin role includes `access:servers` and `shares` (`jupyterhub/roles.py`, admin role), which let them open or share any user's server. The docs and the landing page say so. Follow-up after the MVP: a custom hub admin role in data-science-pack without `access:servers` and `shares`. dask-gateway's `admin` flag grants no access to other users' clusters at `2026.3.0` (`routes.py:157-229`, `models.py:59-61`).

**Sharing a server shares everything that server can reach.** When a user shares a notebook server or jhub-apps app (sharing is on by default, `dsp/config/jupyterhub/02-jhub-apps.py:99-106`), anyone they share it with can read that pod's secret files and environment. They can also read the owner's `JUPYTERHUB_API_TOKEN` from the server's environment (JupyterHub 5.5.0 `spawner.py:1266`) and use it to start Dask clusters as the owner (dask-gateway accepts the owner's token, `dgsrc/auth.py:422-464`), which receive the owner's `dask` secrets. So sharing a server shares every secret bound to any app that server's token can launch, not only the server's own. data-science-pack's share dialog help and the landing page next to every Dask binding ([nebari-dev/nebari-landing#236](https://github.com/nebari-dev/nebari-landing/issues/236)) say: "Anyone you share a server with can start Dask clusters as you and read the secrets you enabled for Dask." Narrowing this (dropping the identity scope from tokens of shared servers) is a follow-up; see "Future-proofing".

**The landing page is inside the trust boundary for managing secrets.** The management API accepts the landing SPA's access token, which keycloak-js keeps in the landing page's JavaScript, and its NetworkPolicy admits only the landing frontend pods. A cross-site scripting bug in the landing page, or code running in its frontend pods, could therefore use a signed-in user's token to overwrite, rebind or delete that user's secrets. It could not read them (values are write-only and no response contains one), and it could not act on another user (every route acts only on the token's `sub`). Overwriting is still harmful: an attacker could swap in a credential they control and capture what the user's workloads send with it. A UI served by this service would carry the same exposure on its own origin; moving the screens to the landing page moves it into nebari-landing's code, so that repo's frontend security (content security policy, dependency hygiene, no rendering of untrusted HTML) is part of this feature and belongs in nebari-landing#236's scope.

## Goals

- A user stores, rotates and deletes their own secrets from the Nebari landing page, which calls this service's cluster-internal management API (see "Management API").
- A user chooses, per secret, which apps receive it and the suffix of its name. Every delivered name is `NEBARI_SECRET_<SUFFIX>`; users never choose a full name (see "Names and values").
- Notebook servers, jhub-apps apps, and Dask clusters (scheduler and every worker, including workers added later by adaptive scaling) receive the secrets the user enabled for them, at pod start, as files under `/var/run/nebari/secrets/`. The reference consumers also export them as environment variables (opt in per pack).
- A pod's user identity comes only from a creator that is allowed to name users for that namespace and app, and is enforced by the Kubernetes API server. The service refuses to deliver when it cannot confirm that enforcement (fail closed).
- A user can see, per app, when secrets were last delivered and why the last attempt failed.
- Secrets are durable: they survive restarts and upgrades of the service and never expire or get evicted.
- Every read of a secret value is audited.
- Any software pack can become a consumer by meeting the consumer contract with the helper. The service changes only by registering the new app ids.

## Non-goals (MVP)

- **Sharing between users.** Only the owner can use a secret in the MVP. The design must not close this off (see "Future-proofing").
- **Per-app access control by the owner beyond on/off enablement**, e.g. an allow-list of specific deployed apps.
- **A credential-injecting proxy** ("use without seeing"). If a grantee can run code that holds the value, they can print it. Scoping is done in the credential itself (fine-grained PATs, project-scoped keys).
- **Non-HTTP credential shapes** handled specially: SSH keys, database passwords, cloud SDK credential files. They are stored as opaque bytes and delivered as files, nothing more.
- **OAuth account linking** (the "Connect GitHub" flow external-auth-pack had).
- **Background workloads with no user present** (scheduled jobs, pipelines, Javo's scheduled jobs). **Not in the MVP, but a goal.** The direction is service (bot) accounts, see "Future-proofing".
- **Live update of running workloads.** A rotated or deleted secret takes effect in pods started afterwards. A Dask cluster that scales up after a rotation can therefore have workers with the old value and workers with the new one; the landing page says so next to the Dask binding.
- **A UI served by this service.** The landing page provides the screens ([nebari-dev/nebari-landing#236](https://github.com/nebari-dev/nebari-landing/issues/236)); a standalone UI may come later.
- **New Dask clusters after the user's Keycloak session has ended.** The hub rejects a user's token once its Keycloak refresh fails (below), which already stops cluster creation today. Existing clusters keep scaling, because each new pod proves itself, not the user.
- **Offboarding cleanup.** When a Keycloak user is deleted, their `us-<sub>` Secrets stay until an admin deletes them. A cleanup job or admin route is a follow-up.
- **Installs without the TokenReview binding.** Without it the service cannot verify pods and does not deliver. Local verification against the cluster's service account issuer keys is a follow-up.

## Anti-goals

- Any path where a caller can name a user and receive that user's secrets without that identity being vouched for by a mechanism the user cannot forge. external-auth-pack had exactly this (a shared secret plus `?user=`, `chart/files/broker_server.py:99-111` at `568ee68`) and it is the reason that repo is being superseded.
- Any way for a pod to choose its own user identity, or for a creator to name users outside the namespaces and apps it is registered for.
- Treating secrets as cache entries: no TTL, no eviction, no in-memory-only store.
- Secret values anywhere but the owner record and the pod's in-memory volume: never in pod specs, env literals, custom resources, per-workload Kubernetes Secrets, logs, audit records, error messages, or management API responses.
- Silent failure as the only signal: a delivery failure always leaves a trace the user can see.

## Design summary

```text
Landing page (keycloak-js token) ──► landing nginx /api/user-secrets/ ──(in-cluster TLS, Bearer unchanged)──► management API :8444
                                                                    ──► K8s Secret us-<sub> (owner record)
                                                          (service runs in its own namespace; no NebariApp, no gateway route)

Creator (JupyterHub hub; dask-gateway controller fed by the gateway API), allowlisted per (namespace, app)
  └─ creates the workload pod, built by the helper library:
       serviceAccountName: the app's registered workload SA
       label: nebari.dev/user-secrets=true
       annotations: nebari.dev/user-secrets-sub=<sub>, nebari.dev/user-secrets-app=<app>
       initContainer user-secrets-init + emptyDir{medium: Memory} (files) + emptyDir (wrapper) + projected SA token (aud=user-secrets)
          │
          │  API server, two ValidatingAdmissionPolicies:
          │   - A (always on): label and annotations go together and are immutable, spec immutable,
          │     no ephemeral containers, no annotated Bindings, only kubelets mint user-secrets tokens
          │   - B (labelled pods only): the creator is registered for this namespace and app
          ▼
user-secrets-init ──(TLS, Bearer: projected, pod-bound SA token)──► POST /api/v1/resolve
          │                                                     TokenReview → pod name + UID
          │                                                     GET pod → UID match, label + annotations, SA registered for (ns, app)
          │                                                     guard verified (else 503)
          ▼
/var/run/nebari/secrets/NEBARI_SECRET_*   (mode 0440, group = pod fsGroup, read-only in the main container)
          └─ optional: main container args wrapped by /var/run/nebari/user-secrets-bin/user-secrets-env, which exports them and execs
```

A resolve call returns values only when three things hold:

1. **Which pod:** the bearer token is a projected ServiceAccount token with audience `user-secrets`, bound to a pod. `TokenReview` returns its ServiceAccount, pod name and pod UID. The service reads that pod and requires the UID to match, so a reused pod name cannot pass. Only kubelets can mint tokens for this audience (policy rule), so the token came from a pod's own projected volume.
2. **Which app:** the pod's `nebari.dev/user-secrets-app` annotation names a registered app, and the pod's namespace and ServiceAccount are registered as a workload of that app.
3. **Which user:** the pod's `nebari.dev/user-secrets-sub` annotation, on a pod carrying the `nebari.dev/user-secrets` label. It is trusted because the API server lets only a creator registered for that namespace and app create such a pod, and nothing change the label or annotations afterwards. The service delivers only while it can confirm both policies are in force, or the deployer has set the explicit override.

The service returns only the secrets that user owns (later: may use) and has enabled for that app.

Prior art: Kubeflow gives pipeline pods a projected ServiceAccount token with a custom audience (`pipelines.kubeflow.org`) that its API checks with TokenReview, and binds pods to users through per-user namespaces ([Kubeflow Pipelines multi-user](https://www.kubeflow.org/docs/components/pipelines/multi-user/), [connect API](https://v1-9-branch.kubeflow.org/docs/components/pipelines/user-guides/core-functions/connect-api)). This design uses the same credential and replaces the per-user namespace with an annotation guarded at admission. The "trusted launcher vouches for the user" model is the one the IETF OAuth Transaction Tokens draft formalises for request chains ([draft-ietf-oauth-transaction-tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/11/)).

## Alternatives considered

| Alternative | Verdict | Why |
|---|---|---|
| **ServiceAccount per user (or per user and app)** | Rejected | The same trust as the annotation (any pod creator in a namespace can use any ServiceAccount there), plus a lifecycle to manage and RBAC to create ServiceAccounts. Its one advantage, that off-the-shelf tools keyed on ServiceAccounts see the user, does not apply. Moving to it later only changes how the service maps a pod to a user. |
| **Namespace per user** | Rejected | The strongest native boundary, but some clients give Nebari a single namespace. |
| **Per-user namespaces as an option** | Rejected for the MVP | Doubles the test matrix, and KubeSpawner and dask-gateway would each need a namespace-per-user mode. |
| **Keycloak token in the pod** | Rejected | Access tokens expire; a refresh token in a user pod is too powerful and still dies at SSO idle. |
| **Pull from inside the pod with the user's hub token** | Rejected | No cluster-scoped objects, but the token lives in the main container, so any code or sharee in the pod can fetch every binding. Dask workers hold no hub token, it inherits the Keycloak session dependency, and it ties the service to JupyterHub. |
| **Mutating webhook that sets env vars** | Rejected | Literal env values land in the pod spec, which the built-in `view` role can read; a webhook that creates Secrets during admission has side effects admission should avoid; an unavailable webhook blocks pod creation. |
| **Vault (Agent Injector, Bank-Vaults) or External Secrets Operator** | Rejected | Both key identity on ServiceAccount or namespace, which brings back per-user ServiceAccounts. External Secrets also materialises per-workload Kubernetes Secrets, an anti-goal. A heavy dependency with no identity gain. |
| **Secrets Store CSI driver** | Rejected | Same ServiceAccount-keyed identity; synced Secrets for env use are an anti-goal. |
| **Extending Javo's store** | Not chosen | The hard part is pod identity and delivery, which is the same whichever store holds the records. Javo can become a consumer, and its sealing model is the encryption follow-up. |
| **A single `.env` file** | Rejected | Dotenv has no common escaping standard, so it cannot carry arbitrary bytes. Per-secret files can. |
| **Creator-signed assertion (as the mechanism or as a fallback)** | Deferred (follow-up) | Needs no cluster-scoped objects, but signing keys may be readable by pod creators in a shared namespace, an assertion can be replayed within its lifetime unless bound to the pod name, and dask-gateway has no maximum cluster lifetime to bound Dask assertions. Cut from the MVP on 2026-11-10 to keep one security mode; see "Future-proofing". |

## Pod identity and the guard

**Annotation on a per-app ServiceAccount.** Each consumer runs its workload pods under a registered ServiceAccount per app, and its creator writes the user's `sub` and the app id as pod annotations. If a deployment already gives its workload pods a ServiceAccount (for example for cloud IAM), that ServiceAccount is registered instead of a new one, and the helper does not replace it.

**Why a guard at all.** Kubernetes lets anyone who can create pods in a namespace use any ServiceAccount, Secret or ConfigMap in it, and the built-in `edit` role can also impersonate ServiceAccounts and create ServiceAccount tokens ([RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices); `policy.go:301`, `:307` at Kubernetes v1.30.0). So any in-namespace identity is exactly as strong as the control over who can create or change pods carrying it and who can mint tokens for it.

**Trust is explicit and scoped.** The registry lists each creator with the namespaces and apps it may name users for. For each creator, the components that feed it are trusted too, and `cluster/REVIEW.md` lists them with a command to check who holds the relevant permissions:

| Creator | Allowed | Trusted inputs (must be reachable only by trusted principals) |
|---|---|---|
| JupyterHub hub ServiceAccount | its user namespace; apps `notebook`, `jhub-apps` | The hub process; `impersonate` and `serviceaccounts/token` on the hub ServiceAccount |
| dask-gateway controller ServiceAccount | registered Dask namespaces; app `dask` only | The gateway API pod (it writes `DaskCluster.spec.config`, `dg_kube_backend.py:404-411`, `:523-524`); every principal that can create or update `daskclusters` in those namespaces; `impersonate` and token creation on both ServiceAccounts |

dask-gateway-pack ships its own small ValidatingAdmissionPolicy (in its own cluster bundle, reviewed with that pack) that lets only the gateway API ServiceAccount create or update a `DaskCluster` whose `spec.config` carries `nebari.dev/user-secrets-*` annotations. A consumer whose creator builds pods from an intermediate resource guards that resource the same way; the service's policy stays consumer-neutral.

**The service runs in its own namespace.** Owner records never share a namespace with workloads or creators. The chart's `validate.yaml` fails when the service namespace appears among registered workload or creator namespaces, unless `guard.allowSharedNamespace: true` is set, which is only valid together with the override below and is documented as "every principal that can create pods in this namespace is trusted with every user's secrets".

**Two policies.** Workload pods carry a required label, `nebari.dev/user-secrets: "true"`, besides the two annotations, and the service trusts only labelled pods. The rules are split across two ValidatingAdmissionPolicies, both in the API server (no webhook whose outage could block pods):

**Policy A, `user-secrets-pod-guard`: no parameters, always evaluated.** It matches `pods` and `pods/*` on CREATE and UPDATE, and `serviceaccounts/token` on CREATE:

- A pod CREATE that carries either annotation must carry the label, and a labelled pod must carry both annotations. So every pod that names a user goes through policy B.
- A pod UPDATE on the main resource or any subresource (`status`, `ephemeralcontainers`, `resize`) must keep the label and both annotations exactly as they were. The label can be neither added nor removed after creation.
- A main-resource UPDATE of a labelled pod must not change `spec`, so no image swap reaches the files. (KubeSpawner and the dask-gateway controller never update a pod's spec after creating it.)
- `pods/ephemeralcontainers` on a labelled pod: denied.
- `pods/binding` CREATE: the `Binding` must not carry user-secrets labels or annotations (the API copies Binding annotations onto the pod, `storage.go:238-242` at v1.30.0).
- `serviceaccounts/token` CREATE with `user-secrets` in `spec.audiences`: only members of `system:nodes`, that is the kubelet minting a pod's projected token (NodeRestriction already limits a kubelet to its own node's pods).
- A pod CREATE by the service's own ServiceAccount: only with `request.dryRun`, so the probe permission below can never create a real pod.

**Policy B, `user-secrets-creators`: the creator allowlist.** It matches only `pods` CREATE, and its binding selects only labelled pods (`objectSelector` on the label). The requester must be a registered creator, the namespace one of its namespaces, and the `user-secrets-app` annotation one of its apps. Parameters come from the ConfigMap `user-secrets-creators` in the service namespace, rendered from the registry: one key per creator, `<namespace>.<serviceaccount>` (ConfigMap keys cannot contain `:`, and namespaces cannot contain `.`), with the value `namespaces=<ns>[,<ns>...];apps=<app>[,<app>...]`. The CEL derives the key from `request.userInfo.username` and splits the value. Its binding keeps `parameterNotFoundAction: Deny`.

**Why two.** Kubernetes collects a binding's parameters before it evaluates anything. With `parameterNotFoundAction: Deny`, a missing ConfigMap denies every request the binding matches; with `Allow`, it skips the binding's rules entirely (`policy_dispatcher.go:286-294`, `dispatcher.go:196-209` and `types.go:582-585` at v1.30.0). A single policy therefore either blocks the cluster or turns itself off when the ConfigMap is missing. With the split, a missing ConfigMap denies only labelled pod creates (policy B's selector), while policy A, which has no parameters, keeps every other rule in force.

**Tests.** The case matrix in `test/policy/run.sh` runs against throwaway kind clusters on Kubernetes 1.30, 1.32 and 1.34, with the bundle built for a non-default namespace; transcripts are in `test/policy/results/`. What it establishes:

| Case | Result |
|---|---|
| Hub creates a labelled `notebook` pod in its namespace; dask controller creates a labelled `dask` pod in its namespace | admitted |
| Non-creator with A's `sub`; hub with app `dask`; dask controller in the hub's namespace with app `notebook` | denied by B |
| Annotated pod without the label; labelled pod missing an annotation | denied by A |
| Annotation change, label removal, label added to an existing pod, annotation change through `pods/status` | denied by A |
| Image patch on a labelled pod; ephemeral container on a labelled pod; Binding carrying the annotation | denied by A |
| Unrelated annotation change on a labelled pod; image patch on an unlabelled pod; plain Binding | admitted |
| `user-secrets` token minted by a non-creator or by cluster-admin | denied by A |
| Labelled pod with a projected `user-secrets` token becomes Ready (the kubelet mints the token) | admitted |
| TokenReview of a pod-bound token returns `authentication.kubernetes.io/pod-name` and `pod-uid` in `extra` | confirmed |
| Service ServiceAccount creates a real pod | denied by A |
| ConfigMap deleted: labelled pods denied ("no params found ... `Deny` parameterNotFoundAction"); unannotated pod in `kube-system`, `pods/status` update, other-audience token admitted; A's immutability and token rules still enforced | as designed |
| ConfigMap restored | creators admitted again |
| B's binding switched to `[Warn]` | a non-creator's labelled pod is admitted, so the guard must treat `Warn` as bad (it does) |
| Restricted-compliant probe pod: labelled is denied by B's message, unlabelled-annotated by A's message; a privileged probe pod is stopped by Pod Security before either policy | as designed |
| Canary: a plain restricted-compliant dry-run pod by the service ServiceAccount | admitted |
| Label removed or added through `pods/status`; a Binding carrying the label | denied by A |
| Binding B switched to `[Warn]` and back to `[Deny]` | `resourceVersion` changed and `generation` rose by 2, `uid` unchanged; the `managedFields` time did not advance (so `verifiedSince` uses the fingerprint) |
| Binding B deleted and re-created | `uid` changed |

Two properties of the YAML matter. `request.subResource` does not exist on requests without a subresource, so every expression guards it with `has()`; an unguarded read raises a CEL error, which `failurePolicy: Fail` turns into a denial, and that is why the guard also runs a canary probe and the matrix is a CI test. When both policies deny a request, the reported message depends on evaluation order, so each probe is built so that exactly one policy can deny it.

Not covered, by decision: `pods/exec` into a user's pod (an admin capability; the threat model accepts admins seeing values), and impersonation of a creator ServiceAccount (an impersonated request is indistinguishable at admission). The latter is a precondition in `REVIEW.md`: only admins may `impersonate` or create tokens for creator ServiceAccounts.

**Guard verification (fail closed).** Each service replica:

- **Watches** both policies, both bindings and the `user-secrets-creators` ConfigMap (informers with `metadata.name` field selectors, so the reader role can grant `list` and `watch` by `resourceNames`), and compares: each policy's spec equals the one embedded in the service binary; binding A has no `paramRef` and empty `matchResources`; binding B's `paramRef` (name, namespace, `parameterNotFoundAction: Deny`) and `objectSelector` match; both bindings' `validationActions` contain `Deny` (`[Deny, Audit]` passes, `[Warn]` or `[Audit]` fail); the ConfigMap's data equals what the service renders from its own registry.
- **Probes** every 5 minutes with three server-side dry-run creates in the service namespace, as the service's own ServiceAccount, each meeting the Pod Security `restricted` level (non-root, `RuntimeDefault` seccomp, all capabilities dropped, no privilege escalation, a pause image pinned by digest), because Pod Security and mutating webhooks run before the policies (`plugins.go:77`, `:100-101` at v1.30.0): a labelled pod must be denied with policy B's message; an unlabelled annotated pod must be denied with policy A's message; a plain pod (the canary) must be admitted. Any other outcome of the first two that is not an admission (another denial, an error) counts as unknown; an admission of either, or a denial of the canary, counts as confirmed bad.
- Keeps three states: **verified**; **confirmed bad** (a watched object differs or is missing, or a probe result is wrong), which denies immediately; and **unknown** (the API could not be reached, or a probe was inconclusive), which keeps the last verified state for up to 2 minutes and then denies. While not verified, resolve returns `503 {"error":"guard_not_verified","reason":...}`.
- **verifiedSince.** A pod admitted while the guard was not enforcing (before the bundle was installed, during the `[Warn, Audit]` rollout phase, or while a binding was edited or removed) must never be trusted later, because policy A would then protect its forged annotations. Each replica fingerprints the two policies and the two bindings by `uid` and `generation` (which tracks spec edits, so chart-label changes do not count), and the ConfigMap by `uid` and `resourceVersion` (it has no `generation`), and keeps the fingerprint and `verifiedSince` in a `user-secrets-guard-state` ConfigMap in the service namespace (written with `resourceVersion` concurrency, so replicas agree). Whenever a watched object no longer matches the stored fingerprint (seen through the watch, or at startup for a change made while no replica was watching), or the guard returns to verified after a confirmed-bad state, `verifiedSince` moves forward and the new fingerprint is stored, but only once the probes pass again; the time is taken from the API server (the `creationTimestamp`-comparable time of that guard-state write) plus a fixed margin of 30 seconds, covering clock skew and the lag before a binding change takes effect on every API server. It never moves backwards. Each replica also watches the guard-state ConfigMap and uses the later of its own and the stored value. Resolve refuses any pod whose `creationTimestamp` is not later than `verifiedSince` (`403`, reason `pod_predates_guard`). A timestamp would not work: a binding's `managedFields` time does not advance when it is switched from `[Warn]` back to `[Deny]` (1.30, 1.32 and 1.34), so a pod admitted in that window would look newer than the last recorded change. `generation` reveals every spec edit and `uid` a delete and re-create. Side effect: any write to a guard object, including a policy or binding spec edit or a consumer added to the ConfigMap, moves `verifiedSince`, so a pod whose init container runs across it gets `.status` `error pod_predates_guard` and resolves after a restart. That is the conservative direction. The override mode skips this check, since it trusts creators by declaration.

**Override (last resort).** `guard.mode: unverified` delivers without any guard. The service warns at startup and on every check, shows an admin banner, and marks every audit line `"guard":"overridden"`. Setting it states that only the registered creators can create or patch pods, impersonate creator ServiceAccounts, or create tokens for them, in the consumer namespaces. The override does not cover a missing TokenReview binding. A signed-assertion fallback is a follow-up.

**Trust in creators.** A compromised hub could name any user in its namespace; it nearly can today, because it holds every logged-in user's refresh token. A compromised gateway API or controller could start Dask pods naming any user and receive that user's `dask` secrets only (the app scope stops it claiming `notebook`). Accepted for the MVP and stated in the docs.

**Cluster bundle (reviewed by the cluster's Kubernetes team).** Plain YAML in `cluster/` plus `cluster/REVIEW.md`. The service namespace appears in two places that kustomize's `namespace` setting does not touch, binding B's `paramRef.namespace` and the service ServiceAccount literal in policy A (isolated in its own CEL variable, `serviceAccount`), so the kustomization substitutes both with `replacements` from a local-only `user-secrets-install` ConfigMap (`config.kubernetes.io/local-config`, never applied; the ServiceAccount literal uses `delimiter: ":"`, `index: 2`). The spike builds and tests it with a namespace other than the default. The service renders its expected policy and binding specs for the guard comparison from the same templates and its configured namespace. Everything else the pack needs is namespaced and lives in the Helm chart.

| Object | Does | Can affect |
|---|---|---|
| `ValidatingAdmissionPolicy` + `ValidatingAdmissionPolicyBinding` `user-secrets-pod-guard` (policy A) | the always-on rules above, no parameters | **Evaluated** on every pod create and update, every pod subresource write and every ServiceAccount token request in the cluster, with `failurePolicy: Fail`. **Designed to deny only** requests carrying or gaining user-secrets metadata, `user-secrets` TokenRequests from non-kubelets, and real pod creates by the service's ServiceAccount, whether or not the ConfigMap exists. Evidence that normal operation is untouched: scheduler bindings, kubelet status updates, kubelet token minting and unrelated pods in `kube-system` all pass in the spike on every tested version; a CEL error would deny, which is why the canary probe and the CI matrix exist |
| `ValidatingAdmissionPolicy` + `ValidatingAdmissionPolicyBinding` `user-secrets-creators` (policy B) | the creator allowlist, params from the ConfigMap | labelled pod creates only; with the ConfigMap missing, every labelled pod create is denied and nothing else is affected |
| `ClusterRoleBinding` to `system:auth-delegator` | lets the service create TokenReviews | the service's ServiceAccount only |
| `ClusterRole` + `ClusterRoleBinding` `user-secrets-guard-reader` | `get`, `list`, `watch` on the two policies and two bindings by `resourceNames` | read-only, four named objects |

`REVIEW.md` covers each object and why it is needed, what it can affect (including the "evaluated on all, designed to deny only" statement for policy A), the preconditions (Kubernetes 1.30 or later; the NodeRestriction admission plugin, on which the token rule relies to keep a kubelet to its own node's pods; only admins may impersonate or mint tokens for creator ServiceAccounts), the trusted-inputs table above with `kubectl auth can-i` / `kubectl get rolebindings,clusterrolebindings` checks, the policy case matrix with its saved transcripts and how to rerun it (`test/policy/run.sh` against kind), how to test before applying (`kubectl apply --dry-run=server -k cluster/`), the rollout (bindings with `[Warn, Audit]` first to observe, then `[Deny]`, at which point delivery starts for pods created afterwards), the install order (the chart, which creates the ConfigMap, before the bundle; installing them the other way round only denies labelled pods until the chart is in) and removal (the bindings before the chart; opted-in packs stop receiving secrets; nothing else changes).

## Consumer contract (pack-independent)

Any software pack that wants a user's secrets in its workloads meets these rules. They are written to `docs/architecture/contracts.md` in the primary repo; the helper implements rules 3 to 7 so a consumer does not hand-build them.

1. **Opt in.** The integration is off by default (`userSecrets.enabled: false`). When it is off, every change the integration makes (pod settings, hub roles and scopes, handlers, gateway hooks, NetworkPolicy, ServiceAccounts) is absent, and golden-file tests prove the rendered chart and the created pods are identical to the previous release.
2. **Register in values only.** The deployer adds the app id, its workload `namespace/serviceaccount`, and the creator's ServiceAccount with its namespaces to nebari-user-secrets's values. The service and the cluster bundle do not change.
3. **Use the helper** (`nebari_user_secrets.py`, a single standard-library-only Python module vendored into the consumer chart at a pinned release) to build the pod settings, and apply them at the last point before the pod is created, after any profile, option or subclass logic that could overwrite them.
4. **Workload ServiceAccount.** Run workload pods as the registered workload ServiceAccount. If the deployment already sets one, register that one; the helper never replaces it. When the helper does set the ServiceAccount it also sets `automountServiceAccountToken: false`.
5. **Label and annotate each pod** with `nebari.dev/user-secrets: "true"`, `nebari.dev/user-secrets-sub` and `nebari.dev/user-secrets-app`. The `sub` comes only from a source the pack authenticated itself, never from user input.
6. **Never let user input choose** the ServiceAccount, annotations, init containers, volumes, security context or command wrapper. Each consumer has a test that every user-fillable profile and option field leaves them unchanged.
7. **Add the delivery pieces:** the `user-secrets-init` init container (image from a chart value defaulting to the digest the helper release pins); an `emptyDir` with `medium: Memory` and `sizeLimit: 1Mi` for the files, mounted read-only into the main container at `/var/run/nebari/secrets`; a separate disk-backed `emptyDir` for the wrapper binary, mounted read-only at `/var/run/nebari/user-secrets-bin`; a projected token (`audience: user-secrets`, `expirationSeconds: 600`) mounted **only** into the init container; an empty `user-secrets-ca` ConfigMap in the workload namespace, which the service fills, mounted `optional: true` into the init container; the label `nebari.dev/user-secrets: "true"`; and a pod `securityContext.fsGroup` (the helper sets one when the pod has none), so files are group-readable by the main container.
8. **Allow egress** from workload pods to the service's in-cluster endpoint, through the pack's own NetworkPolicy when it has one (dsp's single-user policy pattern, `dsp/values.yaml:147-161`).
9. **Never copy values elsewhere:** no env literals in the pod spec, no Kubernetes Secrets, no custom resource fields, no logs. To expose them as environment variables, use the shipped `user-secrets-env` wrapper.
10. **Choose a failure mode.** `soft` (default): on a resolve failure the init container exits 0 and the workload starts without secrets. `strict`: it exits non-zero and the pod does not start. Either way it writes no secret files, records the reason in `.status`, and the service records the failure for the management API when the request reached it. Failures outside the init container (image pull, missing ServiceAccount) stop the pod in both modes; that is Kubernetes behaviour, not a delivery failure.
11. **Never deliver to code the user did not choose to run**, such as a build of an untrusted pull request (Javo's preview apps are an example).

## Delivery: files at a well-known path

- **Layout.** `/var/run/nebari/secrets/NEBARI_SECRET_<SUFFIX>`, one file per secret, holding the exact stored bytes, mode `0440`, group = the pod's `fsGroup`. `/var/run/nebari/secrets/.status` holds `ok <count>` or `error <code> <detail>`. `/var/run/nebari/user-secrets-bin/user-secrets-env` (mode `0550`) is the env wrapper, copied in by the init container onto its own volume, because the binary does not fit beside the values in the 1 MiB memory volume.
- **Why files.** A memory-backed `emptyDir` dies with the pod, so values never reach etcd beyond the owner record, there is nothing to clean up, and no value passes through KubeSpawner's `str.format` templating or Kubernetes' `$(VAR)` expansion.
- **`user-secrets-env -- <cmd> [args]`** reads the files, adds each as an environment variable with the exact bytes (a value containing a NUL byte cannot be an env var; it is skipped and named on stderr), never replaces a variable that is already set, prints one warning line to stderr when `.status` reports an error, and `exec`s the command. Consumers prepend it to the container's `args` (KubeSpawner and dask-gateway both put the command in `args`, `kubespawner/objects.py:540`, `controller.py:1144`), so the image's entrypoint (for example `tini`) still runs first and `exec`s the wrapper.
- **`user-secrets-init`** is a static Go binary (multi-arch image, runs as UID 65532 with the pod's `fsGroup`). It reads the projected token, calls resolve over TLS with a 30-second budget and exponential backoff on `503` and connection errors, writes each file to a temporary name and renames it, writes `.status`, copies itself to the wrapper volume, and exits per the consumer's failure mode.
- **Transport.** The service serves the resolve API on an in-cluster `Service` (`https://user-secrets.<service-namespace>.svc:8443`) over TLS. cert-manager, which NIC always installs, issues a self-signed CA and the serving certificate entirely inside the service namespace (a self-signed `Issuer`, a CA `Certificate`, a CA `Issuer`, the serving `Certificate`), so no cluster-scoped issuer is needed. Each consumer chart creates an empty `user-secrets-ca` ConfigMap in its workload namespace, and the service fills and updates its `data` with server-side apply under its own field manager when cert-manager issues or rotates the CA. The service holds only `get`, `update` and `patch` on that one name, because RBAC cannot restrict `create` by resource name. How Argo CD is kept from reverting `data` (server-side diff respecting other field managers, or an `ignoreDifferences` entry) is an open question; the init container reads it at every start, and a missing ConfigMap gives `.status` `error ca_missing`. trust-manager is not used: NIC installs it only when a trust bundle is configured (`nebari-infrastructure-core` `pkg/argocd/writer.go:82-84`, `:406`). The landing namespace gets the same empty `user-secrets-ca` ConfigMap from the landing chart, filled the same way, for the management API on port 8444. Unlike an init container, the landing nginx reads the CA only when it loads its configuration, so the CA `Certificate` is long-lived (10 years) and only the serving certificate rotates routinely under it, which changes nothing the clients trust. When the CA itself is replaced, the service publishes the old and new CA together in every `user-secrets-ca` until the old one expires, so a client that loaded either keeps working. The chart renders the landing-namespace Role only when `landing.enabled` is set. The service's NetworkPolicy admits port 8443 only from registered workload namespaces and port 8444 only from the landing frontend pods.

## Reference consumers (MVP)

**Python helper (`nebari_user_secrets.py`, in nebari-user-secrets).** One module with no dependencies outside the Python standard library, working on plain dicts, so it runs in the upstream hub and dask-gateway images unchanged. Each consumer chart vendors a copy at a pinned release (a sync script plus a CI check that the copy matches the tag) and loads it through its existing config mechanism, so no consumer image changes and nothing loads it while the integration is disabled. `pod_settings(sub, app, cfg)` returns the settings as dicts; `apply_to_pod(pod, settings)` applies them without replacing an existing ServiceAccount, `fsGroup` or volumes; `dask_options(settings)` returns the dask-gateway overrides. The helper pins the init image digest; that image speaks resolve API `v1`, which the service supports for its whole major version, so helper, init image and service stay compatible without a separate handshake. In data-science-pack, whose hub config is a set of executed (not imported) files built from explicit `.Files.Get` calls (`dsp/templates/hub-config.yaml:92-96`), the helper's source is concatenated ahead of `04-user-secrets.py` inside one template block that renders only when the integration is enabled; in dask-gateway-pack it is inlined the same way into the `usersecrets` `extraConfig` block. The init image reference is a value in each consumer chart, defaulting to the digest the helper release pins, so mirrored or air-gapped registries can override it without re-vendoring.

**Notebook and jhub-apps (data-science-pack, `userSecrets.enabled`, default false).**

- Settings are applied in a KubeSpawner `modify_pod_hook`, which runs on the final pod manifest after profile overrides (`load_user_options`, `kubespawner/spawner.py:3066`) and after jhub-apps sets its command in `start()` (`jhub_apps/spawner/spawner_creation.py:285` at 2026.8.1), at `spawner.py:3151-3154`. A deployer-set `modify_pod_hook` is chained, not replaced. (Decided; this replaces applying them in `_pre_spawn_hook`, where both profile overrides and jhub-apps' command overwrite them.)
- The hook reads `sub` from `auth_state["oauth_user"]["sub"]` (read the same way at `00-gateway-auth.py:428`); if absent, it changes nothing. A small adapter in `04-user-secrets.py` converts between KubeSpawner's `V1Pod` and the helper's dicts.
- App: `jhub-apps` when the spawner is a jhub-apps spawner (the class jhub-apps derives from `_NebiKubeSpawner`, `02-jhub-apps.py:74-84`), else `notebook`. (Decided; planning confirms the attribute jhub-apps sets.)
- With `userSecrets.exportEnv` (default true when enabled), the wrapper is prepended to the notebook container's `args`, ahead of dsp's umask wrapper (`01-spawner.py:114-119`).
- dsp's single-user pods already set `fsGroup: 100` (`01-spawner.py:182-183`); the helper keeps it.
- The hub is the creator (`system:serviceaccount:<ns>:hub`), allowed its user namespace and apps `notebook` and `jhub-apps`.

**Hub identity endpoint (data-science-pack).** `GET /hub/api/user-secrets/identity`, authenticated by a JupyterHub token carrying the custom scope `custom:user-secrets-identity` (`custom_scopes`, `jupyterhub/app.py:356`), returns `{"sub": "<sub>"}` for that token's owner, read from `auth_state`. It is registered with `extra_handlers` (`app.py:1708`), which JupyterHub 5.5.0 marks deprecated in favour of services (`app.py:1708-1723`). **Decided: keep `extra_handlers` for the MVP**, because a hub-managed service would need `admin:auth_state` to read `sub`, which exposes every user's refresh token to that service. Removal tracking: a follow-up issue to propose a narrower upstream scope or to store `sub` outside `auth_state`. When enabled, the scope is added in place to the `user` role (as dsp already extends it, `02-jhub-apps.py:91-104`), because a server token's scopes are limited to what its owner holds (JupyterHub 5.5.0 `user.py:802-851`). dsp defines no `server` role today, so it defines one explicitly, restating JupyterHub's defaults (`users:activity!user`, `access:servers!server`, `jupyterhub/roles.py:54-58`) plus the new scope. When disabled, neither role is touched. A test spawns a server and checks its token's scopes. Every request passes through JupyterHub's `refresh_auth`, and dsp's `refresh_user` returns False on `invalid_grant` (`00-gateway-auth.py:351-352`, `auth_refresh_age = 240` at `:592`), so the endpoint works only while the user's Keycloak session lives; this matches the gateway's own `/user` check.

**Dask (dask-gateway-pack, `userSecrets.enabled`, default false).** A config hook in the existing `gateway.extraConfig`:

- subclasses `JupyterHubAuthenticator`: after the parent's `authenticate()` succeeds, it calls the hub identity endpoint with the user's JupyterHub token and attaches `secrets_sub` to the `User` (it has to happen in `authenticate()`: the options handler is synchronous and receives only `User(name, groups, admin)`, `options.py:106-108`, `models.py:54-57`, and later requests authenticate from a cookie cache, `auth.py:84-107`);
- wraps the options handler (dask-gateway-pack ships none by default; deployers write one in `extraConfig`, `chart/values.yaml:189-205`), merging the helper's `dask_options` into the returned config: `*_extra_pod_annotations` (`backends/kubernetes/backend.py:237-265`), `*_extra_pod_config` with the ServiceAccount (unless the deployer set one), `automountServiceAccountToken: false`, `securityContext.fsGroup`, `initContainers` and `volumes` (deep-merged, lists appended, `controller.py:1192-1193`), `*_extra_container_config` with the mounts, and with `exportEnv` the wrapper prepended to `worker_cmd` and `scheduler_cmd` (`dgsrc/base.py:247`, `controller.py:1031`, `:1054`). These are not declared option fields, so a user cannot set them (`options.py:87-91`). Both forms of `c.Backend.cluster_options` are wrapped: an `Options` object and a callable returning per-user options (`dgsrc/base.py:89-92`). The block is named so it sorts after every deployer block, and at config load it raises if the final `cluster_options` is not wrapped, so a misordered or unrecognised handler fails loudly instead of silently dropping the settings.

Every scheduler and worker pod resolves at its own start, so workers added hours later get the secrets without any Keycloak session. The creator is the controller's ServiceAccount, allowed app `dask` in registered Dask namespaces only, and the gateway API is a trusted input (see "Pod identity and the guard").

## Storage

- One Kubernetes Secret per owner, in the service's own namespace, named `us-<sub>` (Keycloak `sub` is a UUID, which is a valid name). Only the service's ServiceAccount can read Secrets in that namespace.
- Each Secret holds one JSON document (`record.json`) with the owner's secrets and enablements (see Data models). Values are stored as base64-encoded bytes, so any byte sequence round-trips. Writes use `resourceVersion` optimistic concurrency.
- A second per-owner Secret `us-<sub>-status` holds delivery status per app (last success time and count, last failure time and reason), written at most once a minute per app per replica, so resolve traffic never contends with management writes. Writes are best-effort: a failed write is logged and never fails the resolve. Status is recorded only for a pod that passed verification (UID matched, annotations read from the API server) while the guard is verified or overridden, so an untrusted annotation can never write into another user's status. Earlier failures appear only in the pod's `.status` and in `resolve_denied` audit lines.
- No application-level encryption in the MVP. Encryption at rest is whatever the cluster's etcd provides. Follow-up: split sealing from opening, as Javo does (`javo` `site/src/content/docs/admin/secrets-and-keys.md` at `6228cdf`). `record.json` carries `schema_version`.
- Limits enforced on write: at most 50 secrets per user, each value at most 32 KiB, and the whole encoded `record.json` at most 512 KiB, which keeps it under the 1 MiB Secret limit with margin. Names match `^[A-Za-z_][A-Za-z0-9_]{0,63}$`. The management API reports usage against these limits.

## Management API

The service serves no UI. Users manage secrets on the Nebari landing page, which calls this API; the landing page side is tracked in [nebari-dev/nebari-landing#236](https://github.com/nebari-dev/nebari-landing/issues/236).

- **Cluster-internal only.** The API listens on its own port, `:8444`, of the in-cluster `Service`, over the same TLS as resolve. There is no `NebariApp`, `HTTPRoute` or landing page tile for the service. The service's NetworkPolicy admits `:8444` only from the landing frontend pods (namespace and pod selector from values), and `:8443` (resolve) only from registered workload namespaces, so neither side can reach the other's port.
- **Reached through the landing page's nginx.** The landing frontend's nginx already proxies `/api/` to `nebari-webapi`'s ClusterIP and passes `Authorization` through unchanged (`nebari-landing` `charts/nebari-landing/templates/frontend/configmap.yaml` at `6f9b9f9`). It adds `location /api/user-secrets/`, forwarding to `https://user-secrets.<service-namespace>.svc:8444/api/v1/` and verifying the service against the `user-secrets-ca` ConfigMap the service publishes into the landing namespace (the same mechanism as consumer namespaces). The browser calls the API directly with the user's keycloak-js access token; `nebari-webapi` is not involved.
- **Authentication** per "Identity rules": a Keycloak access token whose `azp` is the landing page's SPA client. Every route acts only on the token's `sub`; no route takes a user as input.
- **Values are write-only.** No response contains a value or any part of one.
- **What the landing page shows** is its own concern, tracked in nebari-landing#236; the API returns what it needs: per secret its name, description, last update, bindings with full names (`NEBARI_SECRET_<SUFFIX>`) and file paths, and per app the last delivery; usage against the limits; the registered apps; and the guard state for the admin notice. The landing page also carries the user-facing text this design relies on: the Dask sharing warning, "Anything started before now still has the old value until it restarts" after a rotate or delete, and the `NEBARI_SECRET_` usage example.
- **What the landing proxy must tolerate** (requirements on nebari-landing, tracked in #236): the landing page must start and serve everything else when user-secrets is not installed, not yet ready, or has not yet filled `user-secrets-ca`; only `/api/user-secrets/` fails. In nginx terms that means resolving the service name at request time rather than at startup, and not referencing an empty CA file. The integration is off by default in the landing chart.
- **Text input.** The API stores the bytes it is given. The landing page normalises text-field input to LF line endings before encoding it (browsers submit CRLF) and says so; a file upload is sent byte for byte.

## Names and values

**Every name the service delivers is `NEBARI_SECRET_<SUFFIX>`**, both as the file name and as the env var name when exported. The user picks only the suffix (`^[A-Z][A-Z0-9_]{0,63}$`) and the service adds the prefix.

Why: when a pack exports secrets as env vars, a user-chosen name can turn a secret write into code execution or traffic interception (`LD_PRELOAD`, `PYTHONSTARTUP`, `PYTHONPATH`, `BASH_ENV`, `NODE_OPTIONS`, `GIT_SSH_COMMAND`, `HTTPS_PROXY`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `PIP_INDEX_URL`), and a denylist of such names can never be complete. A prefix that no program reads by default closes the class and keeps file names free of path characters.

Cost: tools that read a conventional name such as `OPENAI_API_KEY` do not pick the secret up on their own. The user passes it in code, e.g. `OpenAI(api_key=os.environ["NEBARI_SECRET_OPENAI"])`. The landing page shows this example.

Enforcement: the service validates the suffix and applies the prefix at write and checks the full name again at resolve; `user-secrets-init` writes only names matching `^NEBARI_SECRET_[A-Z][A-Z0-9_]{0,63}$`, and `user-secrets-env` exports only those.

**Values arrive byte for byte** from storage to the file: values are stored as bytes (base64 in JSON), files hold the exact bytes, and the wrapper passes them to `execve` unchanged. The one documented exception is text-field input, which the landing page normalises to LF before sending it.

## Identity rules

- **Durable identity is the Keycloak `sub`.** Usernames are display only.
- **The management API accepts only tokens issued to the landing page:** RS256 signature against the realm JWKS selected by `kid`, `iss` in {public realm URL, internal realm URL}, `exp` enforced, `typ == "Bearer"` (Keycloak's access-token type, so an ID token for the same client is rejected), and `azp == <landing SPA client id>` (a chart value; nebari-landing's default is `<namespace>-<fullname>-spa`, `charts/nebari-landing/templates/frontend/configmap.yaml` at `6f9b9f9`). A token issued to any other client for the same user, including one forwarded to another `NebariApp` with `forwardAccessToken`, gets `401`. There is no CSRF token: the API reads only the `Authorization` header, never a cookie, so the browser sends no credential on its own and another site cannot obtain the user's token to send one.
- **Resolve accepts only projected, pod-bound ServiceAccount tokens** with audience `user-secrets`, checked by TokenReview. No Keycloak token is accepted at resolve.
- The service re-verifies every token itself. It never trusts a forwarded identity header.

## Audit

- `secret_read`, one line per secret returned: `{"event":"secret_read","owner_sub":..,"reader_sub":..,"secret":<name>,"app":..,"pod":"<ns>/<name>","pod_uid":..,"sa":..,"guard":"enforced"|"overridden","ts":..}`.
- `resolve_denied`: pod, sa, reason (`not_pod_bound`, `uid_mismatch`, `not_annotated`, `not_registered`, `pod_predates_guard`, `guard_not_verified`).
- `secret_write` for management API writes, with owner, actor, secret and action.
- `guard_state` on every state change (`verified`, `confirmed_bad` with reason, `unknown`, `overridden`).
- Logging is configured at the service entrypoint (JSON to stdout), and a test asserts lines are emitted through the real logging configuration. Never logged: values, tokens.

## Operations

- **Replicas.** Two replicas behind the `Service`, with a PodDisruptionBudget of one. State lives only in Kubernetes Secrets, so replicas share nothing in memory; each runs its own guard watch and probe, and a replica that is not verified answers `503` while the other may answer. Rolling updates keep at least one replica serving.
- **Failure visibility.** The init container's `.status`, the wrapper's stderr warning, the `us-<sub>-status` record returned by the management API and shown on the landing page, `resolve_denied` audit lines for admins, and `strict` mode for consumers that prefer a blocked start.

## Future-proofing

1. **Ownership and access are separate fields.** Each secret has `owner_sub` and `grants` (empty in the MVP).
2. **The resolve API answers "what can this principal use in this app".** Shared secrets would appear without consumer changes.
3. **Names live on the binding and belong to the consuming principal.** A grant shares a value, never a name.
4. **Audit records distinguish owner and reader** from day one.
5. **The reader is a principal, not necessarily a person.** Records key on `sub`; `Grant.Kind` allows values beyond `user` and `group`.
6. **Background workloads use service (bot) accounts (design after the MVP).** A background workload's pod is created by a registered creator with the service account's `sub` in the annotation. Where it must also call Keycloak, Keycloak's federated client authentication accepts a Kubernetes ServiceAccount token instead of a client secret, supported since Keycloak 26.6 ([release notes](https://www.keycloak.org/2026/04/keycloak-2660-released), [blog](https://www.keycloak.org/2026/01/federated-client-authentication)); to be tested on NIC's pinned `26.8.1`.
7. **Live refresh needs no new identity.** The pod-bound token can be presented again while the pod lives. It must then allow running pods that predate a later `verifiedSince` move caused by a legitimate change, for example by recording each pod's first successful resolve.
8. **Narrowing what a shared server exposes.** Drop `custom:user-secrets-identity` from tokens of servers that currently have shares, so a sharee cannot use the owner's token to reach Dask bindings.
9. **Cut from the MVP on 2026-11-10: a signed-assertion fallback and a Go helper.** If deployments that decline the policy become common, add a creator-signed assertion mode: bind notebook assertions to the pod name, give Dask assertions a renewable bound (dask-gateway has only `idle_timeout`, `dgsrc/base.py:339`), and keep a replay store for `jti`. Add a Go helper when a Go consumer such as Javo adopts the contract.

## Implementation defaults

- **Go** for the service and the init binary: static binaries on `gcr.io/distroless/static:nonroot`; a single-file Python helper and Python hooks for the consumers.
- Observability follows NIC's conventions: OpenTelemetry span per exported function in `internal/`, `slog` JSON only in `cmd/` and the HTTP layer, audit through an `AuditSink`.
- The JWT/JWKS library is chosen at plan time after reading its source at the pinned version.
- Values write-only through the management API; no application-level encryption; limits as in "Storage".
- No UI in the service; management API on its own port, reachable only from the landing frontend pods.
- Per-secret files; projected token only in the init container; files `0440` with `fsGroup`.
- Default failure mode `soft`; `strict` available per consumer.
- Guard: watch plus dry-run probe, 2-minute grace for "unknown".
- One security mode plus the explicit override.
- The helper is vendored into consumer charts rather than installed in images.
- `extra_handlers` kept for the identity endpoint, with a removal follow-up.
- In-cluster TLS from a cert-manager CA kept in the service namespace; the service publishes the CA to registered namespaces and the landing namespace (trust-manager is not always installed).
- Two admission policies (A always on, B allowlist selected by a pod label), tested on kind against 1.30, 1.32 and 1.34; the case matrix is a CI test.

## Open questions to verify during planning (verifications, not design decisions)

1. The attribute or class check that identifies a jhub-apps spawner in a `modify_pod_hook` at jhub-apps 2026.8.1.
2. That access tokens keycloak-js obtains for the landing page carry `azp = <landing SPA client id>`, `typ = "Bearer"` and the realm `iss` the service expects, and that ID tokens carry a different `typ` (decode real tokens on a dev cluster).
3. The decorator or manual check a JupyterHub 5.5.0 `extra_handlers` handler uses to enforce a custom scope.
4. That a dask-gateway options handler may return the pod, container, annotation and command settings listed above and that they reach the pods at 2026.3.0.
5. That cert-manager's namespaced CA chain (self-signed `Issuer`, CA `Certificate`, CA `Issuer`) works at NIC's pinned cert-manager version.
6. The `fsGroup` behaviour of `emptyDir` volumes (group ownership and setgid on files written by a UID-65532 init container), that the wrapper volume allows execution, and the built init binary's size.
7. The pod-manifest golden harnesses, which neither repo has today: instantiating dsp's configured KubeSpawner against a mocked hub and calling `get_pod_manifest`, and calling dask-gateway's controller `make_pod` with a rendered config.
8. How Argo CD is kept from reverting the service-filled `data` of each consumer's and the landing page's `user-secrets-ca` ConfigMap (server-side diff with field managers, or `ignoreDifferences`) under NIC's Argo CD settings.
9. How NIC passes matching values to both charts (in user-secrets: the landing namespace, frontend pod selector and SPA client id, which nebari-landing lets deployers override with `frontend.keycloak.clientId`; in nebari-landing: the service address and the integration toggle), and the Argo CD sync order between them. A wrong client id gives `401` on every management call; a wrong namespace or selector makes the NetworkPolicy block the landing page.

Already established by the policy test matrix: TokenReview of a pod-bound token carries `pod-name` and `pod-uid` in `extra` at 1.30; every policy rule, the missing-ConfigMap behaviour and the probe behave as designed (see "Pod identity and the guard").

## Program Design

**Scale:** full

### Existing patterns

| Pattern | Tag | Source | Promote? |
|---|---|---|---|
| Packs expose themselves through a `NebariApp` CR (routing, TLS, Keycloak client provisioning, landing tile). Deliberately not followed: the service has no external surface | [documented: software-pack-template docs/nebariapp-crd-reference.md] | `tmpl/docs/nebariapp-crd-reference.md`, `dsp/templates/nebariapp.yaml` | n/a |
| Landing page backends are cluster-internal; the landing frontend's nginx proxies a path to them with the Bearer header unchanged, and they validate the keycloak-js token themselves | [documented: nebari-landing chart comments and ADR] | `nebari-landing` `charts/nebari-landing/templates/frontend/configmap.yaml`, `frontend/src/api/client.ts` at `6f9b9f9`; `nebari-operator` `docs/decisions/2026-03-05-webapi-extracted-to-nebari-landing.md` | n/a |
| Go services in nebari-dev use `cmd/<binary>` + `internal/<pkg>` layout and a distroless nonroot image | [inferred] | `nebari-operator/cmd/operator`, `nebari-operator/internal/`, `nebari-operator/Dockerfile:26` | pending |
| Hub-side per-user pod customisation reads `auth_state` and appends to init containers, volumes and mounts | [inferred] | `dsp/config/jupyterhub/01-spawner.py:266`, `:957`, `:1185`, `:1421-1460` | pending |
| dsp extends built-in hub roles in place in `load_roles`, never by redefining them | [inferred] | `dsp/config/jupyterhub/02-jhub-apps.py:91-104` | pending |
| dask-gateway-pack customisation goes through `gateway.extraConfig` blocks, including deployer-written options handlers | [documented: dask-gateway-pack chart/values.yaml:188-208] | `dask-gateway-pack/chart/values.yaml` | n/a |
| Render-time chart guardrails in a `validate.yaml` template that `fail`s on unsafe values | [inferred] | `external-auth-pack/chart/templates/validate.yaml` | pending |

### Component contracts

| Contract | Status | Owner | Consumers | Verified by | Promote? | Notes |
|---|---|---|---|---|---|---|
| `POST /api/v1/resolve` (resolve API) | new | nebari-user-secrets | `user-secrets-init` in every consumer's pods | n/a (new) | n/a | Pod-token auth only, TLS |
| Consumer contract (`docs/architecture/contracts.md`) | new | nebari-user-secrets | every consuming pack | n/a (new) | n/a | Eleven rules |
| Helper `nebari_user_secrets.py` (single file, standard library only) | new | nebari-user-secrets | consumer charts (vendored) | n/a (new) | n/a | Builds and applies pod settings; pins the init image |
| Pod label `nebari.dev/user-secrets` and annotations `nebari.dev/user-secrets-sub`, `-app` | new | nebari-user-secrets | creators (write), the service and the policies (read) | n/a (new) | n/a | Guarded by policies A and B |
| File layout under `/var/run/nebari/secrets` | new | nebari-user-secrets | consumer workloads and user code | n/a (new) | n/a | The delivery contract |
| `user-secrets-env -- <cmd>` wrapper behaviour | new | nebari-user-secrets | consumers that export env | n/a (new) | n/a | Never replaces a set variable |
| Cluster bundle (`cluster/`, `cluster/REVIEW.md`) | new | nebari-user-secrets | the cluster's Kubernetes team | n/a (new) | n/a | Two policies with bindings, auth-delegator binding, reader role |
| Creator registry and `user-secrets-creators` ConfigMap | new | nebari-user-secrets | the policy (params), the service (guard check) | n/a (new) | n/a | Creator → namespaces, apps |
| `user-secrets-ca` ConfigMap | new | nebari-user-secrets | consumer pods, the landing frontend nginx | n/a (new) | n/a | Published by the service into each registered workload namespace and the landing namespace |
| Management API `/api/v1/secrets`, `/api/v1/apps`, `/api/v1/status` on `:8444` | new | nebari-user-secrets | the landing page (nebari-landing#236) | n/a (new) | n/a | Landing SPA tokens only, cluster-internal, TLS |
| Landing nginx `location /api/user-secrets/` → management API | new | nebari-landing | browsers on the landing page | n/a (new; nebari-landing#236) | n/a | Passes `Authorization` unchanged; verifies TLS with `user-secrets-ca` |
| Owner record `record.json` in `us-<sub>`; status record in `us-<sub>-status` | new | nebari-user-secrets | nebari-user-secrets only | n/a (new) | n/a | Versioned with `schema_version` |
| Audit log line format | new | nebari-user-secrets | admins, log pipelines | n/a (new) | n/a | `secret_read`, `resolve_denied`, `secret_write`, `guard_state` |
| `GET /hub/api/user-secrets/identity` | new | data-science-pack | dask-gateway-pack authenticator | n/a (new) | n/a | Scope `custom:user-secrets-identity` on the `user` and `server` roles |
| dask-gateway-pack DaskCluster policy | new | dask-gateway-pack | the cluster's Kubernetes team | n/a (new) | n/a | Only the gateway API writes annotated `spec.config` |
| `c.KubeSpawner.modify_pod_hook` | changed-compatible (implicit) | data-science-pack | dsp | `rg -n "modify_pod_hook" dsp/` returns no matches (re-run 2026-11-10) | pending | New hook; chains any deployer-set hook |
| `_pre_spawn_hook` step order | unchanged (implicit) | data-science-pack | data-science-pack tests | `rg -n "orders_merge_ca_before_nebi_pull" dsp/tests` | pending | Untouched; user-secrets no longer uses it |
| `c.KubeSpawner.cmd` shape | unchanged (implicit) | data-science-pack | single-user images | `rg -n "KubeSpawner\.cmd" dsp/config` (one assignment, `01-spawner.py:114`) | pending | The wrapper goes into the pod's `args` in `modify_pod_hook`; `cmd` itself is untouched |
| `server` role scopes | changed-compatible (implicit) | data-science-pack | single-user servers | `rg -n "server_token_scopes|\"name\": \"server\"" dsp/config` | pending | When enabled: `server` role defined with defaults restated plus the scope; scope added to `user` in place |
| dask-gateway authenticator / `User` / options handler / `KubeClusterConfig` pod fields | unchanged | dask (upstream) | dask-gateway-pack config hook | `rg -n "async def authenticate|def __init__\(self, name, groups|return self.handler\(" dgsrc/auth.py dgsrc/models.py dgsrc/options.py` | n/a | Subclassed and configured, not modified |

**Resolve API.** `POST /api/v1/resolve` over TLS with `Authorization: Bearer <projected ServiceAccount token>` and no body. Promises: `200 {"secrets": [{"env": "NEBARI_SECRET_<SUFFIX>", "value_b64": "<base64>"}, ...]}` containing exactly the secrets the pod's annotated `sub` may use with `enabled` for the pod's annotated app. Requires: TokenReview with audience `user-secrets` succeeds and names a pod; that pod exists with the same UID; it carries the label and both annotations; its `creationTimestamp` is later than `verifiedSince` (policy mode); the pod's `namespace/serviceaccount` is registered for the app; the guard is verified or overridden. Errors: `401` token fails TokenReview or is not pod-bound; `403` pod missing, UID mismatch, annotation missing, not registered, or `pod_predates_guard`; `503 guard_not_verified`; `503` Kubernetes API unavailable. Never returns another user's secrets.

**Management API.** Over TLS on `:8444`, every route with `Authorization: Bearer <Keycloak access token>` meeting "Identity rules", acting only on the token's `sub`. The landing page reaches it as `/api/user-secrets/...`, which its nginx maps to `/api/v1/...`.

- `GET /api/v1/secrets` → `200` `OwnerView`: the secrets with their bindings (suffix, full name and file path), delivery status per app, and usage. `usage.bytes` is the size of the encoded `record.json`, the quantity the 512 KiB limit applies to.
- `PUT /api/v1/secrets/{name}` with `{"description", "value_b64", "bindings": [{"app", "env"}]}` → `201` created or `200` updated, body a `SecretSummary`. `description` and `bindings` replace the stored ones wholesale. `value_b64` is required on create; on update, present rotates the value and absent keeps it.
- `DELETE /api/v1/secrets/{name}` → `204`.
- `GET /api/v1/apps` → `200 {"apps": [<app id>, ...]}`, the registered apps a binding may name.
- `GET /api/v1/status` → `200 {"guard": {"state", "mode", "reason"}}`, so the landing page can show the admin notice. It is returned to any authenticated user, since it only says whether delivery is working; the landing page decides who sees the notice.

Errors carry an `APIError` body, `{"error": "<code>", "detail": "..."}`: `401 invalid_token` (bad token, wrong `azp`, or not an access token); `400 invalid_name`, `invalid_suffix`, `unknown_app`, `grants_not_supported`, `limit_exceeded`; `404 not_found`; `409 env_conflict` (that suffix is already bound for that app); `503 kubernetes_unavailable`. No response contains a value.

**Hub identity endpoint.** `GET /hub/api/user-secrets/identity` with `Authorization: token <JupyterHub token>`. Promises: `200 {"sub": "<sub>"}` for the token's owner. Errors: `403` missing scope or the hub rejected the token (expired Keycloak session), `404` no `sub` in `auth_state`. Never another user's `sub`, never a token.

**Name collisions.** Nothing in the hub, the operator or dask-gateway-pack uses the `NEBARI_SECRET_` prefix (`rg -n NEBARI_SECRET dsp dask-gateway-pack nebari-operator` returns no matches, re-run 2026-11-10). The wrapper never replaces a set variable.

### Data models and types

```go
// internal/model/model.go
package model

import "time"

type AppID string // must exist in the app registry

type Binding struct {
	App AppID  `json:"app"`
	Env string `json:"env"` // suffix only; delivered as NEBARI_SECRET_<Env>
}

type Grant struct {
	Kind    string `json:"kind"`    // "user" | "group"; unused in MVP
	Subject string `json:"subject"`
}

type SecretEntry struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Value       []byte    `json:"value"` // base64 in JSON; <= 32 KiB
	Bindings    []Binding `json:"bindings,omitempty"`
	Grants      []Grant   `json:"grants,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type OwnerRecord struct {
	SchemaVersion int           `json:"schemaVersion"` // 1
	OwnerSub      string        `json:"ownerSub"`
	OwnerUsername string        `json:"ownerUsername"`
	Secrets       []SecretEntry `json:"secrets"` // <= 50; encoded record <= 512 KiB
}

type DeliveryStatus struct {
	App         AppID     `json:"app"`
	LastOK      time.Time `json:"lastOk,omitempty"`
	LastCount   int       `json:"lastCount,omitempty"`
	LastFailure time.Time `json:"lastFailure,omitempty"`
	LastReason  string    `json:"lastReason,omitempty"`
}

type Principal struct {
	Kind     string // "user" in the MVP; "service-account" later
	Sub      string
	Username string // empty when the principal comes from a pod annotation
	Groups   []string
}

type PodIdentity struct{ Namespace, Name, UID, ServiceAccount string }

type PodClaim struct {
	Pod       PodIdentity
	App       AppID
	Principal Principal
}

type GuardMode string // "enforced" | "overridden"

type ResolvedSecret struct {
	Env   string
	Value []byte
}

// Management API wire types. These are the contract nebari-landing builds against.
type BindingView struct {
	App  AppID  `json:"app"`
	Env  string `json:"env"`  // suffix as stored
	Name string `json:"name"` // NEBARI_SECRET_<Env>
	Path string `json:"path"` // /var/run/nebari/secrets/NEBARI_SECRET_<Env>
}

type SecretSummary struct {
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Bindings    []BindingView `json:"bindings"`
	UpdatedAt   time.Time     `json:"updatedAt"`
}

type Usage struct {
	Count    int `json:"count"`    // secrets stored
	MaxCount int `json:"maxCount"` // 50
	Bytes    int `json:"bytes"`    // size of the encoded record.json, the quantity the 512 KiB limit applies to
	MaxBytes int `json:"maxBytes"` // 524288
}

type OwnerView struct { // GET /api/v1/secrets
	Secrets    []SecretSummary  `json:"secrets"`
	Deliveries []DeliveryStatus `json:"deliveries"` // per app, not per secret: an app's last failure may concern no secret
	Usage      Usage            `json:"usage"`
}

type APIError struct { // body of every management API error
	Error  string `json:"error"`            // machine-readable code, listed under "Management API"
	Detail string `json:"detail,omitempty"` // human-readable; never contains a value
}

type Creator struct {
	Username   string   // system:serviceaccount:<ns>:<name>
	Namespaces []string
	Apps       []AppID
}
```

Invariants: `name` unique within a record; within one app, `env` unique across a user's bindings; writes with non-empty `grants` rejected in the MVP.

### Method signatures

```go
// internal/auth
type JWKSSource interface{ Key(ctx context.Context, kid string) (crypto.PublicKey, error) }
func NewSessionVerifier(jwks JWKSSource, issuers []string, clientID string) *SessionVerifier // clientID: the landing SPA client; azp must equal it
func (v *SessionVerifier) Verify(ctx context.Context, bearer string) (model.Principal, error)

// internal/podidentity
type TokenReviewer interface {
	Review(ctx context.Context, token string, audiences []string) (authenticationv1.TokenReviewStatus, error)
}
type PodGetter interface{ GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) }
type Registry interface {
	WorkloadAllowed(app model.AppID, namespace, serviceAccount string) bool
	Creators() []model.Creator
	Apps() []model.AppID // for GET /api/v1/apps
}
func NewPodVerifier(r TokenReviewer, p PodGetter, reg Registry) *PodVerifier
func (v *PodVerifier) Verify(ctx context.Context, bearer string) (model.PodClaim, error)

// internal/guard
type AdmissionWatcher interface { // informers on the policy, binding and ConfigMap
	Policies() (guard, creators *admissionregistrationv1.ValidatingAdmissionPolicy, ok bool)
	Bindings() (guard, creators *admissionregistrationv1.ValidatingAdmissionPolicyBinding, ok bool)
	Creators() (*corev1.ConfigMap, bool)
	Synced() bool
}
type Prober interface{ Probe(ctx context.Context) (ProbeResult, error) } // three dry-run creates: labelled (B denies), unlabelled annotated (A denies), canary (admitted)
type GuardState struct {
	State  string // verified | confirmed_bad | unknown
	Mode   model.GuardMode
	Reason string
}
func NewGuard(w AdmissionWatcher, p Prober, expected Expectation, configuredMode model.GuardMode, grace time.Duration, now func() time.Time) *Guard
func (g *Guard) Evaluate(ctx context.Context) GuardState // on watch events and every 5 minutes
func (g *Guard) Allows() (model.GuardMode, bool)
func (g *Guard) State() GuardState // for GET /api/v1/status
func (g *Guard) VerifiedSince() time.Time // monotonic; persisted in the user-secrets-guard-state ConfigMap

// internal/store
type SecretStore interface {
	Get(ctx context.Context, ownerSub string) (*model.OwnerRecord, string, error)
	Put(ctx context.Context, rec *model.OwnerRecord, expectedVersion string) (string, error)
	Delete(ctx context.Context, ownerSub string) error
	RecordDelivery(ctx context.Context, ownerSub string, s model.DeliveryStatus) error // rate-limited per app
	Deliveries(ctx context.Context, ownerSub string) ([]model.DeliveryStatus, error)
}
func NewKubernetesSecretStore(c kubernetes.Interface, namespace string) *KubernetesSecretStore

// internal/audit
type AuditSink interface {
	SecretRead(ctx context.Context, ownerSub, readerSub, secret string, c model.PodClaim, g model.GuardMode)
	ResolveDenied(ctx context.Context, pod model.PodIdentity, reason string)
	SecretWrite(ctx context.Context, ownerSub, actorSub, secret, action string)
	GuardChanged(ctx context.Context, state, mode, reason string)
}
func NewSlogAuditSink(l *slog.Logger) *SlogAuditSink

// internal/service
func NewSecretService(s SecretStore, a AuditSink, l Limits) *SecretService
func (s *SecretService) ListForOwner(ctx context.Context, u model.Principal) (model.OwnerView, error)
func (s *SecretService) Upsert(ctx context.Context, u model.Principal, in UpsertInput) error
func (s *SecretService) Delete(ctx context.Context, u model.Principal, name string) error
func (s *SecretService) Resolve(ctx context.Context, c model.PodClaim, g model.GuardMode) ([]model.ResolvedSecret, error)

// internal/initfiles (cmd/user-secrets-init)
type ResolveClient interface{ Resolve(ctx context.Context, token string) ([]model.ResolvedSecret, error) }
func NewFileWriter(dir string) *FileWriter
func (w *FileWriter) WriteAll(secrets []model.ResolvedSecret) error // temp + rename, 0440, prefix-checked
func (w *FileWriter) WriteStatus(status string) error
func Fetch(ctx context.Context, c ResolveClient, tokenPath string, w *FileWriter, budget time.Duration) (status string, ok bool)
func ExecWithEnv(dir string, argv []string, environ []string, stderr io.Writer) error

```

```python
# nebari-user-secrets: python/nebari_user_secrets.py (single file, standard library only, vendored by consumers)
RESOLVE_API = "v1"
def pod_settings(sub: str, app: str, cfg: dict) -> dict: ...
def apply_to_pod(pod: dict, settings: dict) -> dict: ...   # keeps existing SA, fsGroup, volumes
def dask_options(settings: dict) -> dict: ...

# data-science-pack: config/jupyterhub/04-user-secrets.py (only when enabled)
class UserSecretsIdentityHandler(APIHandler):                            # GET /hub/api/user-secrets/identity
    async def get(self) -> None: ...
async def _user_secrets_modify_pod(spawner, pod) -> V1Pod: ...          # chained modify_pod_hook; V1Pod <-> dict adapter

# dask-gateway-pack: chart extraConfig "usersecrets" (only when enabled)
class UserSecretsJupyterHubAuthenticator(JupyterHubAuthenticator):
    async def authenticate(self, request) -> User: ...                   # super(), then hub identity endpoint
def wrap_options_handler(inner, cfg) -> Callable: ...                    # merges dask_options(pod_settings(...))
```

### Program layout

```text
nebari-user-secrets/                       (+ new repo, laid out like nebari-operator)
+ chart/values.yaml                      registry (apps, workload SAs, creators with namespaces), guard.mode, limits, TLS, landing {namespace, podSelector, clientID}
+ chart/templates/deployment.yaml        2 replicas, PodDisruptionBudget
+ chart/templates/service.yaml           ClusterIP only: https :8443 (resolve), https :8444 (management)
+ chart/templates/certificate.yaml       cert-manager self-signed CA and serving cert, all in the service namespace
+ chart/templates/creators-configmap.yaml
+ chart/templates/rbac.yaml              Role in own namespace: secrets, guard-state ConfigMap, pods create (dry-run probe only, enforced by policy A); per registered namespace: pods get, ConfigMap user-secrets-ca get/update/patch by name; landing namespace: ConfigMap user-secrets-ca get/update/patch by name
+ chart/templates/networkpolicy.yaml     ingress :8443 from registered workload namespaces; :8444 from the landing frontend pods only
+ chart/templates/validate.yaml          shared-namespace guard, mode combinations, registry sanity
+ cluster/, cluster/REVIEW.md            policies A and B with bindings, auth-delegator binding, guard-reader role
+ test/policy/run.sh                     the policy case matrix, run in CI against kind
+ cmd/user-secrets/main.go               composition root, guard watch and probe, HTTP servers
+ cmd/user-secrets-init/main.go          fetch (init container) and env (wrapper)
+ internal/model, auth, podidentity, guard, store, service, audit, httpapi, initfiles
+ python/nebari_user_secrets.py         Python helper (single file, vendored by consumers)
+ scripts/vendor-check                   CI check that a vendored copy matches a release
+ Dockerfile                             distroless static nonroot, both binaries, multi-arch
+ docs/architecture/contracts.md, AGENTS.md

data-science-pack/
+ config/jupyterhub/04-user-secrets.py   identity endpoint, role scopes, modify_pod_hook (all only when enabled)
+ files/nebari_user_secrets.py           vendored helper, concatenated ahead of 04-user-secrets.py only when enabled
~ values.yaml                            userSecrets: {enabled: false, exportEnv: true, failureMode: soft, workloadServiceAccounts}
+ templates/user-secrets-*.yaml          workload SAs, egress NetworkPolicy (only when enabled)
+ tests/golden/                          rendered chart and pod manifests from the previous release
+ tests/unit/test_user_secrets_*.py      hook, identity endpoint, user options cannot reach settings, unchanged when disabled

dask-gateway-pack/
~ chart/values.yaml                      userSecrets block; gateway.extraConfig.usersecrets
+ chart/files/nebari_user_secrets.py     vendored helper, inlined into extraConfig only when enabled
+ chart/templates/user-secrets-*.yaml    workload SA, egress (only when enabled)
+ cluster/                               DaskCluster policy + REVIEW.md
+ tests/ (new pytest harness)            hook, options merge, golden helm template when disabled

nebari-landing/                            (designed in that repo; tracked in nebari-landing#236)
~ charts/nebari-landing/templates/frontend/configmap.yaml   location /api/user-secrets/ → management API, TLS verified with user-secrets-ca
+ charts/nebari-landing/templates/...    empty user-secrets-ca ConfigMap; values to turn the integration on and name the service
+ frontend/src/...                       secrets screens, calling /api/user-secrets/ with apiFetch-style Bearer auth
```

### Call stacks

```text
Management write:
  landing page → nginx /api/user-secrets/secrets/{name} → PUT /api/v1/secrets/{name} (:8444, TLS)
    → SessionVerifier.Verify (signature, iss, exp, typ = Bearer, azp = landing SPA client) → SecretService.Upsert
    → KubernetesSecretStore.Get / Put (resourceVersion, 512 KiB cap) → AuditSink.SecretWrite

Guard (each replica):
  informer events / 5-minute tick → Guard.Evaluate
    → compare both policies, both bindings and the ConfigMap with the expectation; Prober.Probe (three dry-run creates)
    → state change → AuditSink.GuardChanged

Notebook / jhub-apps spawn (enabled):
  JupyterHub spawn → (jhub-apps start() sets cmd) → KubeSpawner._start
    → load_user_options (profile overrides) → get_pod_manifest
    → modify_pod_hook: _user_secrets_modify_pod(spawner, pod)
      → sub from auth_state; app from spawner type → pod_settings → apply_to_pod (via the V1Pod adapter)
    → create pod as hub SA → policy A (shape) and policy B (creator, namespace, app) admit
  pod: user-secrets-init fetch → POST /api/v1/resolve (TLS)
    → Guard.Allows → PodVerifier.Verify → TokenReview → GetPod → UID, annotations, registry
    → SecretService.Resolve → store Get → AuditSink.SecretRead; store.RecordDelivery
    → FileWriter.WriteAll, WriteStatus; copy self to the wrapper volume
  main container: [entrypoint] → user-secrets-env -- sh -c 'umask 0002; exec "$0" "$@"' jupyterhub-singleuser ...

Dask create and scale-up (enabled):
  client → gateway API with JUPYTERHUB_API_TOKEN
    → UserSecretsJupyterHubAuthenticator.authenticate → hub /user check → GET /hub/api/user-secrets/identity
    → cluster create → wrapped options handler → dask_options merged into spec.config
    → (dask-gateway-pack policy admits the DaskCluster write: gateway API SA)
  controller creates scheduler and worker pods at any time → policies A and B admit (controller SA, Dask namespace, app dask)
    → each pod: user-secrets-init fetch → resolve → files
```

### Component trees and DI

`cmd/user-secrets/main.go` builds the cached `JWKSSource`, `SessionVerifier`, `client-go` backed `TokenReviewer`, `PodGetter`, informer-backed `AdmissionWatcher`, dry-run `Prober`, the `Registry` (from a values-rendered config file), `PodVerifier`, `Guard` (expected policy embedded via `embed.FS` from the same YAML `cluster/` ships), `KubernetesSecretStore`, `SlogAuditSink`, `Limits` and `SecretService`, starts the informers, then passes them to the `httpapi` constructors for the resolve server (`:8443`) and the management server (`:8444`). Everything below the root takes interfaces, so tests use fakes (`client-go/kubernetes/fake`, a fake clock for the grace period). The Python helper is pure and tested once; consumer hooks are thin.

### Test approach and seams

| Boundary | Seam | Real/fake | Level | Proves |
|---|---|---|---|---|
| Management API token | `JWKSSource` | real RSA keypair, real JWT library, table-driven | unit | signature, iss, exp, azp (a token for any other client is rejected) |
| Management API | `SecretService` over a fake store, `Guard`, `Registry` | fakes, `httptest` | unit | routes act only on the token's `sub`; no response contains a value; error codes |
| Network exposure | rendered chart | `helm template` | unit | no `NebariApp` or `HTTPRoute`; NetworkPolicy admits `:8444` only from the landing selector and `:8443` only from workload namespaces |
| Pod identity | `TokenReviewer`, `PodGetter`, `Registry` | fakes, table-driven | unit | UID mismatch, missing label or annotation, unregistered SA or namespace rejected |
| Pod identity | TokenReview + pod read | real kind API server (1.30) | integration | pod-bound token passes; wrong audience fails; pod name and UID present |
| Policy | API server | real kind (1.30) with `cluster/` | integration (CI) | the policy case matrix (`test/policy/run.sh`): every A and B rule, the missing-ConfigMap behaviour, `[Warn]` admission, kubelet-minted projected token, TokenReview extras |
| Guard | `AdmissionWatcher`, `Prober`, clock | fakes for unit; real kind for integration | unit + integration | each confirmed-bad case (Warn-only, binding B narrowed or its `paramRef` changed, a `paramRef` added to binding A, an edited policy, ConfigMap drift, a probe admitted, the canary denied); a probe denied by Pod Security counts as unknown; unknown within and past grace |
| Storage | `SecretStore` | fakes and real kind | unit + integration | durability, concurrency, 512 KiB cap, byte round trip, delivery status rate limit, status written only for verified pods, failed status write does not fail resolve |
| Audit | `AuditSink` | real `SlogAuditSink` to a buffer | unit | lines emitted, no values or tokens |
| Init files and wrapper | `ResolveClient`, temp dir, real exec | fake client, real filesystem | unit | exact bytes, `0440`, prefix enforced, soft and strict modes, retries within budget, stderr warning |
| Python helper | pure functions | plain dicts, standard library only | unit | keeps existing SA, fsGroup, volumes; idempotent; dask options shape |
| Vendored helper copies | file hash | real | CI (each consumer) | the vendored copy matches the pinned release |
| Hub hook and endpoint | spawner objects, JupyterHub test app | fakes | unit (dsp) | settings on the final manifest, jhub-apps args wrapped, user options cannot reach settings, scope enforced |
| Unchanged when disabled | rendered chart and pod manifests | golden files | unit (dsp, dask-gateway-pack) | byte-identical to the previous release |
| End to end | HTTP | real service, kind, Keycloak, dsp, dask-gateway | e2e | journeys below |

## Journeys

| # | Item | Proof | Check method | Evidence |
|---|------|-------|--------------|----------|
| 1 | A user can add a secret through the management API, as the landing page does | With an access token for the configured client, `PUT /api/v1/secrets/vendor_key` returns `201`, and `GET /api/v1/secrets` lists it with its bindings; on a dev cluster the same works with a token keycloak-js obtained for the real landing SPA client. The landing screens are not part of this item; they are tracked in nebari-landing#236 | automated: `internal/httpapi` tests, and e2e on kind with a test Keycloak client that allows direct grants, set as the service's `clientID` (the same `azp` code path); narrated: dev cluster `curl` transcript with a real landing token | |
| 2 | After saving, the API never returns the value again | Every management API response for that secret (list, update, delete, errors) contains no substring of the value or its base64 | automated: `internal/httpapi` test `TestValueNeverReturned` | |
| 3 | A user can enable a secret per app and choose its suffix; the name is always `NEBARI_SECRET_<SUFFIX>` | Enabling `vendor_key` for `notebook` with suffix `VENDOR_API_KEY` shows `NEBARI_SECRET_VENDOR_API_KEY`; suffixes `ld_preload`, `A=B`, `../x` and empty are rejected; no stored record can make resolve return an unprefixed name | automated: `internal/service` tests `TestBindings`, `TestEnvNameAlwaysPrefixed` | |
| 4 | A notebook started after enabling has the secret as a file and, with `exportEnv`, as an env var; disabled means absent | File and `os.environ["NEBARI_SECRET_VENDOR_API_KEY"]` equal the stored value; after disabling and restarting both are absent and `.status` reads `ok 0` | narrated: dev cluster, terminal transcripts from two server starts | |
| 5 | A Dask cluster has the secret on the scheduler and every worker, including adaptively added ones, in either namespace layout | `client.run` and `client.run_on_scheduler` return the value after `cluster.adapt(minimum=1, maximum=4)` scales up; repeated with dask-gateway-pack in a separate namespace | narrated: notebook transcript, both layouts | |
| 6 | A jhub-apps app runs with the secrets enabled for jhub-apps, as a file and as an env var | A deployed Panel/Streamlit app shows the file present and `os.environ.get("NEBARI_SECRET_VENDOR_API_KEY") is not None` as `True`; with the binding removed and the app restarted, both are absent | automated: dsp unit test that a jhub-apps spawner's final manifest has the wrapper in `args`; narrated: dev cluster screenshots | |
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
