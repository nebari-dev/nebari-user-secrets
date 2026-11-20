# User Secrets Pack - Design

**Date:** 2026-11-10, revised 2026-11-20
**Status:** Draft for review
**Primary repo:** `nebari-dev/nebari-user-secrets` (new; deployed by NIC as foundational software, like nebari-operator, per NIC ADR-0022)
**Other repos (reference consumers for the MVP):** `nebari-dev/data-science-pack` (pod hook + hub identity endpoint), `nebari-dev/dask-gateway-pack` (gateway config hook + its own DaskCluster policy). `nebari-dev/nebari-landing` provides the secrets screens on the landing page and proxies to the management API ([nebari-dev/nebari-landing#236](https://github.com/nebari-dev/nebari-landing/issues/236)). The service has no `NebariApp`, so it does not depend on `nebari-dev/nebari-operator`. Later consumers (for example `nebari-dev/javo`, Ray) integrate through the same consumer contract.
**Requires:** NIC's always-on cluster CA (`nebari-ca-issuer`) and trust bundle (`nebari-trust-bundle`), proposed in [nebari-dev/nebari-infrastructure-core#787](https://github.com/nebari-dev/nebari-infrastructure-core/pull/787), stacked on #776.
**Supersedes:** `nebari-dev/external-auth-pack` (private, experimental; to be archived after this repo lands its first slice)

Versions this design is written against: data-science-pack `77531a4`, dask-gateway-pack `c9c2bd6`, nebari-operator `ccbc217`, external-auth-pack `568ee68`, software-pack-template `dbc89fa`, nebari-landing `6f9b9f9`, dask-gateway `2026.3.0` (upstream), JupyterHub `5.5.0` (upstream), KubeSpawner `7.0.0` (upstream, pinned by dsp `images/jupyterhub/pixi.toml:15`), jhub-apps `2026.8.1` (read by the reviewer).

## Intent

A data scientist has an API key (a data vendor token, an OpenAI key, a fine-grained GitHub PAT). Today they paste it into a notebook cell or a `.env` file in their home directory, and it does not reach the Dask clusters they launch. This component gives every Nebari user a place to store their own secrets, tied to their durable Keycloak identity, and delivers them as files at a well-known path in the workloads they choose: in the MVP, their notebook server, their jhub-apps apps, and their Dask clusters. Each consuming pack decides whether to also export them as environment variables.

**The service is independent of any software pack.** It is a platform component that owns the secrets; JupyterHub (data-science-pack), Dask (dask-gateway-pack), and later Javo, Ray or a job scheduler are consumers that meet one written consumer contract: they set a label and two annotations, and the service's injector adds the rest. No part of the service names or depends on a particular consumer. Javo (`nebari-dev/javo`) currently ships its own per-user secret store; with this decision Javo becomes a consumer, which needs agreement with its maintainer. Until then Nebari has two stores.

**Backward compatible, opt in.** NIC installs this component on every cluster, and that changes no existing workload. Every consuming pack's integration is off by default, and when it is off the pack's rendered manifests and the pods it creates are identical to the previous release, checked against committed golden files.

The threat this protects against is **other users**. Platform admins may see secret values (they can read the master key and the store's Kubernetes Secrets, and exec into pods). Per-user encryption (see "Storage") keeps values out of any copy of the owner records made without the master key, and lets a deleted user's values be destroyed. The owner may see their own values (they already have them). Another user must never obtain them, except as a direct consequence of something the owner chose to share (see below).

**Who counts as an admin:** the target is platform admins only, meaning people with Kubernetes RBAC over the cluster. **For the MVP, JupyterHub admins (the `/admin` Keycloak group, `00-gateway-auth.py:587`) are also accepted as able to see values**, because the JupyterHub 5.5.0 admin role includes `access:servers` and `shares` (`jupyterhub/roles.py`, admin role), which let them open or share any user's server. The docs and the landing page say so. Follow-up after the MVP: a custom hub admin role in data-science-pack without `access:servers` and `shares`. dask-gateway's `admin` flag grants no access to other users' clusters at `2026.3.0` (`routes.py:157-229`, `models.py:59-61`).

**Sharing a server shares everything that server can reach.** When a user shares a notebook server or jhub-apps app (sharing is on by default, `dsp/config/jupyterhub/02-jhub-apps.py:99-106`), anyone they share it with can read that pod's secret files and environment. They can also read the owner's `JUPYTERHUB_API_TOKEN` from the server's environment (JupyterHub 5.5.0 `spawner.py:1266`) and use it to start Dask clusters as the owner (dask-gateway accepts the owner's token, `dgsrc/auth.py:422-464`), which receive the owner's `dask` secrets. So sharing a server shares every secret bound to any app that server's token can launch, not only the server's own. data-science-pack's share dialog help and the landing page next to every Dask binding ([nebari-dev/nebari-landing#236](https://github.com/nebari-dev/nebari-landing/issues/236)) say: "Anyone you share a server with can start Dask clusters as you and read the secrets you enabled for Dask." Narrowing this (dropping the identity scope from tokens of shared servers) is a follow-up; see "Future-proofing".

**The landing page is inside the trust boundary for managing secrets.** The management API accepts the landing SPA's access token, which keycloak-js keeps in the landing page's JavaScript, and its NetworkPolicy admits only the landing frontend pods. A cross-site scripting bug in the landing page, or code running in its frontend pods, could therefore use a signed-in user's token to overwrite, rebind or delete that user's secrets. It could not read them (values are write-only and no response contains one), and it could not act on another user (every route acts only on the token's `sub`). Overwriting is still harmful: an attacker could swap in a credential they control and capture what the user's workloads send with it. A UI served by this service would carry the same exposure on its own origin; moving the screens to the landing page moves it into nebari-landing's code, so that repo's frontend security (content security policy, dependency hygiene, no rendering of untrusted HTML) is part of this feature and belongs in nebari-landing#236's scope.

**Principals that can issue from the cluster CA are trusted not to intercept the service.** The serving certificate comes from NIC's `nebari-ca-issuer` and clients trust it through `nebari-trust-bundle` (nebari-infrastructure-core#787). Any principal that can create a cert-manager `Certificate` or `CertificateRequest` in any namespace can get a certificate for `user-secrets.<service-namespace>.svc` (#787's `docs/internal-certificates.md`, "Who can issue"). To use it they would also need to redirect traffic for that name, for example by changing the service's `Service` or `EndpointSlice`, DNS, or the CNI. With both, they could capture an init container's projected token (600 seconds, presented once) and replay it to the real service for that pod's secrets. Accepted: a CA private to the service would remove the first half, but it needs a CA ConfigMap that the service writes into every consumer namespace and the landing namespace, and keeping Argo CD from reverting those was unsolved. `cluster/REVIEW.md` lists Certificate creation alongside the creator-impersonation precondition.

## Goals

- A user stores, rotates and deletes their own secrets from the Nebari landing page, which calls this service's cluster-internal management API (see "Management API").
- A user chooses, per secret, which apps receive it and the suffix of its name. Every delivered name is `NEBARI_SECRET_<SUFFIX>`; users never choose a full name (see "Names and values").
- Notebook servers, jhub-apps apps, and Dask clusters (scheduler and every worker, including workers added later by adaptive scaling) receive the secrets the user enabled for them, at pod start, as files under `/var/run/nebari/secrets/`. The reference consumers also export them as environment variables (opt in per pack).
- A pod's user identity comes only from a creator that is allowed to name users for that namespace and app, and is enforced by the Kubernetes API server. The service refuses to deliver when it cannot confirm that enforcement (fail closed).
- A user can see, per app, when secrets were last delivered and why the last attempt failed.
- Secrets are durable: they survive restarts and upgrades of the service and never expire or get evicted.
- Stored values are encrypted with a data key per user, wrapped by a master key that admins can rotate without re-encrypting values.
- Every read of a secret value is audited.
- Any software pack can become a consumer by meeting the consumer contract, which asks it to set a label and two annotations and nothing from this repo in its code. The service changes only by registering the new app ids.

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
- **Offboarding cleanup.** When a Keycloak user is deleted, their `us-<sub>` Secrets stay until an admin deletes them; deleting `us-<sub>` destroys that user's data key, so the values cannot be recovered from any other copy. A cleanup job or admin route is a follow-up.
- **Cloud KMS master keys.** The master key interface allows them; the MVP ships only the Kubernetes Secret implementation.
- **Installs without the TokenReview binding.** Without it the service cannot verify pods and does not deliver. Local verification against the cluster's service account issuer keys is a follow-up.

## Anti-goals

- Any path where a caller can name a user and receive that user's secrets without that identity being vouched for by a mechanism the user cannot forge. external-auth-pack had exactly this (a shared secret plus `?user=`, `chart/files/broker_server.py:99-111` at `568ee68`) and it is the reason that repo is being superseded.
- Any way for a pod to choose its own user identity, or for a creator to name users outside the namespaces and apps it is registered for.
- Treating secrets as cache entries: no TTL, no eviction, no in-memory-only store.
- Secret values anywhere but the owner record (encrypted) and the pod's in-memory volume: never in pod specs, env literals, custom resources, per-workload Kubernetes Secrets, logs, audit records, error messages, or management API responses.
- Silent failure as the only signal: a delivery failure always leaves a trace the user can see.

## Design summary

```text
Landing page (keycloak-js token) ──► landing nginx /api/user-secrets/ ──(in-cluster TLS, Bearer unchanged)──► management API :8444
                                                                    ──► K8s Secret us-<sub> (owner record, values sealed with the user's data key,
                                                                         data key wrapped by the master key in Secret user-secrets-kek)
                                                          (service runs in its own namespace; no NebariApp, no gateway route)

Creator (JupyterHub hub; dask-gateway controller fed by the gateway API), allowlisted per (namespace, app)
  └─ creates the workload pod with:
       serviceAccountName: the app's registered workload SA
       label: nebari.dev/user-secrets=true            (optional label nebari.dev/user-secrets-failure=strict)
       annotations: nebari.dev/user-secrets-sub=<sub>, nebari.dev/user-secrets-app=<app>
                    (optional: nebari.dev/user-secrets-export-env, nebari.dev/user-secrets-containers)
          │
          │  API server, mutating webhook user-secrets-injector (labelled pods only, served by the service):
          │   adds initContainer user-secrets-init + emptyDir{medium: Memory} (files) + emptyDir (wrapper)
          │   + projected SA token (aud=user-secrets) + nebari-trust-bundle, mounts, fsGroup, optional wrapper in args
          │
          │  then two ValidatingAdmissionPolicies, on the finished pod:
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
| **Mutating webhook that sets env vars** | Rejected | Literal env values land in the pod spec, which the built-in `view` role can read; a webhook that creates Secrets during admission has side effects admission should avoid. The injector chosen instead adds only delivery pieces, never values, and has no side effects. |
| **A Python helper vendored into each consumer chart** (the previous draft) | Replaced by the injector (decided 2026-11-18) | Each pack carried a pinned copy, a sync script, a CI check and the init image digest, and a non-Python consumer needed a port. The injector applies the same pieces once, after every pack-side hook, and the init image moves with the service release. Cost: a webhook in the pod-create path, scoped to labelled pods, whose outage follows the pack's failure mode. |
| **Values stored in plaintext in Kubernetes Secrets** (the previous draft) | Replaced (decided 2026-11-18) | Any copy of `us-<sub>` held readable values, and offboarding could only delete them. Envelope encryption with a key per user costs one interface and one extra Secret. |
| **One master key encrypting every value directly** | Rejected | Per-user data keys make deletion destroy the values, keep a value or key copied into another user's record from decrypting (associated data), and make master-key rotation a rewrap of 50-byte keys instead of a re-encryption of every value. |
| **A database (Postgres through CloudNativePG)** | Not now | Better audit queries and backup tooling, but a second stateful component in the foundational install. `SecretStore` is the seam if this changes. |
| **A cloud secrets manager as the store** | Not now | Identity still comes from the pod, so this is storage only, and each cloud plus local clusters needs an implementation. A cloud KMS behind the master-key interface gets the useful part: a key that never enters the cluster and the cloud's log of each unwrap. |
| **A CA private to the service, published as `user-secrets-ca` into each consumer and the landing namespace** (the previous draft) | Replaced by NIC's cluster CA (decided 2026-11-20, nebari-infrastructure-core#787) | The service needed write access to a ConfigMap in every consumer namespace, keeping Argo CD from reverting it was unsolved, and nginx's load-once CA forced a multi-CA publishing scheme. Cost: see "Principals that can issue from the cluster CA" under Intent. |
| **Vault (Agent Injector, Bank-Vaults) or External Secrets Operator** | Rejected | Both key identity on ServiceAccount or namespace, which brings back per-user ServiceAccounts. External Secrets also materialises per-workload Kubernetes Secrets, an anti-goal. A heavy dependency with no identity gain. |
| **Secrets Store CSI driver** | Rejected | Same ServiceAccount-keyed identity; synced Secrets for env use are an anti-goal. |
| **Extending Javo's store** | Not chosen | The hard part is pod identity and delivery, which is the same whichever store holds the records. Javo can become a consumer. Its split of sealing from opening informed the envelope design under "Storage". |
| **A single `.env` file** | Rejected | Dotenv has no common escaping standard, so it cannot carry arbitrary bytes. Per-secret files can. |
| **Creator-signed assertion (as the mechanism or as a fallback)** | Deferred (follow-up) | Needs no cluster-scoped objects, but signing keys may be readable by pod creators in a shared namespace, an assertion can be replayed within its lifetime unless bound to the pod name, and dask-gateway has no maximum cluster lifetime to bound Dask assertions. Cut from the MVP on 2026-11-10 to keep one security mode; see "Future-proofing". |

## Pod identity and the guard

**Annotation on a per-app ServiceAccount.** Each consumer runs its workload pods under a registered ServiceAccount per app, and its creator writes the user's `sub` and the app id as pod annotations. If a deployment already gives its workload pods a ServiceAccount (for example for cloud IAM), that ServiceAccount is registered instead of a new one. The injector never sets or changes the ServiceAccount.

**Why a guard at all.** Kubernetes lets anyone who can create pods in a namespace use any ServiceAccount, Secret or ConfigMap in it, and the built-in `edit` role can also impersonate ServiceAccounts and create ServiceAccount tokens ([RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices); `policy.go:301`, `:307` at Kubernetes v1.30.0). So any in-namespace identity is exactly as strong as the control over who can create or change pods carrying it and who can mint tokens for it.

**Trust is explicit and scoped.** The registry lists each creator with the namespaces and apps it may name users for. For each creator, the components that feed it are trusted too, and `cluster/REVIEW.md` lists them with a command to check who holds the relevant permissions:

| Creator | Allowed | Trusted inputs (must be reachable only by trusted principals) |
|---|---|---|
| JupyterHub hub ServiceAccount | its user namespace; apps `notebook`, `jhub-apps` | The hub process; `impersonate` and `serviceaccounts/token` on the hub ServiceAccount |
| dask-gateway controller ServiceAccount | registered Dask namespaces; app `dask` only | The gateway API pod (it writes `DaskCluster.spec.config`, `dg_kube_backend.py:404-411`, `:523-524`); every principal that can create or update `daskclusters` in those namespaces; `impersonate` and token creation on both ServiceAccounts |

dask-gateway-pack ships its own small ValidatingAdmissionPolicy (in its own cluster bundle, reviewed with that pack) that lets only the gateway API ServiceAccount create or update a `DaskCluster` whose `spec.config` carries `nebari.dev/user-secrets-*` annotations. A consumer whose creator builds pods from an intermediate resource guards that resource the same way; the service's policy stays consumer-neutral.

**The service runs in its own namespace.** Owner records never share a namespace with workloads or creators. The chart's `validate.yaml` fails when the service namespace appears among registered workload or creator namespaces, unless `guard.allowSharedNamespace: true` is set, which is only valid together with the override below and is documented as "every principal that can create pods in this namespace is trusted with every user's secrets".

**Two policies.** Workload pods carry a required label, `nebari.dev/user-secrets: "true"`, besides the two annotations, and the service trusts only labelled pods. The rules are split across two ValidatingAdmissionPolicies, both evaluated in the API server, so the guard itself has no webhook whose outage could block pods. (The injector below is a webhook, but it only adds delivery pieces, and its outage follows the pack's failure mode.) Validating policies run after every mutating webhook, so they see the pod as the injector left it:

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
- **Probes** every 5 minutes with three server-side dry-run creates in the service namespace, as the service's own ServiceAccount, each meeting the Pod Security `restricted` level (non-root, `RuntimeDefault` seccomp, all capabilities dropped, no privilege escalation, a pause image pinned by digest), because Pod Security and mutating webhooks run before the policies (`plugins.go:77`, `:100-101` at v1.30.0). The labelled probe passes through the injector, which declares no side effects, so its patch must keep the pod `restricted`-compliant (the injected init container runs as non-root with all capabilities dropped, `RuntimeDefault` seccomp and no privilege escalation); the probe does not carry the `strict` label, so an unreachable injector does not change its outcome: a labelled pod must be denied with policy B's message; an unlabelled annotated pod must be denied with policy A's message; a plain pod (the canary) must be admitted. Any other outcome of the first two that is not an admission (another denial, an error) counts as unknown; an admission of either, or a denial of the canary, counts as confirmed bad.
- Keeps three states: **verified**; **confirmed bad** (a watched object differs or is missing, or a probe result is wrong), which denies immediately; and **unknown** (the API could not be reached, or a probe was inconclusive), which keeps the last verified state for up to 2 minutes and then denies. While not verified, resolve returns `503 {"error":"guard_not_verified","reason":...}`.
- **verifiedSince.** A pod admitted while the guard was not enforcing (before the bundle was installed, during the `[Warn, Audit]` rollout phase, or while a binding was edited or removed) must never be trusted later, because policy A would then protect its forged annotations. Each replica fingerprints the two policies and the two bindings by `uid` and `generation` (which tracks spec edits, so chart-label changes do not count), and the ConfigMap by `uid` and `resourceVersion` (it has no `generation`), and keeps the fingerprint and `verifiedSince` in a `user-secrets-guard-state` ConfigMap in the service namespace (written with `resourceVersion` concurrency, so replicas agree). Whenever a watched object no longer matches the stored fingerprint (seen through the watch, or at startup for a change made while no replica was watching), or the guard returns to verified after a confirmed-bad state, `verifiedSince` moves forward and the new fingerprint is stored, but only once the probes pass again; the time is taken from the API server (the `creationTimestamp`-comparable time of that guard-state write) plus a fixed margin of 30 seconds, covering clock skew and the lag before a binding change takes effect on every API server. It never moves backwards. Each replica also watches the guard-state ConfigMap and uses the later of its own and the stored value. Resolve refuses any pod whose `creationTimestamp` is not later than `verifiedSince` (`403`, reason `pod_predates_guard`). A timestamp would not work: a binding's `managedFields` time does not advance when it is switched from `[Warn]` back to `[Deny]` (1.30, 1.32 and 1.34), so a pod admitted in that window would look newer than the last recorded change. `generation` reveals every spec edit and `uid` a delete and re-create. Side effect: any write to a guard object, including a policy or binding spec edit or a consumer added to the ConfigMap, moves `verifiedSince`, so a pod whose init container runs across it gets `.status` `error pod_predates_guard` and resolves after a restart. That is the conservative direction. The override mode skips this check, since it trusts creators by declaration.

**Override (last resort).** `guard.mode: unverified` delivers without any guard. The service warns at startup and on every check, shows an admin banner, and marks every audit line `"guard":"overridden"`. Setting it states that only the registered creators can create or patch pods, impersonate creator ServiceAccounts, or create tokens for them, in the consumer namespaces. The override does not cover a missing TokenReview binding. A signed-assertion fallback is a follow-up.

**Trust in creators.** A compromised hub could name any user in its namespace; it nearly can today, because it holds every logged-in user's refresh token. A compromised gateway API or controller could start Dask pods naming any user and receive that user's `dask` secrets only (the app scope stops it claiming `notebook`). Accepted for the MVP and stated in the docs.

**Cluster bundle (reviewed by the cluster's Kubernetes team).** Plain YAML in `cluster/` plus `cluster/REVIEW.md`. The service namespace appears in two places that kustomize's `namespace` setting does not touch, binding B's `paramRef.namespace` and the service ServiceAccount literal in policy A (isolated in its own CEL variable, `serviceAccount`), so the kustomization substitutes both with `replacements` from a local-only `user-secrets-install` ConfigMap (`config.kubernetes.io/local-config`, never applied; the ServiceAccount literal uses `delimiter: ":"`, `index: 2`). The spike builds and tests it with a namespace other than the default. The service renders its expected policy and binding specs for the guard comparison from the same templates and its configured namespace. Everything else the pack needs is namespaced and lives in the Helm chart.

| Object | Does | Can affect |
|---|---|---|
| `ValidatingAdmissionPolicy` + `ValidatingAdmissionPolicyBinding` `user-secrets-pod-guard` (policy A) | the always-on rules above, no parameters | **Evaluated** on every pod create and update, every pod subresource write and every ServiceAccount token request in the cluster, with `failurePolicy: Fail`. **Designed to deny only** requests carrying or gaining user-secrets metadata, `user-secrets` TokenRequests from non-kubelets, and real pod creates by the service's ServiceAccount, whether or not the ConfigMap exists. Evidence that normal operation is untouched: scheduler bindings, kubelet status updates, kubelet token minting and unrelated pods in `kube-system` all pass in the spike on every tested version; a CEL error would deny, which is why the canary probe and the CI matrix exist |
| `ValidatingAdmissionPolicy` + `ValidatingAdmissionPolicyBinding` `user-secrets-creators` (policy B) | the creator allowlist, params from the ConfigMap | labelled pod creates only; with the ConfigMap missing, every labelled pod create is denied and nothing else is affected |
| `MutatingWebhookConfiguration` `user-secrets-injector` (entries `strict` and `soft`) | adds the delivery pieces to labelled pods (see "The injector") | labelled pod creates only (`objectSelector`); never denies; while the service is unreachable, labelled pods marked `strict` are refused (`failurePolicy: Fail`) and other labelled pods start without secrets (`Ignore`). Its `cert-manager.io/inject-ca-from` annotation names the service namespace, substituted by kustomize like the other two literals. Added with the service, like the two bindings below, because it names the service's `Service` |
| `ClusterRoleBinding` to `system:auth-delegator` | lets the service create TokenReviews | the service's ServiceAccount only |
| `ClusterRole` + `ClusterRoleBinding` `user-secrets-guard-reader` | `get`, `list`, `watch` on the two policies and two bindings by `resourceNames` | read-only, four named objects |

`REVIEW.md` covers each object and why it is needed, what it can affect (including the "evaluated on all, designed to deny only" statement for policy A), the preconditions (Kubernetes 1.30 or later; the NodeRestriction admission plugin, on which the token rule relies to keep a kubelet to its own node's pods; only admins may impersonate or mint tokens for creator ServiceAccounts), the trusted-inputs table above with `kubectl auth can-i` / `kubectl get rolebindings,clusterrolebindings` checks, the policy case matrix with its saved transcripts and how to rerun it (`test/policy/run.sh` against kind), how to test before applying (`kubectl apply --dry-run=server -k cluster/`), the rollout (bindings with `[Warn, Audit]` first to observe, then `[Deny]`, at which point delivery starts for pods created afterwards), the install order (the chart, which creates the ConfigMap, before the bundle; installing them the other way round only denies labelled pods until the chart is in) and removal (the bindings before the chart; opted-in packs stop receiving secrets; nothing else changes).

## The injector

The service serves a mutating admission webhook, `user-secrets-injector`, on its own port (`:9443`) of the in-cluster `Service`. It adds every delivery piece to labelled pods, so a consumer sets only the ServiceAccount, the label and the annotations, and the init image version moves with the service release.

**Configuration.** One `MutatingWebhookConfiguration` in the cluster bundle with two entries, both for `pods` `CREATE` in API group `""`, `sideEffects: None`, `admissionReviewVersions: ["v1"]`, `reinvocationPolicy: IfNeeded`, `timeoutSeconds: 5`, and a `caBundle` filled by cert-manager's CA injector from the service's serving `Certificate` (`cert-manager.io/inject-ca-from: <service-namespace>/user-secrets-tls`; nebari-infrastructure-core#787 `docs/internal-certificates.md`, "Admission webhooks"):

| Entry | `objectSelector` | `failurePolicy` |
|---|---|---|
| `strict.injector.user-secrets.nebari.dev` | `nebari.dev/user-secrets: "true"` and `nebari.dev/user-secrets-failure: strict` | `Fail` |
| `soft.injector.user-secrets.nebari.dev` | `nebari.dev/user-secrets: "true"` and `nebari.dev/user-secrets-failure` not `strict` | `Ignore` |

No `namespaceSelector`: policy B already limits labelled pods to registered namespaces, and labelling namespaces would add a step for every consumer.

**What it adds**, to the pod as the API server has it after every earlier mutating webhook:

- the init container `user-secrets-init` (image from the service's values, defaulting to the digest the service release pins; `restricted`-compliant security context; mounts the token, the trust bundle and both volumes read-write);
- an `emptyDir` with `medium: Memory` and `sizeLimit: 1Mi` (`user-secrets-files`), mounted read-only at `/var/run/nebari/secrets`, and a disk-backed `emptyDir` (`user-secrets-bin`), mounted read-only at `/var/run/nebari/user-secrets-bin`, into each workload container;
- a projected token volume (`user-secrets-token`, `audience: user-secrets`, `expirationSeconds: 600`) mounted only into the init container;
- the `nebari-trust-bundle` ConfigMap (`optional: true`) as volume `user-secrets-trust`, mounted only into the init container;
- `securityContext.fsGroup` when the pod has none (an existing one is kept);
- with `nebari.dev/user-secrets-export-env: "true"`, `/var/run/nebari/user-secrets-bin/user-secrets-env --` prepended to each workload container's `args`, or to its `command` when the container sets `command` (both KubeSpawner and dask-gateway put the command in `args`, `kubespawner/objects.py:540`, `controller.py:1144`, so the image entrypoint still runs first).

**Workload containers.** The containers named, comma-separated, in `nebari.dev/user-secrets-containers`, or else the first container, which is the workload container in KubeSpawner and dask-gateway pods. A named container that does not exist is ignored; the injector never mounts into containers it was not told about, so a pack's sidecars receive nothing by default.

**Rules.**

- It never denies; every response is `allowed: true`, with a JSON patch or none. Admission decisions stay with policies A and B, which run after it.
- It never writes a value, never changes the ServiceAccount, labels or annotations, and never reads the owner records.
- Volume and container names starting with `user-secrets-` are reserved: an existing one is replaced, so a pod cannot pre-seed a volume the init container trusts.
- It is idempotent: a reinvocation that finds its pieces in place returns no patch, and one that finds a container added by a later webhook mounts the files into it only if it is a named workload container.
- It does not read the guard state. A pod injected while the guard is not verified simply fails to resolve.

**Failure.** When the injector is unreachable, a `soft` pod starts without any delivery piece: no files, no `.status`, no wrapper. A missing `.status` is therefore the user-visible sign of an injection failure, and the landing page's help text says so; admins see it in the API server's admission webhook metrics. A `strict` pod is refused at creation and the creator gets the API error: KubeSpawner reports a spawn failure; how the dask-gateway controller handles a refused pod is a planning verification.

**Network.** The API server must reach `:9443`; its source address depends on the cluster (control-plane nodes, or a managed control plane outside the pod network), so the service's NetworkPolicy admits `:9443` from any source. The port serves only patches and carries no values.

## Consumer contract (pack-independent)

Any software pack that wants a user's secrets in its workloads meets these rules. They are written to `docs/architecture/contracts.md` in the primary repo. The injector does the delivery work, so a consumer writes no delivery code and vendors nothing from this repo.

1. **Opt in.** The integration is off by default (`userSecrets.enabled: false`). When it is off, every change the integration makes (pod settings, hub roles and scopes, handlers, gateway hooks, NetworkPolicy, ServiceAccounts) is absent, and golden-file tests prove the rendered chart and the created pods are identical to the previous release.
2. **Register in values only.** The deployer adds the app id, its workload `namespace/serviceaccount`, and the creator's ServiceAccount with its namespaces to nebari-user-secrets's values. The service and the cluster bundle do not change.
3. **Workload ServiceAccount.** Run workload pods as the registered workload ServiceAccount, with `automountServiceAccountToken: false` when the pack creates that ServiceAccount for this purpose. If the deployment already sets one, register that one.
4. **Set the identity metadata at the last point before the pod is created**, after any profile, option or subclass logic that could overwrite it: the label `nebari.dev/user-secrets: "true"` and the annotations `nebari.dev/user-secrets-sub` and `nebari.dev/user-secrets-app`. The `sub` comes only from a source the pack authenticated itself, never from user input.
5. **Leave delivery to the injector.** Do not add the init container, its volumes, the projected token or the wrapper yourself; names starting with `user-secrets-` are reserved. Keep the workload container first, or name the workload containers in `nebari.dev/user-secrets-containers`. To export environment variables, set `nebari.dev/user-secrets-export-env: "true"`.
6. **Never let user input choose** the ServiceAccount, labels or annotations. Each consumer has a test that every user-fillable profile and option field leaves them unchanged.
7. **Allow egress** from workload pods to the service's in-cluster endpoint, through the pack's own NetworkPolicy when it has one (dsp's single-user policy pattern, `dsp/values.yaml:147-161`).
8. **Never copy values elsewhere:** no env literals in the pod spec, no Kubernetes Secrets, no custom resource fields, no logs. To expose them as environment variables, use the export annotation.
9. **Choose a failure mode** with the label `nebari.dev/user-secrets-failure`. `soft` (default, label absent): if the injector is unreachable the pod starts without delivery pieces; on a resolve failure the init container exits 0 and the workload starts without secrets. `strict` (label `strict`): the pod is refused while the injector is unreachable, and on a resolve failure the init container exits non-zero and the pod does not start. On a resolve failure the init container writes no secret files, records the reason in `.status`, and the service records the failure for the management API when the request reached it. Failures outside the init container (image pull, missing ServiceAccount) stop the pod in both modes; that is Kubernetes behaviour, not a delivery failure.
10. **Never deliver to code the user did not choose to run**, such as a build of an untrusted pull request (Javo's preview apps are an example).

## Delivery: files at a well-known path

- **Layout.** `/var/run/nebari/secrets/NEBARI_SECRET_<SUFFIX>`, one file per secret, holding the exact stored bytes, mode `0440`, group = the pod's `fsGroup`. `/var/run/nebari/secrets/.status` holds `ok <count>` or `error <code> <detail>`. `/var/run/nebari/user-secrets-bin/user-secrets-env` (mode `0550`) is the env wrapper, copied in by the init container onto its own volume, because the binary does not fit beside the values in the 1 MiB memory volume.
- **Why files.** A memory-backed `emptyDir` dies with the pod, so values never reach etcd beyond the owner record, there is nothing to clean up, and no value passes through KubeSpawner's `str.format` templating or Kubernetes' `$(VAR)` expansion.
- **`user-secrets-env -- <cmd> [args]`** reads the files, adds each as an environment variable with the exact bytes (a value containing a NUL byte cannot be an env var; it is skipped and named on stderr), never replaces a variable that is already set, prints one warning line to stderr when `.status` reports an error, and `exec`s the command. The injector prepends it to the workload container's `args` when the pod asks for it (see "The injector"), so the image's entrypoint (for example `tini`) still runs first and `exec`s the wrapper.
- **`user-secrets-init`** is a static Go binary (multi-arch image, runs as UID 65532 with the pod's `fsGroup`). It reads the projected token, calls resolve over TLS with a 30-second budget and exponential backoff on `503` and connection errors, writes each file to a temporary name and renames it, writes `.status`, copies itself to the wrapper volume, and exits per the consumer's failure mode.
- **Transport.** The service serves the resolve API on an in-cluster `Service` (`https://user-secrets.<service-namespace>.svc:8443`) over TLS, the management API on `:8444` and the injector on `:9443`. One serving `Certificate`, `user-secrets-tls`, in the service namespace, comes from NIC's `ClusterIssuer` `nebari-ca-issuer` with the names `user-secrets.<service-namespace>.svc` and `user-secrets.<service-namespace>.svc.cluster.local`, which the root CA's name constraints permit on every certificate type (nebari-infrastructure-core#787). Clients verify it against `nebari-trust-bundle` (key `ca-certificates.crt`), which trust-manager projects into every namespace: the init container mounts it from the workload namespace, the landing nginx from the landing namespace, and the API server gets the CA through `inject-ca-from`. Every client checks the service's DNS name, so the public roots in the bundle cannot vouch for it (public CAs do not issue `.svc` names). A missing bundle gives `.status` `error ca_missing`. The service publishes nothing into other namespaces. The root CA keeps its key across renewals (`rotationPolicy: Never` in #787), so a client that loaded the bundle once, such as nginx, keeps verifying renewed serving certificates until the root copy it loaded expires. The service's NetworkPolicy admits port 8443 only from registered workload namespaces, port 8444 only from the landing frontend pods, and port 9443 from any source (see "The injector").

## Reference consumers (MVP)

**No shared consumer code.** Each reference consumer sets the ServiceAccount, the label and the annotations in a few lines of its own config, so no consumer image changes and nothing loads while the integration is disabled. The init image is a value of nebari-user-secrets's chart, released with the service, so mirrored or air-gapped registries override it in one place, and the init image and resolve API `v1` always ship together.

**Notebook and jhub-apps (data-science-pack, `userSecrets.enabled`, default false).**

- The ServiceAccount, label and annotations are set in a KubeSpawner `modify_pod_hook`, which runs on the final pod manifest after profile overrides (`load_user_options`, `kubespawner/spawner.py:3066`) and after jhub-apps sets its command in `start()` (`jhub_apps/spawner/spawner_creation.py:285` at 2026.8.1), at `spawner.py:3151-3154`. A deployer-set `modify_pod_hook` is chained, not replaced. (Decided; this replaces applying them in `_pre_spawn_hook`, where both profile overrides and jhub-apps' command overwrite them.)
- The hook reads `sub` from `auth_state["oauth_user"]["sub"]` (read the same way at `00-gateway-auth.py:428`); if absent, it changes nothing, so the pod is not labelled and the injector never sees it.
- App: `jhub-apps` when the spawner is a jhub-apps spawner (the class jhub-apps derives from `_NebiKubeSpawner`, `02-jhub-apps.py:74-84`), else `notebook`. (Decided; planning confirms the attribute jhub-apps sets.)
- With `userSecrets.exportEnv` (default true when enabled), the hook sets `nebari.dev/user-secrets-export-env: "true"`, and the injector prepends the wrapper to the notebook container's `args`, ahead of dsp's umask wrapper (`01-spawner.py:114-119`). With `userSecrets.failureMode: strict` it also sets the `nebari.dev/user-secrets-failure: strict` label.
- dsp's single-user pods already set `fsGroup: 100` (`01-spawner.py:182-183`); the injector keeps it. The notebook container is the pod's first container, so no `user-secrets-containers` annotation is needed.
- The hub is the creator (`system:serviceaccount:<ns>:hub`), allowed its user namespace and apps `notebook` and `jhub-apps`.

**Hub identity endpoint (data-science-pack).** `GET /hub/api/user-secrets/identity`, authenticated by a JupyterHub token carrying the custom scope `custom:user-secrets-identity` (`custom_scopes`, `jupyterhub/app.py:356`), returns `{"sub": "<sub>"}` for that token's owner, read from `auth_state`. It is registered with `extra_handlers` (`app.py:1708`), which JupyterHub 5.5.0 marks deprecated in favour of services (`app.py:1708-1723`). **Decided: keep `extra_handlers` for the MVP**, because a hub-managed service would need `admin:auth_state` to read `sub`, which exposes every user's refresh token to that service. Removal tracking: a follow-up issue to propose a narrower upstream scope or to store `sub` outside `auth_state`. When enabled, the scope is added in place to the `user` role (as dsp already extends it, `02-jhub-apps.py:91-104`), because a server token's scopes are limited to what its owner holds (JupyterHub 5.5.0 `user.py:802-851`). dsp defines no `server` role today, so it defines one explicitly, restating JupyterHub's defaults (`users:activity!user`, `access:servers!server`, `jupyterhub/roles.py:54-58`) plus the new scope. When disabled, neither role is touched. A test spawns a server and checks its token's scopes. Every request passes through JupyterHub's `refresh_auth`, and dsp's `refresh_user` returns False on `invalid_grant` (`00-gateway-auth.py:351-352`, `auth_refresh_age = 240` at `:592`), so the endpoint works only while the user's Keycloak session lives; this matches the gateway's own `/user` check.

**Dask (dask-gateway-pack, `userSecrets.enabled`, default false).** A config hook in the existing `gateway.extraConfig`:

- subclasses `JupyterHubAuthenticator`: after the parent's `authenticate()` succeeds, it calls the hub identity endpoint with the user's JupyterHub token and attaches `secrets_sub` to the `User` (it has to happen in `authenticate()`: the options handler is synchronous and receives only `User(name, groups, admin)`, `options.py:106-108`, `models.py:54-57`, and later requests authenticate from a cookie cache, `auth.py:84-107`);
- wraps the options handler (dask-gateway-pack ships none by default; deployers write one in `extraConfig`, `chart/values.yaml:189-205`), merging into the returned config: `*_extra_pod_annotations` with the `sub`, the app and, with `exportEnv`, the export annotation (`backends/kubernetes/backend.py:237-265`), `*_extra_pod_labels` with the label and, in `strict` mode, the failure label (`backend.py:267-295`), and `*_extra_pod_config` with the ServiceAccount (unless the deployer set one) and `automountServiceAccountToken: false` (deep-merged, `controller.py:1192-1193`). The injector then wraps the scheduler and worker command in the container's `args` (`controller.py:1144`). These are not declared option fields, so a user cannot set them (`options.py:87-91`). Both forms of `c.Backend.cluster_options` are wrapped: an `Options` object and a callable returning per-user options (`dgsrc/base.py:89-92`). The block is named so it sorts after every deployer block, and at config load it raises if the final `cluster_options` is not wrapped, so a misordered or unrecognised handler fails loudly instead of silently dropping the settings.

Every scheduler and worker pod resolves at its own start, so workers added hours later get the secrets without any Keycloak session. The creator is the controller's ServiceAccount, allowed app `dask` in registered Dask namespaces only, and the gateway API is a trusted input (see "Pod identity and the guard").

## Storage

- One Kubernetes Secret per owner, in the service's own namespace, named `us-` plus the first 32 hex characters of the SHA-256 of the `sub` (written `us-<sub>` elsewhere in this document). The `sub` cannot be used directly: Keycloak gives users federated without import an id like `f:<component>:<username>`, which is not a valid Secret name. The record's `ownerSub` is checked on every read. Only the service's ServiceAccount can read Secrets in that namespace.
- Each Secret holds one JSON document (`record.json`) with the owner's secrets and enablements (see Data models). Values are stored encrypted (below), as base64-encoded bytes, so any byte sequence round-trips. Writes use `resourceVersion` optimistic concurrency.
- A second per-owner Secret `us-<sub>-status` holds delivery status per app (last success time and count, last failure time and reason), written at most once a minute per app per replica, so resolve traffic never contends with management writes. Writes are best-effort: a failed write is logged and never fails the resolve. Status is recorded only for a pod that passed verification (UID matched, annotations read from the API server) while the guard is verified or overridden, so an untrusted annotation can never write into another user's status. Earlier failures appear only in the pod's `.status` and in `resolve_denied` audit lines.
- `record.json` carries `schemaVersion`.
- Limits enforced on write: at most 50 secrets per user, each value at most 32 KiB before encryption, and the whole encoded `record.json` at most 512 KiB, which keeps it under the 1 MiB Secret limit with margin (encryption adds 28 bytes per value). Names match `^[A-Za-z_][A-Za-z0-9_]{0,63}$`. The management API reports usage against these limits.

**Encryption (envelope, a key per user).**

- **Data key.** Each owner record has its own random 256-bit data key, created with the record. The record stores it only wrapped by the master key, with the master key's id (`WrappedKey`). The wrap uses the owner's `sub` as associated data, so a wrapped key copied into another record fails to unwrap.
- **Values.** Each value is sealed with AES-256-GCM under the data key, with a random 96-bit nonce and associated data `"nebari-user-secrets/v1"`, `sub` and the secret name, each length-prefixed so no two inputs encode the same, so a ciphertext moved to another secret or another user fails to open. Nonces are random; a data key seals at most a few thousand values over its life (50 secrets, rotations), far below the 2^32 bound for random GCM nonces.
- **Master key (KEK) behind `KeyEncryptionKey`.** The MVP implementation, `kubernetes`, keeps 256-bit master keys in the Secret `user-secrets-kek` in the service namespace: one entry per master-key id holding that key, plus `primary` naming the id used for new wraps; wrapping is AES-256-GCM with the owner's `sub` as associated data. Cloud KMS implementations are follow-ups (see "Future-proofing"); with AWS KMS, for example, the `sub` would be the encryption context, and every unwrap would appear in CloudTrail.
- **Bootstrap.** On start, a replica reads `user-secrets-kek`. If it is missing and a successful list shows no `us-*` record, the replica creates it (creation is atomic, so a second replica gets `AlreadyExists` and reads the first one's key). If it is missing while any record exists, or the list fails, the service never generates a new one: resolve and the management API return `503 kek_unavailable` and a `kek_unavailable` audit line is logged. The chart does not template this Secret, so Argo CD neither tracks, prunes nor reverts it.
- **Rotation.** `user-secrets admin rotate-kek` (the service binary, run as a one-off Job by an admin) adds a new master key, makes it `primary`, and rewraps every record's data key, one record at a time with `resourceVersion` concurrency; it reports how many records still use each older id, and `user-secrets admin retire-kek <id>` removes an id only when none do. Reads keep working throughout, because each record names its master key. `user-secrets admin rotate-dek [--owner <sub>]` replaces data keys and re-encrypts values, for a suspected data-key exposure.
- **Backup.** Losing `user-secrets-kek` loses every secret. Until Nebari backs up Kubernetes objects, the operations guide tells admins to back it up separately from any copy of the records, and a backup of the records alone holds no readable value.
- **Not protected.** A principal that can read Secrets in the service namespace (the service and cluster admins) can read both the master key and the records; that is the admin exception in the threat model.

## Management API

The service serves no UI. Users manage secrets on the Nebari landing page, which calls this API; the landing page side is tracked in [nebari-dev/nebari-landing#236](https://github.com/nebari-dev/nebari-landing/issues/236).

- **Cluster-internal only.** The API listens on its own port, `:8444`, of the in-cluster `Service`, over the same TLS as resolve. There is no `NebariApp`, `HTTPRoute` or landing page tile for the service. The service's NetworkPolicy admits `:8444` only from the landing frontend pods (namespace and pod selector from values), and `:8443` (resolve) only from registered workload namespaces, so neither side can reach the other's port.
- **Reached through the landing page's nginx.** The landing frontend's nginx already proxies `/api/` to `nebari-webapi`'s ClusterIP and passes `Authorization` through unchanged (`nebari-landing` `charts/nebari-landing/templates/frontend/configmap.yaml` at `6f9b9f9`). It adds `location /api/user-secrets/`, forwarding to `https://user-secrets.<service-namespace>.svc:8444/api/v1/` and verifying the service against `nebari-trust-bundle` in the landing namespace and the service's DNS name (`proxy_ssl_verify on`, `proxy_ssl_name`). The browser calls the API directly with the user's keycloak-js access token; `nebari-webapi` is not involved.
- **Authentication** per "Identity rules": a Keycloak access token whose `azp` is the landing page's SPA client. Every route acts only on the token's `sub`; no route takes a user as input.
- **Values are write-only.** No response contains a value or any part of one.
- **What the landing page shows** is its own concern, tracked in nebari-landing#236; the API returns what it needs: per secret its name, description, last update, bindings with full names (`NEBARI_SECRET_<SUFFIX>`) and file paths, and per app the last delivery; usage against the limits; the registered apps; and the guard state for the admin notice. The landing page also carries the user-facing text this design relies on: the Dask sharing warning, "Anything started before now still has the old value until it restarts" after a rotate or delete, and the `NEBARI_SECRET_` usage example.
- **What the landing proxy must tolerate** (requirements on nebari-landing, tracked in #236): the landing page must start and serve everything else when user-secrets is not installed or not yet ready; only `/api/user-secrets/` fails. In nginx terms that means resolving the service name at request time rather than at startup. The integration is off by default in the landing chart.
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
- `key_event` for master-key and data-key operations: `kek_created`, `kek_rotated` (new id, records rewrapped), `kek_retired`, `dek_rotated` (owner), `kek_unavailable`, and `decrypt_failed` (owner, secret, no detail that could help an attacker), with the actor for admin commands.
- Logging is configured at the service entrypoint (JSON to stdout), and a test asserts lines are emitted through the real logging configuration. Never logged: values, tokens.

## Operations

- **Replicas.** Two replicas behind the `Service`, with a PodDisruptionBudget of one. State lives only in Kubernetes Secrets, so replicas share nothing in memory; each runs its own guard watch and probe, and a replica that is not verified answers `503` while the other may answer. Rolling updates keep at least one replica serving.
- **Master key.** `user-secrets-kek` is the one object whose loss loses data; the operations guide covers backing it up apart from the records, rotation with `user-secrets admin rotate-kek`, and the `503 kek_unavailable` state.
- **Injector.** Two replicas serve the webhook as well; a rolling update keeps one answering, so `strict` pods are not refused during an upgrade.
- **Failure visibility.** The init container's `.status` (absent when injection failed), the wrapper's stderr warning, the `us-<sub>-status` record returned by the management API and shown on the landing page, `resolve_denied` audit lines for admins, and `strict` mode for consumers that prefer a blocked start.

## Future-proofing

1. **Ownership and access are separate fields.** Each secret has `owner_sub` and `grants` (empty in the MVP).
2. **The resolve API answers "what can this principal use in this app".** Shared secrets would appear without consumer changes.
3. **Names live on the binding and belong to the consuming principal.** A grant shares a value, never a name.
4. **Audit records distinguish owner and reader** from day one.
5. **The reader is a principal, not necessarily a person.** Records key on `sub`; `Grant.Kind` allows values beyond `user` and `group`.
6. **Background workloads use service (bot) accounts (design after the MVP).** A background workload's pod is created by a registered creator with the service account's `sub` in the annotation. Where it must also call Keycloak, Keycloak's federated client authentication accepts a Kubernetes ServiceAccount token instead of a client secret, supported since Keycloak 26.6 ([release notes](https://www.keycloak.org/2026/04/keycloak-2660-released), [blog](https://www.keycloak.org/2026/01/federated-client-authentication)); to be tested on NIC's pinned `26.8.1`.
7. **Live refresh needs no new identity.** The pod-bound token can be presented again while the pod lives. It must then allow running pods that predate a later `verifiedSince` move caused by a legitimate change, for example by recording each pod's first successful resolve.
8. **Narrowing what a shared server exposes.** Drop `custom:user-secrets-identity` from tokens of servers that currently have shares, so a sharee cannot use the owner's token to reach Dask bindings.
9. **Cut from the MVP on 2026-11-10: a signed-assertion fallback.** If deployments that decline the policy become common, add a creator-signed assertion mode: bind notebook assertions to the pod name, give Dask assertions a renewable bound (dask-gateway has only `idle_timeout`, `dgsrc/base.py:339`), and keep a replay store for `jti`. (A Go helper is no longer needed: a Go consumer such as Javo sets the same label and annotations.)
10. **Cloud KMS master keys.** AWS KMS, Google Cloud KMS and Azure Key Vault behind `KeyEncryptionKey`, with workload identity for the service's ServiceAccount and the `sub` as encryption context. Records name their master-key id, so moving to a cloud key is a `rotate-kek` to the new implementation.
11. **Backups.** When Nebari backs up Kubernetes objects, owner records can be included as they are (they hold no readable value); the master key needs its own path.
12. **Ask the user at first use.** An app requesting a secret the user has not bound to it could prompt the user to allow it, instead of only on/off bindings. Resolve already knows the pod, app and user, so this extends the management API, not pod identity.

## Implementation defaults

- **Go** for the service (including the injector and the admin commands) and the init binary: static binaries on `gcr.io/distroless/static:nonroot`; short Python hooks in the consumers.
- Observability follows NIC's conventions: OpenTelemetry span per exported function in `internal/`, `slog` JSON only in `cmd/` and the HTTP layer, audit through an `AuditSink`.
- The JWT/JWKS library is chosen at plan time after reading its source at the pinned version.
- Values write-only through the management API; envelope encryption with a data key per user and a master key in a Kubernetes Secret, behind an interface; limits as in "Storage".
- No UI in the service; management API on its own port, reachable only from the landing frontend pods.
- Per-secret files; projected token only in the init container; files `0440` with `fsGroup`.
- Default failure mode `soft`; `strict` available per consumer.
- Guard: watch plus dry-run probe, 2-minute grace for "unknown".
- One security mode plus the explicit override.
- Delivery pieces added by the service's mutating webhook, two entries by failure mode; consumers set only the ServiceAccount, label and annotations.
- `extra_handlers` kept for the identity endpoint, with a removal follow-up.
- In-cluster TLS from NIC's `nebari-ca-issuer`, trusted through `nebari-trust-bundle` (nebari-infrastructure-core#787); the service publishes nothing into other namespaces.
- Two admission policies (A always on, B allowlist selected by a pod label), tested on kind against 1.30, 1.32 and 1.34; the case matrix is a CI test.

## Open questions to verify during planning (verifications, not design decisions)

1. The attribute or class check that identifies a jhub-apps spawner in a `modify_pod_hook` at jhub-apps 2026.8.1.
2. That access tokens keycloak-js obtains for the landing page carry `azp = <landing SPA client id>`, `typ = "Bearer"` and the realm `iss` the service expects, and that ID tokens carry a different `typ` (decode real tokens on a dev cluster).
3. The decorator or manual check a JupyterHub 5.5.0 `extra_handlers` handler uses to enforce a custom scope.
4. That a dask-gateway options handler may return the annotation, label and pod settings listed above and that they reach the pods at 2026.3.0.
5. That nebari-infrastructure-core#787 (and #776 under it) merges before this ships, and how clusters created before it get the root CA's `svc` name constraints (#787 notes that cert-manager 1.17.2 does not reissue on a constraints-only change).
6. The `fsGroup` behaviour of `emptyDir` volumes (group ownership and setgid on files written by a UID-65532 init container), that the wrapper volume allows execution, and the built init binary's size.
7. The pod-manifest golden harnesses, which neither repo has today: instantiating dsp's configured KubeSpawner against a mocked hub and calling `get_pod_manifest`, and calling dask-gateway's controller `make_pod` with a rendered config.
8. The injector against a real NIC cluster: its patch passes Pod Security `restricted` in the consumer namespaces, `reinvocationPolicy: IfNeeded` behaves with the other mutating webhooks installed there, which source address API server calls to `:9443` come from on each provider, and how the dask-gateway controller handles a refused `strict` pod.
9. How NIC passes matching values to both charts (in user-secrets: the landing namespace, frontend pod selector and SPA client id, which nebari-landing lets deployers override with `frontend.keycloak.clientId`; in nebari-landing: the service address and the integration toggle), and the Argo CD sync order between them. A wrong client id gives `401` on every management call; a wrong namespace or selector makes the NetworkPolicy block the landing page.

Already established by the policy test matrix: TokenReview of a pod-bound token carries `pod-name` and `pod-uid` in `extra` at 1.30; every policy rule, the missing-ConfigMap behaviour and the probe behave as designed (see "Pod identity and the guard").

## Program Design

**Scale:** full

### Existing patterns

| Pattern | Tag | Source | Promote? |
|---|---|---|---|
| Packs expose themselves through a `NebariApp` CR (routing, TLS, Keycloak client provisioning, landing tile). Deliberately not followed: the service has no external surface | [documented: software-pack-template docs/nebariapp-crd-reference.md] | `tmpl/docs/nebariapp-crd-reference.md`, `dsp/templates/nebariapp.yaml` | n/a |
| Landing page backends are cluster-internal; the landing frontend's nginx proxies a path to them with the Bearer header unchanged, and they validate the keycloak-js token themselves | [documented: nebari-landing chart comments and ADR] | `nebari-landing` `charts/nebari-landing/templates/frontend/configmap.yaml`, `frontend/src/api/client.ts` at `6f9b9f9`; `nebari-operator` `docs/decisions/2026-03-05-webapi-extracted-to-nebari-landing.md` | n/a |
| Go services in nebari-dev use `cmd/<binary>` + `internal/<pkg>` layout and a distroless nonroot image | [inferred] | `nebari-operator/cmd/operator`, `nebari-operator/internal/`, `nebari-operator/Dockerfile:26` | yes |
| Hub-side per-user pod customisation reads `auth_state` and appends to init containers, volumes and mounts | [inferred] | `dsp/config/jupyterhub/01-spawner.py:266`, `:957`, `:1185`, `:1421-1460` | no |
| dsp extends built-in hub roles in place in `load_roles`, never by redefining them | [inferred] | `dsp/config/jupyterhub/02-jhub-apps.py:91-104` | no |
| dask-gateway-pack customisation goes through `gateway.extraConfig` blocks, including deployer-written options handlers | [documented: dask-gateway-pack chart/values.yaml:188-208] | `dask-gateway-pack/chart/values.yaml` | n/a |
| Render-time chart guardrails in a `validate.yaml` template that `fail`s on unsafe values | [inferred] | `external-auth-pack/chart/templates/validate.yaml` | yes |

### Component contracts

| Contract | Status | Owner | Consumers | Verified by | Promote? | Notes |
|---|---|---|---|---|---|---|
| `POST /api/v1/resolve` (resolve API) | new | nebari-user-secrets | `user-secrets-init` in every consumer's pods | n/a (new) | n/a | Pod-token auth only, TLS |
| Consumer contract (`docs/architecture/contracts.md`) | new | nebari-user-secrets | every consuming pack | n/a (new) | n/a | Ten rules |
| Injector `MutatingWebhookConfiguration` `user-secrets-injector` and its patch | new | nebari-user-secrets | every labelled pod; the cluster's Kubernetes team | n/a (new) | n/a | Adds delivery pieces only; never denies; reserved `user-secrets-` names; entries by failure mode |
| Pod label `nebari.dev/user-secrets` and annotations `nebari.dev/user-secrets-sub` and `-app` | new | nebari-user-secrets | creators (write), the service, the injector and the policies (read) | n/a (new) | n/a | Guarded by policies A and B |
| Optional pod metadata (label `nebari.dev/user-secrets-failure`; annotations `nebari.dev/user-secrets-export-env` and `-containers`) | new | nebari-user-secrets | creators (write), the injector (read) | n/a (new) | n/a | Read only at creation; the spec of a labelled pod is immutable afterwards |
| File layout under `/var/run/nebari/secrets` | new | nebari-user-secrets | consumer workloads and user code | n/a (new) | n/a | The delivery contract |
| `user-secrets-env -- <cmd>` wrapper behaviour | new | nebari-user-secrets | consumers that export env | n/a (new) | n/a | Never replaces a set variable |
| Cluster bundle (`cluster/` with `cluster/REVIEW.md`) | new | nebari-user-secrets | the cluster's Kubernetes team | n/a (new) | n/a | Two policies with bindings, auth-delegator binding, reader role |
| Creator registry and `user-secrets-creators` ConfigMap | new | nebari-user-secrets | the policy (params), the service (guard check) | n/a (new) | n/a | Creator → namespaces, apps |
| `ClusterIssuer` `nebari-ca-issuer` and ConfigMap `nebari-trust-bundle` (key `ca-certificates.crt`) | unchanged | nebari-infrastructure-core (#787, not yet merged) | the service's serving certificate; the init container, the landing nginx and the API server as clients | `docs/internal-certificates.md` and `journeys/test_internal_certificates.py` in #787 | n/a | Replaces the service's own CA and the `user-secrets-ca` ConfigMap |
| Management API on `:8444` (`/api/v1/secrets`; `/api/v1/apps`; `/api/v1/status`) | new | nebari-user-secrets | the landing page (nebari-landing#236) | n/a (new) | n/a | Landing SPA tokens only, cluster-internal, TLS |
| Landing nginx `location /api/user-secrets/` → management API | new | nebari-landing | browsers on the landing page | n/a (new; nebari-landing#236) | n/a | Passes `Authorization` unchanged; verifies TLS with `nebari-trust-bundle` |
| Owner record `record.json` in `us-<sub>`; status record in `us-<sub>-status` | new | nebari-user-secrets | nebari-user-secrets only | n/a (new) | n/a | Versioned with `schemaVersion`; values sealed, data key wrapped |
| Master-key Secret `user-secrets-kek` and the `user-secrets admin` commands | new | nebari-user-secrets | admins (backup, rotation) | n/a (new) | n/a | Created by the service, never by the chart |
| Audit log line format | new | nebari-user-secrets | admins, log pipelines | n/a (new) | n/a | `secret_read`, `resolve_denied`, `secret_write`, `guard_state`, `key_event` |
| `GET /hub/api/user-secrets/identity` | new | data-science-pack | dask-gateway-pack authenticator | n/a (new) | n/a | Scope `custom:user-secrets-identity` on the `user` and `server` roles |
| dask-gateway-pack DaskCluster policy | new | dask-gateway-pack | the cluster's Kubernetes team | n/a (new) | n/a | Only the gateway API writes annotated `spec.config` |
| `c.KubeSpawner.modify_pod_hook` | changed-compatible (implicit) | data-science-pack | dsp | `rg -n "modify_pod_hook" dsp/` returns no matches (re-run 2026-11-10) | no | New hook; chains any deployer-set hook |
| `_pre_spawn_hook` step order | unchanged (implicit) | data-science-pack | data-science-pack tests | `rg -n "orders_merge_ca_before_nebi_pull" dsp/tests` | no | Untouched; user-secrets no longer uses it |
| `c.KubeSpawner.cmd` shape | unchanged (implicit) | data-science-pack | single-user images | `rg -n "KubeSpawner\.cmd" dsp/config` (one assignment, `01-spawner.py:114`) | no | The wrapper goes into the pod's `args` in `modify_pod_hook`; `cmd` itself is untouched |
| `server` role scopes | changed-compatible (implicit) | data-science-pack | single-user servers | `rg -n "server_token_scopes|\"name\": \"server\"" dsp/config` | no | When enabled: `server` role defined with defaults restated plus the scope; scope added to `user` in place |
| dask-gateway authenticator / `User` / options handler / `KubeClusterConfig` pod fields | unchanged | dask (upstream) | dask-gateway-pack config hook | `rg -n "async def authenticate|def __init__\(self, name, groups|return self.handler\(" dgsrc/auth.py dgsrc/models.py dgsrc/options.py` | n/a | Subclassed and configured, not modified |

**Resolve API.** `POST /api/v1/resolve` over TLS with `Authorization: Bearer <projected ServiceAccount token>` and no body. Promises: `200 {"secrets": [{"env": "NEBARI_SECRET_<SUFFIX>", "value_b64": "<base64>"}, ...]}` containing exactly the secrets the pod's annotated `sub` may use with `enabled` for the pod's annotated app. Requires: TokenReview with audience `user-secrets` succeeds and names a pod; that pod exists with the same UID; it carries the label and both annotations; its `creationTimestamp` is later than `verifiedSince` (policy mode); the pod's `namespace/serviceaccount` is registered for the app; the guard is verified or overridden. Errors: `401` token fails TokenReview or is not pod-bound; `403` pod missing, UID mismatch, annotation missing, not registered, or `pod_predates_guard`; `503 guard_not_verified`; `503 kek_unavailable`; `503` Kubernetes API unavailable; `500 decrypt_failed` (a record that does not open under its own owner's key, logged as a `key_event`). Never returns another user's secrets.

**Management API.** Over TLS on `:8444`, every route with `Authorization: Bearer <Keycloak access token>` meeting "Identity rules", acting only on the token's `sub`. The landing page reaches it as `/api/user-secrets/...`, which its nginx maps to `/api/v1/...`.

- `GET /api/v1/secrets` → `200` `OwnerView`: the secrets with their bindings (suffix, full name and file path), delivery status per app, and usage. `usage.bytes` is the size of the encoded `record.json`, the quantity the 512 KiB limit applies to.
- `PUT /api/v1/secrets/{name}` with `{"description", "value_b64", "bindings": [{"app", "env"}]}` → `201` created or `200` updated, body a `SecretSummary`. `description` and `bindings` replace the stored ones wholesale. `value_b64` is required on create; on update, present rotates the value and absent keeps it.
- `DELETE /api/v1/secrets/{name}` → `204`.
- `GET /api/v1/apps` → `200 {"apps": [<app id>, ...]}`, the registered apps a binding may name.
- `GET /api/v1/status` → `200 {"guard": {"state", "mode", "reason"}}`, so the landing page can show the admin notice. It is returned to any authenticated user, since it only says whether delivery is working; the landing page decides who sees the notice.

Errors carry an `APIError` body, `{"error": "<code>", "detail": "..."}`: `401 invalid_token` (bad token, wrong `azp`, or not an access token); `400 invalid_name`, `invalid_suffix`, `unknown_app`, `grants_not_supported`, `limit_exceeded`; `404 not_found`; `409 env_conflict` (that suffix is already bound for that app); `503 kubernetes_unavailable`, `kek_unavailable`. No response contains a value.

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
	Sealed      []byte    `json:"sealed"` // nonce || AES-256-GCM ciphertext and tag; base64 in JSON; plaintext <= 32 KiB
	Bindings    []Binding `json:"bindings,omitempty"`
	Grants      []Grant   `json:"grants,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type WrappedKey struct {
	KEKID      string `json:"kekId"`      // master key that wrapped it
	Ciphertext []byte `json:"ciphertext"` // the wrapped 256-bit data key; base64 in JSON
}

type OwnerRecord struct {
	SchemaVersion int           `json:"schemaVersion"` // 1
	OwnerSub      string        `json:"ownerSub"`
	OwnerUsername string        `json:"ownerUsername"`
	DataKey       WrappedKey    `json:"dataKey"`
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
func NewKubernetesSecretStore(c kubernetes.Interface, namespace string, clock func() time.Time) *KubernetesSecretStore // clock drives the delivery-status rate limit

// internal/crypto
type KeyEncryptionKey interface {
	PrimaryID(ctx context.Context) (string, error)
	Wrap(ctx context.Context, dek []byte, ownerSub string) (model.WrappedKey, error)        // under the primary key
	Unwrap(ctx context.Context, w model.WrappedKey, ownerSub string) ([]byte, error)       // under w.KEKID
}
func NewKubernetesKEK(c kubernetes.Interface, namespace string, records RecordLister) *KubernetesKEK // bootstrap rules in "Storage"
type RecordLister interface{ AnyRecords(ctx context.Context) (bool, error) }
func NewSealer(k KeyEncryptionKey, rand io.Reader) *Sealer
func (s *Sealer) NewDataKey(ctx context.Context, ownerSub string) (model.WrappedKey, error)
func (s *Sealer) Seal(ctx context.Context, rec *model.OwnerRecord, name string, value []byte) ([]byte, error)
func (s *Sealer) Open(ctx context.Context, rec *model.OwnerRecord, e model.SecretEntry) ([]byte, error)
func (s *Sealer) Rewrap(ctx context.Context, rec *model.OwnerRecord) (changed bool, err error) // rotate-kek

// internal/inject
type InjectorConfig struct {
	InitImage    string
	ServiceURL   string // https://user-secrets.<ns>.svc:8443
	TokenSeconds int64  // 600
}
func NewInjector(cfg InjectorConfig) *Injector
func (i *Injector) Patch(pod *corev1.Pod) ([]jsonpatch.Operation, error) // pure; idempotent; never denies

// internal/audit
type AuditSink interface {
	SecretRead(ctx context.Context, ownerSub, readerSub, secret string, c model.PodClaim, g model.GuardMode)
	ResolveDenied(ctx context.Context, pod model.PodIdentity, reason string)
	SecretWrite(ctx context.Context, ownerSub, actorSub, secret, action string)
	GuardChanged(ctx context.Context, state, mode, reason string)
}
func NewSlogAuditSink(l *slog.Logger) *SlogAuditSink

// internal/service
func NewSecretService(s SecretStore, c *crypto.Sealer, a AuditSink, l Limits) *SecretService
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
# data-science-pack: config/jupyterhub/04-user-secrets.py (only when enabled)
class UserSecretsIdentityHandler(APIHandler):                            # GET /hub/api/user-secrets/identity
    async def get(self) -> None: ...
async def _user_secrets_modify_pod(spawner, pod) -> V1Pod: ...          # chained modify_pod_hook; SA, label, annotations

# dask-gateway-pack: chart extraConfig "usersecrets" (only when enabled)
class UserSecretsJupyterHubAuthenticator(JupyterHubAuthenticator):
    async def authenticate(self, request) -> User: ...                   # super(), then hub identity endpoint
def wrap_options_handler(inner, cfg) -> Callable: ...                    # merges SA, labels, annotations
```

### Program layout

```text
nebari-user-secrets/                       (+ new repo, laid out like nebari-operator)
+ chart/values.yaml                      registry (apps, workload SAs, creators with namespaces), guard.mode, limits, initImage, landing {namespace, podSelector, clientID}
+ chart/templates/deployment.yaml        2 replicas, PodDisruptionBudget
+ chart/templates/service.yaml           ClusterIP only: https :8443 (resolve), https :8444 (management), https :9443 (injector)
+ chart/templates/certificate.yaml       serving Certificate user-secrets-tls from ClusterIssuer nebari-ca-issuer (NIC #787)
+ chart/templates/creators-configmap.yaml
+ chart/templates/rbac.yaml              Role in own namespace: secrets (records and user-secrets-kek), guard-state ConfigMap, pods create (dry-run probe only, enforced by policy A); per registered namespace: pods get
+ chart/templates/networkpolicy.yaml     ingress :8443 from registered workload namespaces; :8444 from the landing frontend pods only; :9443 from any source (API server)
+ chart/templates/validate.yaml          shared-namespace guard, mode combinations, registry sanity
+ cluster/, cluster/REVIEW.md            policies A and B with bindings, injector MutatingWebhookConfiguration, auth-delegator binding, guard-reader role
+ test/policy/run.sh                     the policy case matrix, run in CI against kind
+ cmd/user-secrets/main.go               composition root, guard watch and probe, HTTP servers; `admin rotate-kek | retire-kek | rotate-dek`
+ cmd/user-secrets-init/main.go          fetch (init container) and env (wrapper)
+ internal/model, auth, podidentity, guard, store, crypto, inject, service, audit, httpapi, initfiles
+ Dockerfile                             distroless static nonroot, both binaries, multi-arch
+ docs/architecture/contracts.md, AGENTS.md

data-science-pack/
+ config/jupyterhub/04-user-secrets.py   identity endpoint, role scopes, modify_pod_hook setting SA, label, annotations (all only when enabled)
~ values.yaml                            userSecrets: {enabled: false, exportEnv: true, failureMode: soft, workloadServiceAccounts}
+ templates/user-secrets-*.yaml          workload SAs, egress NetworkPolicy (only when enabled)
+ tests/golden/                          rendered chart and pod manifests from the previous release
+ tests/unit/test_user_secrets_*.py      hook, identity endpoint, user options cannot reach settings, unchanged when disabled

dask-gateway-pack/
~ chart/values.yaml                      userSecrets block; gateway.extraConfig.usersecrets
+ chart/templates/user-secrets-*.yaml    workload SA, egress (only when enabled)
+ cluster/                               DaskCluster policy + REVIEW.md
+ tests/ (new pytest harness)            hook, options merge, golden helm template when disabled

nebari-landing/                            (designed in that repo; tracked in nebari-landing#236)
~ charts/nebari-landing/templates/frontend/configmap.yaml   location /api/user-secrets/ → management API, TLS verified with nebari-trust-bundle
~ charts/nebari-landing/templates/...    mount nebari-trust-bundle into the frontend (when enabled); values to turn the integration on and name the service
+ frontend/src/...                       secrets screens, calling /api/user-secrets/ with apiFetch-style Bearer auth
```

### Call stacks

```text
Management write:
  landing page → nginx /api/user-secrets/secrets/{name} → PUT /api/v1/secrets/{name} (:8444, TLS)
    → SessionVerifier.Verify (signature, iss, exp, typ = Bearer, azp = landing SPA client) → SecretService.Upsert
    → KubernetesSecretStore.Get → (new record: Sealer.NewDataKey) → Sealer.Seal (AAD: sub, name)
    → KubernetesSecretStore.Put (resourceVersion, 512 KiB cap) → AuditSink.SecretWrite

Master-key rotation (admin Job):
  user-secrets admin rotate-kek → KubernetesKEK adds a key, sets primary → AuditSink key_event kek_created
    → for each us-<sub>: Get → Sealer.Rewrap → Put (resourceVersion; retry on conflict) → report records per kek id
    → AuditSink key_event kek_rotated

Guard (each replica):
  informer events / 5-minute tick → Guard.Evaluate
    → compare both policies, both bindings and the ConfigMap with the expectation; Prober.Probe (three dry-run creates)
    → state change → AuditSink.GuardChanged

Notebook / jhub-apps spawn (enabled):
  JupyterHub spawn → (jhub-apps start() sets cmd) → KubeSpawner._start
    → load_user_options (profile overrides) → get_pod_manifest
    → modify_pod_hook: _user_secrets_modify_pod(spawner, pod)
      → sub from auth_state; app from spawner type → SA, label, annotations (export-env when enabled)
    → create pod as hub SA
    → API server: injector webhook (:9443) → Injector.Patch → init container, volumes, token, trust bundle, mounts, wrapper in args
    → policy A (shape) and policy B (creator, namespace, app) admit the patched pod
  pod: user-secrets-init fetch → POST /api/v1/resolve (TLS, verified with nebari-trust-bundle)
    → Guard.Allows → PodVerifier.Verify → TokenReview → GetPod → UID, annotations, registry
    → SecretService.Resolve → store Get → Sealer.Open per enabled secret → AuditSink.SecretRead; store.RecordDelivery
    → FileWriter.WriteAll, WriteStatus; copy self to the wrapper volume
  main container: [entrypoint] → user-secrets-env -- sh -c 'umask 0002; exec "$0" "$@"' jupyterhub-singleuser ...

Dask create and scale-up (enabled):
  client → gateway API with JUPYTERHUB_API_TOKEN
    → UserSecretsJupyterHubAuthenticator.authenticate → hub /user check → GET /hub/api/user-secrets/identity
    → cluster create → wrapped options handler → SA, labels, annotations merged into spec.config
    → (dask-gateway-pack policy admits the DaskCluster write: gateway API SA)
  controller creates scheduler and worker pods at any time → injector patches them
    → policies A and B admit (controller SA, Dask namespace, app dask)
    → each pod: user-secrets-init fetch → resolve → files
```

### Component trees and DI

`cmd/user-secrets/main.go` builds the cached `JWKSSource`, `SessionVerifier`, `client-go` backed `TokenReviewer`, `PodGetter`, informer-backed `AdmissionWatcher`, dry-run `Prober`, the `Registry` (from a values-rendered config file), `PodVerifier`, `Guard` (expected policy embedded via `embed.FS` from the same YAML `cluster/` ships), `KubernetesSecretStore`, `KubernetesKEK` (bootstrapped before any server starts), `Sealer`, `SlogAuditSink`, `Limits`, `SecretService` and `Injector`, starts the informers, then passes them to the `httpapi` constructors for the resolve server (`:8443`), the management server (`:8444`) and the webhook server (`:9443`). The `admin` subcommands build only the store, `KubernetesKEK`, `Sealer` and the audit sink. Everything below the root takes interfaces, so tests use fakes (`client-go/kubernetes/fake`, a fake clock for the grace period, a fixed `rand` reader). `Injector.Patch` is a pure function of the pod; consumer hooks are thin.

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
| Injector patch | `Injector.Patch` | real `corev1.Pod` values, table-driven | unit | pieces added once (idempotent on reinvocation); existing `fsGroup` kept; only named or first container mounted; token and trust bundle only in the init container; reserved names replaced; wrapper in `args` or `command`; SA, labels and annotations untouched; the patched pod passes Pod Security `restricted` |
| Injector in admission | API server | real kind (1.30) with the webhook config and the service | integration | labelled pods patched and unlabelled pods never sent; service down: `soft` pod admitted without pieces, `strict` pod refused; policies A and B still decide on the patched pod; dry-run probe unchanged |
| Encryption | `KeyEncryptionKey`, `rand` | real AES-GCM, fake KEK store, table-driven | unit | round trip of arbitrary bytes; a sealed value or wrapped key moved to another `sub` or name fails to open; tampered ciphertext fails; no plaintext in the encoded record |
| Master key bootstrap and rotation | `KubernetesKEK`, `RecordLister` | `client-go` fake; real kind | unit + integration | generated only when no records exist and the list succeeded; missing with records → `kek_unavailable`; two replicas racing create one key; `rotate-kek` rewraps every record and reads keep working mid-rotation; `retire-kek` refuses an id still in use |
| Hub hook and endpoint | spawner objects, JupyterHub test app | fakes | unit (dsp) | SA, label and annotations on the final manifest, export annotation when enabled, user options cannot reach them, scope enforced |
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
