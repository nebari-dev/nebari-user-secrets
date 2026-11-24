# Reviewing the cluster-scoped objects

This directory holds everything nebari-user-secrets needs at cluster scope. Under the proposed NIC ADR-0022, NIC applies it as part of the foundational install; teams that review cluster-scoped objects before they are installed review this directory. The design is in [`docs/design/user-secrets.md`](../docs/design/user-secrets.md).

## Objects

Everything below ships in this directory: both policies, both bindings (at `validationActions: [Deny]`), the `system:auth-delegator` binding and the guard-reader role and binding. The end-to-end harness applies it after the chart (`test/e2e/setup.sh`).

| Object | Evaluated on | Designed to deny only |
|---|---|---|
| `ValidatingAdmissionPolicy` and binding `user-secrets-pod-guard` (policy A, no parameters) | Every pod create and update, every pod subresource write and every ServiceAccount token request in the cluster, with `failurePolicy: Fail` | Pods carrying or gaining the `nebari.dev/user-secrets` label or `nebari.dev/user-secrets-*` annotations in a way the rules forbid; Bindings carrying that metadata; `user-secrets` audience tokens requested by anything but a kubelet; real (non-dry-run) pod creates by the service's ServiceAccount |
| `ValidatingAdmissionPolicy` and binding `user-secrets-creators` (policy B, parameters from the `user-secrets-creators` ConfigMap) | Creation of pods labelled `nebari.dev/user-secrets: "true"` | Labelled pods from a requester not registered for that namespace and app; every labelled pod while the ConfigMap is missing |

The service also needs cluster-scoped RBAC, in [`rbac.yaml`](rbac.yaml). Both bindings name the service's ServiceAccount (`user-secrets`) in the namespace set in `install-config.yaml`.

| Object | Does | Can affect |
|---|---|---|
| `ClusterRoleBinding` `user-secrets-auth-delegator` to `system:auth-delegator` | lets the service create TokenReviews | the service's ServiceAccount only |
| `ClusterRole` and `ClusterRoleBinding` `user-secrets-guard-reader` | `get`, `list`, `watch` on the two policies and two bindings, by `resourceNames` | read-only, four named objects |

The same goes for the injector, a `MutatingWebhookConfiguration` named `user-secrets-injector` that names the service's `Service`:

| Object | Evaluated on | Effect |
|---|---|---|
| `MutatingWebhookConfiguration` `user-secrets-injector`, entries `strict` and `soft` | Only pod creates labelled `nebari.dev/user-secrets: "true"` (`objectSelector`); no other request is sent to it | Adds the init container, its volumes, the projected token and the trust-bundle mount; never denies, never sets values, `sideEffects: None`. While the service is unreachable, labelled pods also labelled `nebari.dev/user-secrets-failure: strict` are refused (`failurePolicy: Fail`) and other labelled pods start without secrets (`Ignore`). Its `caBundle` is filled by cert-manager (`cert-manager.io/inject-ca-from`) |

The policies run after every mutating webhook, so they decide on the pod as the injector left it.

Unrelated pods, scheduler bindings, kubelet status updates and kubelet token minting all pass in the test matrix on every tested version. A CEL evaluation error in policy A would deny the requests it matches, which is why the service runs a canary probe and the matrix will run in CI once the repo has CI.

## Preconditions

- Kubernetes 1.30 or later.
- The NodeRestriction admission plugin, which keeps each kubelet to its own node's pods; the token rule relies on it.
- NIC's cluster CA and trust bundle: the `ClusterIssuer` `nebari-ca-issuer` and the `nebari-trust-bundle` ConfigMap in every namespace ([nebari-dev/nebari-infrastructure-core#787](https://github.com/nebari-dev/nebari-infrastructure-core/pull/787)). The service's certificate comes from that issuer, so principals that can create cert-manager `Certificate` or `CertificateRequest` objects, and can also redirect traffic for the service's in-cluster name, could intercept resolve calls. Grant `Certificate` creation only to principals you would trust to serve any in-cluster Service name, as #787's internal-certificates guide advises.
- Only admins may impersonate, or create tokens for, the creator ServiceAccounts (the JupyterHub hub and the dask-gateway controller). Check with `kubectl auth can-i impersonate serviceaccounts --as=<user> -n <namespace>` and `kubectl auth can-i create serviceaccounts/token --as=<user> -n <namespace>` for each non-admin principal with access to those namespaces.

## Namespace

The service namespace appears in policy B's binding (`paramRef.namespace`), in policy A's `serviceAccount` variable and in the subjects of the two RBAC bindings. Set it once in `install-config.yaml`; the kustomization substitutes all of them. `install-config.yaml` is local to kustomize and is never applied.

```bash
kubectl kustomize cluster/            # inspect the rendered objects
kubectl apply --dry-run=server -k cluster/
```

## Rollout and removal

1. Install the chart first. It creates the `user-secrets-creators` ConfigMap. Installing in the other order only denies labelled pods until the chart is in.
2. Apply this directory with both bindings at `validationActions: [Warn, Audit]` to observe.
3. Switch both bindings to `[Deny]`. The service starts delivering for pods created after the switch; pods admitted earlier are never trusted.
4. To remove, delete the bindings before uninstalling the chart. Packs that opted in stop receiving secrets; nothing else changes.

## Evidence

[`test/policy/run.sh`](../test/policy/run.sh) runs the case matrix against a throwaway kind cluster, and [`run-all.sh`](../test/policy/run-all.sh) repeats it for Kubernetes 1.30.13, 1.32.11 and 1.34.3. The transcripts are in [`test/policy/results/`](../test/policy/results/).

## Guard limitations

Each service replica verifies these objects (watch, compare, dry-run probes) and stops delivering when they are not in force. Known limits of that check:

- A webhook installed by a cluster admin could return a denial that carries the same status cause as a policy denial, so a probe would read as denied by the policy. Cluster admins are trusted.
- A replica that stays bad after its last marking, whose marker another replica clears, and that restarts after the flaw heals and before its next evaluation, does not move `verifiedSince`. The window is bounded by the retry backoff plus one evaluation: while a replica is not verified it starts its next evaluation at most 30 seconds after the last one ended, and an evaluation takes up to 60 seconds of probes (three dry-run creates with a 20-second timeout each) plus the server-time read and the guard-state write.
- The guard reads the API-server time with a dry-run ConfigMap create in the service namespace. A `count/configmaps` ResourceQuota at its limit, or a ConfigMap-create webhook without `sideEffects: None`, makes that read fail; whenever `verifiedSince` has to move, the guard then fails closed (it stays `unknown` and does not deliver).
