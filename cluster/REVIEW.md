# Reviewing the cluster-scoped objects

This directory holds everything nebari-user-secrets needs at cluster scope. Under the proposed NIC ADR-0022, NIC applies it as part of the foundational install; teams that review cluster-scoped objects before they are installed review this directory. The design is in [`docs/design/user-secrets.md`](../docs/design/user-secrets.md).

## Objects

| Object | Evaluated on | Designed to deny only |
|---|---|---|
| `ValidatingAdmissionPolicy` and binding `user-secrets-pod-guard` (policy A, no parameters) | Every pod create and update, every pod subresource write and every ServiceAccount token request in the cluster, with `failurePolicy: Fail` | Pods carrying or gaining the `nebari.dev/user-secrets` label or `nebari.dev/user-secrets-*` annotations in a way the rules forbid; Bindings carrying that metadata; `user-secrets` audience tokens requested by anything but a kubelet; real (non-dry-run) pod creates by the service's ServiceAccount |
| `ValidatingAdmissionPolicy` and binding `user-secrets-creators` (policy B, parameters from the `user-secrets-creators` ConfigMap) | Creation of pods labelled `nebari.dev/user-secrets: "true"` | Labelled pods from a requester not registered for that namespace and app; every labelled pod while the ConfigMap is missing |

The service also needs a `ClusterRoleBinding` to `system:auth-delegator` (TokenReview) and a read-only `ClusterRole` and binding on the two policies and two bindings. They belong in this directory too and will be added with the service, since they name its ServiceAccount.

Unrelated pods, scheduler bindings, kubelet status updates and kubelet token minting all pass in the test matrix on every tested version. A CEL evaluation error in policy A would deny the requests it matches, which is why the service runs a canary probe and the matrix will run in CI once the repo has CI.

## Preconditions

- Kubernetes 1.30 or later.
- The NodeRestriction admission plugin, which keeps each kubelet to its own node's pods; the token rule relies on it.
- Only admins may impersonate, or create tokens for, the creator ServiceAccounts (the JupyterHub hub and the dask-gateway controller). Check with `kubectl auth can-i impersonate serviceaccounts --as=<user> -n <namespace>` and `kubectl auth can-i create serviceaccounts/token --as=<user> -n <namespace>` for each non-admin principal with access to those namespaces.

## Namespace

The service namespace appears in policy B's binding (`paramRef.namespace`) and in policy A's `serviceAccount` variable. Set it once in `install-config.yaml`; the kustomization substitutes both. `install-config.yaml` is local to kustomize and is never applied.

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
