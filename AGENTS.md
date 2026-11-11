# AGENTS.md

This file provides guidance to AI coding agents working in this repository.

## Repository state

Per-user secrets for Nebari workloads: users store API keys once, tied to their Keycloak identity, and the secrets they enable for an app arrive as files in that app's pods.

As of the initial commit, `main` holds only the README, license and `.gitignore`. Everything else is design-stage and lives on the `docs/user-secrets-design` branch (PR #1):

- `docs/design/user-secrets.md`: the design doc. Read this first.
- `docs/design/user-secrets-spec.md`: the detailed spec (types, method signatures, program layout, call stacks, test seams, Journeys that define done). The `### Program layout` section is the source of truth for where future code goes.
- `cluster/`: the two ValidatingAdmissionPolicies, their bindings, a kustomization, and `REVIEW.md` for cluster-scoped review.
- `test/policy/`: the admission test matrix and transcripts for Kubernetes 1.30, 1.32 and 1.34.

There is no service code yet. Do not invent build commands for it; check the spec's program layout before creating files.

## Commands

Admission policy tests (need `kind`, `kubectl` and a container runtime). Both scripts use their own `test/policy/kubeconfig` (gitignored) and never touch `~/.kube/config`:

```bash
bash test/policy/run-all.sh                  # kind cluster per K8s version, writes test/policy/results/<version>.txt
SVC_NS=secrets-svc bash test/policy/run.sh   # run the matrix against the cluster already in test/policy/kubeconfig
kubectl kustomize cluster/                   # render the cluster bundle
```

`run.sh` prints one `PASS`/`FAIL` line per case. To run a single case, there is no filter flag; comment out other `expect` calls or run that `kubectl ... --dry-run=server` command by hand.

## Architecture (planned)

Planned implementation per the spec: Go service (`cmd/user-secrets`, `cmd/user-secrets-init`, `internal/{model,auth,podidentity,guard,store,service,audit,httpapi,ui,initfiles}`), a Helm chart in `chart/`, the cluster bundle in `cluster/`, and a single-file, standard-library-only Python helper `python/nebari_user_secrets.py` that consumer packs vendor. Repo layout follows `nebari-operator`.

The service returns a secret only when three checks hold:

1. **Which pod**: TokenReview of a projected ServiceAccount token with audience `user-secrets`, then the pod's UID must match the live pod.
2. **Which app**: annotation `nebari.dev/user-secrets-app` names a registered app, and the pod runs as that app's registered ServiceAccount in a registered namespace.
3. **Which user**: annotation `nebari.dev/user-secrets-sub` on a pod labelled `nebari.dev/user-secrets: "true"`.

The trust for check 3 comes from two admission policies, split on purpose:

- **Policy A `user-secrets-pod-guard`** (no params, always on): label/annotation consistency and immutability (including `pods/status`), labelled pod spec immutable, no ephemeral containers, only kubelets mint `user-secrets` tokens, service account may only create dry-run probe pods.
- **Policy B `user-secrets-creators`** (params from the `user-secrets-creators` ConfigMap, labelled pods only): requester must be a registered creator for that namespace and app.

The split exists because a missing param ConfigMap must deny only labelled pod creates, not every pod in the cluster (`Deny`) and not disable the guard (`Allow`). Keep it that way when editing `cluster/policies.yaml`.

**Fail closed.** The service watches both policies, bindings and the ConfigMap, runs dry-run probes every 5 minutes, and returns `503 guard_not_verified` unless verified. A `verifiedSince` timestamp only moves forward, and pods created before it are never trusted. `guard.mode: unverified` is the only override.

**Delivery** is files, not env vars: `/var/run/nebari/secrets/NEBARI_SECRET_<SUFFIX>`, mode `0440`, in a 1 MiB memory `emptyDir`, written by the `user-secrets-init` init container. The fixed `NEBARI_SECRET_` prefix is a security property (blocks names like `LD_PRELOAD`); do not make it configurable. Env vars are optional via the `user-secrets-env` wrapper.

**Consumers** (`data-science-pack`, `dask-gateway-pack`) integrate off by default (`userSecrets.enabled: false`) and register via values only; the service and cluster bundle must not change to add a consumer. The 11-point consumer contract is in the design doc.

## Repo conventions

- `cluster/kustomization.yaml` injects the service namespace from `install-config.yaml` into policy A's `serviceAccount` variable and policy B's `paramRef.namespace`. Change the namespace there, not in `policies.yaml`.
- The transcripts in `test/policy/results/*.txt` are checked in as evidence; regenerate them with `run-all.sh` when the policies change.
