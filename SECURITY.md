# Security Policy

## Supported Versions

Security fixes are made on `main` and shipped in the next release. Only the most recent release receives fixes; older releases are not patched. If you can, please confirm the issue against the latest release or `main` before reporting.

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues, pull requests, or discussions.

Report them privately through GitHub's private vulnerability reporting: [open a new advisory](https://github.com/nebari-dev/nebari-user-secrets/security/advisories/new). Only the maintainers can see the report.

Please include as much of the following as you can:

- The version of this service you are running, the Kubernetes version, and where it is deployed
- Steps to reproduce, or a proof of concept
- The impact as you understand it, including what an attacker would need to exploit it

## What to Expect

The maintainers will acknowledge the report, work with you to confirm and understand the issue, and keep you updated on progress toward a fix. Once a fix is released, we will publish a GitHub Security Advisory and credit you unless you ask us not to.

Please give us a reasonable chance to release a fix before disclosing the issue publicly.

## Scope

This project's job is to keep each user's secrets away from other users. Issues of particular interest:

- A pod receiving secrets that belong to a different user, or to a different app of the same user
- Getting past the admission policies in `cluster/`: creating or changing a pod that carries user-secrets identity without being a registered creator, or minting a `user-secrets` token outside a kubelet
- The service delivering secrets when the admission guard is not in force, or trusting a pod admitted while it was not
- Secret values reaching anywhere other than the owner's store record and the workload's memory volume, such as logs, etcd objects, or environment literals in pod specs

In scope:

- The user-secrets service, its API, and the `user-secrets-init` init container and env wrapper
- The admission policies, bindings and RBAC in `cluster/`
- The Helm chart and its default values
- The vendored Python helper that consumer packs use to build pod settings
- The release pipeline and published release artifacts

Out of scope here:

- How a consumer pack applies the helper, such as a JupyterHub hook or dask-gateway options handler; report those to that pack, for example [data-science-pack](https://github.com/nebari-dev/data-science-pack/security/advisories/new)
- Vulnerabilities in the Nebari platform itself; report those to [Nebari Infrastructure Core](https://github.com/nebari-dev/nebari-infrastructure-core/security/advisories/new) or [nebari-operator](https://github.com/nebari-dev/nebari-operator/security/advisories/new)
- Access that the design accepts: platform admins and JupyterHub admins can see secret values, and a user who shares a notebook server shares what that server can reach
- Issues that require an attacker to already hold cluster-admin or cloud-account administrator credentials

## Verifying Releases

No releases have been published yet. See [Verifying Nebari artifacts](https://github.com/nebari-dev/.github/blob/main/verifying-nebari-artifacts.md) for how Nebari release artifacts are signed and verified.
