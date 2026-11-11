# nebari-user-secrets

Per-user secrets for Nebari workloads. Users store their own API keys and similar secrets once, tied to their Keycloak identity, and the secrets they enable for an app arrive as files in that app's pods: notebook servers, jhub-apps apps and Dask clusters first.

The proposal ([NIC ADR-0022](https://github.com/nebari-dev/nebari-infrastructure-core/pull/764), tracked in [nebari-dev/nebari-infrastructure-core#763](https://github.com/nebari-dev/nebari-infrastructure-core/issues/763)) is for NIC to deploy this component as foundational software, alongside `nebari-operator` and the landing page. Software packs consume it through a written contract; nothing changes for a pack until it opts in.

## Status

Design under review. There is no service code yet.

- [Design](docs/design/user-secrets.md): the architecture, the threat model and the alternatives considered. Start here.
- [Detailed spec](docs/design/user-secrets-spec.md): types, method signatures, program layout, test seams and the journeys that define done.
- [`cluster/`](cluster/): the two ValidatingAdmissionPolicies that guard pod identity, their bindings and the kustomization that sets the service namespace.
- [`test/policy/`](test/policy/): the admission test matrix and its transcripts on Kubernetes 1.30, 1.32 and 1.34.

## License

Apache-2.0. See [LICENSE](LICENSE).
