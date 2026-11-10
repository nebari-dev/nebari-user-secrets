# nebari-user-secrets

Per-user secrets for Nebari workloads. Users store their own API keys and similar secrets once, tied to their Keycloak identity, and the secrets they enable for an app arrive as files in that app's pods.

The design is under review in [#1](https://github.com/nebari-dev/nebari-user-secrets/pull/1), and the proposal for NIC to deploy it as foundational software is tracked in [nebari-dev/nebari-infrastructure-core#763](https://github.com/nebari-dev/nebari-infrastructure-core/issues/763).

## License

Apache-2.0. See [LICENSE](LICENSE).
