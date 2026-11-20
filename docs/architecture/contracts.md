# Contracts

### Owner record
**Owner:** nebari-user-secrets · **Consumers:** none outside this repo
**Promises:** One Kubernetes Secret per owner, named `us-` plus the first 32 hex characters of the SHA-256 of the Keycloak `sub`, holds `record.json` (an `OwnerRecord`, `schemaVersion` 1). Values are sealed with the owner's data key, which is stored wrapped by a master key. The record's `ownerSub` is checked on every read. The encoded record is at most 524288 bytes and holds at most 50 secrets. Writes use `resourceVersion` optimistic concurrency.
**Errors:** A record whose `ownerSub` does not match the requested sub is rejected. An unknown `schemaVersion` is rejected. Oversize records are rejected on write.
**Since:** 2026-11-20 (spec: docs/design/user-secrets-spec.md)

### Status record
**Owner:** nebari-user-secrets · **Consumers:** none outside this repo
**Promises:** One Kubernetes Secret per owner, named like the owner record plus `-status`, holds per-app delivery status (`DeliveryStatus`: last success time and count, last failure time and reason). Writes are best-effort, at most once a minute per app per replica, and only for pods that passed verification. It never holds a value.
**Errors:** A failed status write is logged and never fails a resolve.
**Since:** 2026-11-20 (spec: docs/design/user-secrets-spec.md)
