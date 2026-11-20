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

### Master-key Secret `user-secrets-kek`
**Owner:** nebari-user-secrets · **Consumers:** operators
**Promises:** One Kubernetes Secret named `user-secrets-kek` in the service namespace holds every master key as a 32-byte entry named by its id (`k` plus a UTC timestamp, for example `k20261120T101500Z`) and a `primary` entry naming the id used for new wraps. The service creates it only when it is absent and no owner record exists; if records exist and the Secret is missing or invalid, the service generates no key and fails closed (`503 kek_unavailable`, `key_event kek_unavailable`). Losing it loses every secret, so operators back it up separately from any copy of the records. A backup of the records alone holds no readable value.
**Errors:** A missing, unreadable or invalid Secret (bad entry length, `primary` naming an absent id) gives `ErrKEKUnavailable`. A record naming an id the Secret does not hold cannot be opened.
**Since:** 2026-11-20 (spec: docs/design/user-secrets-spec.md)

### Admin commands
**Owner:** nebari-user-secrets · **Consumers:** operators (run as one-off Jobs with the service image)
**Promises:** `user-secrets admin rotate-kek` adds a master key, makes it primary and rewraps every record's data key one record at a time with `resourceVersion` concurrency (up to 5 conflict retries per record); reads keep working throughout because each record names its master key. `user-secrets admin retire-kek <id>` removes an id only when it is not primary and no record uses it. `user-secrets admin rotate-dek [--owner <sub>]` replaces the data key and re-encrypts every value for one owner or all owners; a record is never written unless every value re-sealed. Flags: `--actor` (required, recorded in `key_event`), `--namespace` (default `$POD_NAMESPACE`). Uses `KUBECONFIG` when set, else the in-cluster config. Exit status is non-zero on any failure, and a failed rotation names how many owners were done and is safe to re-run.
**Errors:** Refuses to start when the master key cannot be loaded (admin commands never create a master key; only the service's startup does, and only when no record exists). `retire-kek` of the primary, an unknown id or an id still in use fails and changes nothing.
**Since:** 2026-11-20 (spec: docs/design/user-secrets-spec.md)

### Audit lines: `key_event`
**Owner:** nebari-user-secrets · **Consumers:** admins, log pipelines
**Promises:** JSON lines with `audit: true`, `event: key_event` and `key_event` one of `kek_created` (detail: new id), `kek_rotated` (detail: `<new id> rewrapped=<n>`, emitted once at the end of a fully successful pass), `kek_retired` (detail: id), `dek_rotated` (`owner_sub` set, one line per owner), `kek_unavailable` (detail: reason), `decrypt_failed`. `actor` names the admin for admin commands. No line carries a value, data key or master key.
**Errors:** A failed rotation emits no `kek_rotated` or `dek_rotated` line for the work that did not complete.
**Since:** 2026-11-20 (spec: docs/design/user-secrets-spec.md)

### Management API
**Owner:** nebari-user-secrets · **Consumers:** nebari-landing (nebari-landing#236)
**Promises:** Over TLS on `:8444`, every route requires `Authorization: Bearer <Keycloak access token>` (scheme matched without case, exactly one token; cookies are never read) and acts only on the token's `sub`. Routes: `GET /api/v1/secrets` (`200` `OwnerView`), `PUT /api/v1/secrets/{name}` with `{"description", "value_b64", "bindings": [{"app", "env"}]}` (`201` created or `200` updated, body `SecretSummary`; `value_b64` is standard base64, required on create, and on update present rotates while absent or `null` keeps; an empty string is rejected as `invalid_value` so a form sending `""` for an untouched field cannot wipe a secret; `description` and `bindings` replace the stored ones), `DELETE /api/v1/secrets/{name}` (`204`), `GET /api/v1/apps` (`200 {"apps": [...]}`), `GET /api/v1/status` (`200 {"guard": {"state", "mode", "reason"}}`, any authenticated user). Every response is `Content-Type: application/json` (none on `204`) with `Cache-Control: no-store`, except that Go's `ServeMux` answers paths containing `.`, `..` or `//` with a `307` redirect to the cleaned path (the redirect has no JSON body, and the cleaned path still requires auth). `405` carries an `Allow` header. Request bodies are at most 64 KiB. Write-only: no response, header or log line contains a secret value.
**Errors:** Body is `{"error": "<code>"}` with no `detail`. `401 invalid_token`; `400 invalid_name`, `invalid_suffix`, `unknown_app`, `grants_not_supported`, `limit_exceeded`, `value_required`, `invalid_value` (`value_b64` is not standard base64), `invalid_request` (not JSON, unknown field, any trailing data); `404 not_found` (also any unknown path); `405 method_not_allowed`; `409 env_conflict`; `413 request_too_large`; `500 internal` (a handler panic, logged and recorded on the span); `503 kek_unavailable`, `kubernetes_unavailable`.
**Since:** 2026-11-20 (spec: docs/design/user-secrets-spec.md)
