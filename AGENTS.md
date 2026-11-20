# AGENTS.md

Guidance for AI coding agents and contributors working in this repository.

## Contracts

Contracts are documented in `docs/architecture/contracts.md`. Changing a contract updates that file in the same PR.

## Conventions

- Layout is `cmd/<binary>` plus `internal/<pkg>`.
- OpenTelemetry: every exported function in `internal/` that takes a `context.Context` starts a span from `otel.Tracer("nebari-user-secrets")` named `<package>.<Function>`. Errors go to `span.RecordError`. Pure value helpers without a ctx are exempt.
- Logging: `slog` JSON only in `cmd/` and `internal/httpapi`. Audit events go through `AuditSink`.
- No value, token or data key appears in any log, audit line, error message, response or pod spec.
- Go tests are table-driven. Constructors take interfaces and return concrete types.
- Before a commit: `make lint test`.
