# Architecture patterns

### Go layout: cmd and internal
Binaries live in `cmd/<binary>` and contain wiring only. All other code lives in `internal/<pkg>`, one package per concern, with constructors that take interfaces and return concrete types.

**Confirmed:** 2026-11-20 (spec: docs/design/user-secrets-spec.md)
