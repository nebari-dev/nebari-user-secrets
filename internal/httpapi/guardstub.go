package httpapi

import (
	"github.com/nebari-dev/nebari-user-secrets/internal/guard"
	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

// StubGuardStatus reports an unstarted guard until Slice 5 provides the real
// one.
type StubGuardStatus struct{}

// State returns the fixed not-started state. Pure value helper, no span.
func (StubGuardStatus) State() guard.GuardState {
	return guard.GuardState{State: "unknown", Mode: model.GuardMode("enforced"), Reason: "not_started"}
}
