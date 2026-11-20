// Package guard holds the admission guard's state. Slice 5 extends it.
package guard

import "github.com/nebari-dev/nebari-user-secrets/internal/model"

// GuardState is the guard's current verification state, as reported by the
// management API's status route.
type GuardState struct {
	State  string // "verified" | "unknown" | ...
	Mode   model.GuardMode
	Reason string
}
