package catalog

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"
)

// Catalog is test/journeys/catalog.yaml: the design doc's features, the
// spec's journeys with their CI checks, and the platform checks.
type Catalog struct {
	Features       []Feature `json:"features"`
	Journeys       []Journey `json:"journeys"`
	PlatformChecks []Check   `json:"platform_checks"`
}

// Feature is a promise of the design doc. IDs are stable and never reused.
type Feature struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Source string `json:"source"`
	Status string `json:"status"` // active | retired
}

// Journey is one row of the spec's Journeys table, J<n>.
type Journey struct {
	ID      string  `json:"id"`
	Feature string  `json:"feature"`
	Checks  []Check `json:"checks"`
}

// Check is one CI check of a journey (J<n>.<k>) or a platform check.
type Check struct {
	ID     string `json:"id"`
	Status string `json:"status"` // covered | planned | not-covered
	// Reason is required unless covered.
	Reason string `json:"reason,omitempty"`
	// Until is the slice that adds the test (planned, required) or what would
	// make the check possible (not-covered, optional).
	Until string `json:"until,omitempty"`
	// Tier is 1, 2 or 3; 0 (none) only for a not-covered check whose test
	// would live outside this repo.
	Tier int `json:"tier,omitempty"`
	// Tests are required when covered: Go test function names, or
	// run.sh:<section label> for the tier 2 policy matrix.
	Tests []string `json:"tests,omitempty"`
}

// Check and feature statuses.
const (
	StatusCovered    = "covered"
	StatusPlanned    = "planned"
	StatusNotCovered = "not-covered"

	FeatureActive  = "active"
	FeatureRetired = "retired"
)

// TestIndex reports whether a test of that name runs in that tier.
type TestIndex interface {
	Has(tier int, name string) bool
}

// Load parses the catalog YAML; unknown fields are an error.
func Load(r io.Reader) (*Catalog, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	var c Catalog
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}
	return &c, nil
}

// Validate returns every way the catalog is malformed, claims coverage it
// does not have, or disagrees with the spec's journey ids. Each error names
// the feature, journey or check it is about.
func (c *Catalog) Validate(index TestIndex, specJourneys []string) []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	features := map[string]bool{}
	for _, f := range c.Features {
		if features[f.ID] {
			add("feature %s: duplicate id", f.ID)
		}
		features[f.ID] = true
		if f.Status != FeatureActive && f.Status != FeatureRetired {
			add("feature %s: status %q, want %s or %s", f.ID, f.Status, FeatureActive, FeatureRetired)
		}
	}

	journeys := map[string]bool{}
	used := map[string]bool{}
	checks := map[string]bool{}
	checkOne := func(ch Check) {
		if checks[ch.ID] {
			add("check %s: duplicate id", ch.ID)
		}
		checks[ch.ID] = true
		errs = append(errs, validateCheck(ch, index)...)
	}
	for _, j := range c.Journeys {
		if journeys[j.ID] {
			add("journey %s: duplicate id", j.ID)
		}
		journeys[j.ID] = true
		if !features[j.Feature] {
			add("journey %s: unknown feature %q", j.ID, j.Feature)
		}
		used[j.Feature] = true
		if !slices.Contains(specJourneys, j.ID) {
			add("journey %s: not in the spec's Journeys table", j.ID)
		}
		if len(j.Checks) == 0 {
			add("journey %s: no checks", j.ID)
		}
		for _, ch := range j.Checks {
			if !strings.HasPrefix(ch.ID, j.ID+".") {
				add("check %s: id is not %s.<k> under journey %s", ch.ID, j.ID, j.ID)
			}
			checkOne(ch)
		}
	}
	for _, ch := range c.PlatformChecks {
		checkOne(ch)
	}
	for _, id := range specJourneys {
		if !journeys[id] {
			add("journey %s: in the spec's Journeys table but not in the catalog", id)
		}
	}
	for _, f := range c.Features {
		if f.Status == FeatureActive && !used[f.ID] {
			add("feature %s: active but no journey belongs to it", f.ID)
		}
	}
	return errs
}

func validateCheck(ch Check, index TestIndex) []error {
	var errs []error
	add := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf("check %s: "+format, append([]any{ch.ID}, a...)...))
	}
	tierOK := ch.Tier >= 1 && ch.Tier <= 3 || ch.Tier == 0 && ch.Status == StatusNotCovered
	if !tierOK {
		add("tier %d, want 1, 2 or 3 (none only when not-covered)", ch.Tier)
	}
	switch ch.Status {
	case StatusCovered:
		if len(ch.Tests) == 0 {
			add("covered but names no tests")
		}
		if tierOK {
			for _, name := range ch.Tests {
				if !index.Has(ch.Tier, name) {
					add("covered but test %s does not exist in tier %d", name, ch.Tier)
				}
			}
		}
	case StatusPlanned:
		if ch.Reason == "" {
			add("planned with no reason")
		}
		if ch.Until == "" {
			add("planned with no until (the slice that adds the test)")
		}
	case StatusNotCovered:
		if ch.Reason == "" {
			add("not-covered with no reason")
		}
	default:
		add("status %q, want %s, %s or %s", ch.Status, StatusCovered, StatusPlanned, StatusNotCovered)
	}
	return errs
}
