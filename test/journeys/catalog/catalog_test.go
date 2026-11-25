package catalog_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebari-dev/nebari-user-secrets/test/journeys/catalog"
)

// fakeIndex holds the test names per tier.
type fakeIndex map[int]map[string]bool

func (f fakeIndex) Has(tier int, name string) bool { return f[tier][name] }

var index = fakeIndex{
	1: {"TestUnit": true},
	2: {"TestE2E": true, "run.sh:policy B": true},
	3: {"TestJourney": true},
}

var specIDs = []string{"J1", "J2", "J3"}

// validCatalog covers every status and tier, and passes Validate against
// index and specIDs.
func validCatalog() *catalog.Catalog {
	return &catalog.Catalog{
		Features: []catalog.Feature{
			{ID: "F1", Title: "one", Source: "docs/design/user-secrets.md#goals", Status: "active"},
			{ID: "F2", Title: "two", Source: "docs/design/user-secrets.md#goals", Status: "active"},
			{ID: "F3", Title: "gone", Source: "docs/design/user-secrets.md#goals", Status: "retired"},
		},
		Journeys: []catalog.Journey{
			{ID: "J1", Feature: "F1", Checks: []catalog.Check{
				{ID: "J1.1", Tier: 1, Status: "covered", Tests: []string{"TestUnit"}},
				{ID: "J1.2", Tier: 2, Status: "covered", Tests: []string{"TestE2E", "run.sh:policy B"}},
			}},
			{ID: "J2", Feature: "F2", Checks: []catalog.Check{
				{ID: "J2.1", Tier: 3, Status: "planned", Tests: []string{"TestLater"}, Reason: "needs a cluster", Until: "Slice 8"},
			}},
			{ID: "J3", Feature: "F2", Checks: []catalog.Check{
				{ID: "J3.1", Tier: 3, Status: "covered", Tests: []string{"TestJourney"}},
				{ID: "J3.2", Status: "not-covered", Reason: "lives in another repo"},
			}},
		},
		PlatformChecks: []catalog.Check{
			{ID: "P3.1", Tier: 3, Status: "covered", Tests: []string{"TestJourney"}},
		},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(c *catalog.Catalog)
		spec   []string
		// want is the id the single error must name; empty means no error.
		want string
	}{
		{name: "valid catalog", mutate: func(*catalog.Catalog) {}},
		{
			name:   "covered test missing from the index",
			mutate: func(c *catalog.Catalog) { c.Journeys[0].Checks[0].Tests = []string{"TestGone"} },
			want:   "J1.1",
		},
		{
			name:   "covered test exists only in another tier",
			mutate: func(c *catalog.Catalog) { c.Journeys[0].Checks[0].Tests = []string{"TestE2E"} },
			want:   "J1.1",
		},
		{
			name:   "covered with no tests",
			mutate: func(c *catalog.Catalog) { c.Journeys[0].Checks[1].Tests = nil },
			want:   "J1.2",
		},
		{
			name:   "planned with empty reason",
			mutate: func(c *catalog.Catalog) { c.Journeys[1].Checks[0].Reason = "" },
			want:   "J2.1",
		},
		{
			name:   "planned with empty until",
			mutate: func(c *catalog.Catalog) { c.Journeys[1].Checks[0].Until = "" },
			want:   "J2.1",
		},
		{
			name:   "not-covered with empty reason",
			mutate: func(c *catalog.Catalog) { c.Journeys[2].Checks[1].Reason = "" },
			want:   "J3.2",
		},
		{
			name:   "unknown status",
			mutate: func(c *catalog.Catalog) { c.Journeys[0].Checks[0].Status = "done" },
			want:   "J1.1",
		},
		{
			name:   "spec journey absent from the catalog",
			mutate: func(*catalog.Catalog) {},
			spec:   []string{"J1", "J2", "J3", "J4"},
			want:   "J4",
		},
		{
			name: "catalog journey absent from the spec",
			mutate: func(c *catalog.Catalog) {
				c.Journeys = append(c.Journeys, catalog.Journey{ID: "J9", Feature: "F1", Checks: []catalog.Check{
					{ID: "J9.1", Tier: 1, Status: "covered", Tests: []string{"TestUnit"}},
				}})
			},
			want: "J9",
		},
		{
			name: "active feature with no journey",
			mutate: func(c *catalog.Catalog) {
				c.Features = append(c.Features, catalog.Feature{ID: "F4", Title: "four", Source: "x", Status: "active"})
			},
			want: "F4",
		},
		{
			name:   "journey names an unknown feature",
			mutate: func(c *catalog.Catalog) { c.Journeys[2].Feature = "F9" },
			want:   "J3",
		},
		{
			name:   "tier above 3",
			mutate: func(c *catalog.Catalog) { c.Journeys[0].Checks[0].Tier = 4 },
			want:   "J1.1",
		},
		{
			name:   "covered with no tier",
			mutate: func(c *catalog.Catalog) { c.Journeys[0].Checks[0].Tier = 0 },
			want:   "J1.1",
		},
		{
			name:   "planned with no tier",
			mutate: func(c *catalog.Catalog) { c.Journeys[1].Checks[0].Tier = 0 },
			want:   "J2.1",
		},
		{
			name:   "negative tier on a platform check",
			mutate: func(c *catalog.Catalog) { c.PlatformChecks[0].Tier = -1 },
			want:   "P3.1",
		},
		{
			name: "duplicate check id",
			mutate: func(c *catalog.Catalog) {
				c.PlatformChecks = append(c.PlatformChecks,
					catalog.Check{ID: "J1.1", Tier: 1, Status: "covered", Tests: []string{"TestUnit"}})
			},
			want: "J1.1",
		},
		{
			name:   "check id outside its journey",
			mutate: func(c *catalog.Catalog) { c.Journeys[2].Checks[1].ID = "J2.2" },
			want:   "J2.2",
		},
		{
			name:   "journey with no checks",
			mutate: func(c *catalog.Catalog) { c.Journeys[1].Checks = nil },
			want:   "J2",
		},
		{
			name:   "unknown feature status",
			mutate: func(c *catalog.Catalog) { c.Features[2].Status = "gone" },
			want:   "F3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validCatalog()
			tt.mutate(c)
			spec := tt.spec
			if spec == nil {
				spec = specIDs
			}
			errs := c.Validate(index, spec)
			if tt.want == "" {
				if len(errs) != 0 {
					t.Fatalf("Validate() = %v, want no errors", errs)
				}
				return
			}
			if len(errs) != 1 {
				t.Fatalf("Validate() = %v, want exactly one error naming %s", errs, tt.want)
			}
			if !strings.Contains(errs[0].Error(), tt.want) {
				t.Errorf("Validate() error = %v, want it to name %s", errs[0], tt.want)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    *catalog.Catalog
		wantErr string
	}{
		{
			name: "every field",
			in: `features:
  - id: F1
    title: one
    source: docs/design/user-secrets.md#goals
    status: active
journeys:
  - id: J1
    feature: F1
    checks:
      - id: J1.1
        tier: 2
        status: planned
        tests: [TestA, "run.sh:policy B: creator allowlist"]
        reason: later
        until: Slice 8
platform_checks:
  - id: P3.1
    tier: 3
    status: covered
    tests: [TestP]
`,
			want: &catalog.Catalog{
				Features: []catalog.Feature{
					{ID: "F1", Title: "one", Source: "docs/design/user-secrets.md#goals", Status: "active"},
				},
				Journeys: []catalog.Journey{{ID: "J1", Feature: "F1", Checks: []catalog.Check{{
					ID: "J1.1", Tier: 2, Status: "planned", Tests: []string{"TestA", "run.sh:policy B: creator allowlist"},
					Reason: "later", Until: "Slice 8",
				}}}},
				PlatformChecks: []catalog.Check{{ID: "P3.1", Tier: 3, Status: "covered", Tests: []string{"TestP"}}},
			},
		},
		{name: "unknown top-level field", in: "features: []\nextra: 1\n", wantErr: "extra"},
		{
			name:    "unknown check field",
			in:      "journeys:\n  - id: J1\n    checks:\n      - id: J1.1\n        teir: 2\n",
			wantErr: "teir",
		},
		{name: "tier not a number", in: "platform_checks:\n  - id: P3.1\n    tier: three\n", wantErr: "tier"},
		{name: "not yaml", in: "features: [\n", wantErr: "catalog"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := catalog.Load(strings.NewReader(tt.in))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Load() error = %v, want one naming %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			var gotDoc, wantDoc bytes.Buffer
			if err := catalog.RenderCoverage(got, &gotDoc); err != nil {
				t.Fatal(err)
			}
			if err := catalog.RenderCoverage(tt.want, &wantDoc); err != nil {
				t.Fatal(err)
			}
			if gotDoc.String() != wantDoc.String() {
				t.Errorf("Load() rendered:\n%s\nwant:\n%s", gotDoc.String(), wantDoc.String())
			}
		})
	}
}

func TestSpecJourneyIDs(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []string
		wantErr string
	}{
		{
			name: "rows of the Journeys table only",
			in: "# Spec\n\n| 7 | not this table |\n\n## Journeys\n\n| # | Item |\n|---|------|\n" +
				"| 1 | first | x |\n| 2 | second |\n|  10 | tenth |\n\n## Next\n\n| 3 | not a journey |\n",
			want: []string{"J1", "J2", "J10"},
		},
		{name: "no Journeys section", in: "# Spec\n\n| 1 | x |\n", wantErr: "Journeys"},
		{name: "empty Journeys table", in: "## Journeys\n\n| # | Item |\n|---|---|\n", wantErr: "Journeys"},
		{name: "duplicate row", in: "## Journeys\n\n| 1 | a |\n| 1 | b |\n", wantErr: "J1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := catalog.SpecJourneyIDs(strings.NewReader(tt.in))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("SpecJourneyIDs() error = %v, want one naming %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("SpecJourneyIDs() error = %v", err)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("SpecJourneyIDs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSourceIndex(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"internal/a/a_test.go": "package a\n\nimport \"testing\"\n\n" +
			"func TestUnit(t *testing.T) {}\n" +
			"func TestBench(b *testing.B) {}\n" +
			"func helperTest(t *testing.T) {}\n" +
			"type x struct{}\n\nfunc (x) TestMethod(t *testing.T) {}\n",
		"internal/a/a.go": "package a\n\nimport \"testing\"\n\nfunc TestNotInTestFile(t *testing.T) {}\n",
		"internal/a/integration_test.go": "//go:build integration\n\npackage a\n\nimport \"testing\"\n\n" +
			"func TestIntegration(t *testing.T) {}\n",
		"internal/a/linux_test.go": "//go:build linux\n\npackage a\n\nimport \"testing\"\n\n" +
			"func TestOtherTag(t *testing.T) {}\n",
		"test/e2e/e2e_test.go": "// Copyright\n\n//go:build e2e\n\npackage e2e\n\nimport \"testing\"\n\n" +
			"func TestE2E(t *testing.T) {}\n",
		"test/journeys/nebari_test.go": "//go:build journeys\n\npackage journeys\n\nimport \"testing\"\n\n" +
			"func TestJourney(t *testing.T) {}\n",
		"test/policy/run.sh": "#!/usr/bin/env bash\necho \"== setup\"\necho \"== policy B: creator allowlist\"\n" +
			"kubectl apply -f x\n",
		"internal/a/notintegration_test.go": "//go:build !integration\n\npackage a\n\nimport \"testing\"\n\n" +
			"func TestNotIntegration(t *testing.T) {}\n",
		"test/e2e/compound_test.go": "//go:build e2e && !windows\n\npackage e2e\n\nimport \"testing\"\n\n" +
			"func TestE2ECompound(t *testing.T) {}\n",
		"cmd/x/integration_test.go": "//go:build integration\n\npackage x\n\nimport \"testing\"\n\n" +
			"func TestIntegrationOutsideInternal(t *testing.T) {}\n",
		"test/e2e-extra/e2e_test.go": "//go:build e2e\n\npackage extra\n\nimport \"testing\"\n\n" +
			"func TestE2EOutsideDir(t *testing.T) {}\n",
		"internal/b/journeys_test.go": "//go:build journeys\n\npackage b\n\nimport \"testing\"\n\n" +
			"func TestJourneyOutsideDir(t *testing.T) {}\n",
		".hidden/h_test.go":  "package h\n\nimport \"testing\"\n\nfunc TestHidden(t *testing.T) {}\n",
		"vendor/v/v_test.go": "package v\n\nimport \"testing\"\n\nfunc TestVendored(t *testing.T) {}\n",
	}
	for p, content := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	idx, err := catalog.NewSourceIndex(root)
	if err != nil {
		t.Fatalf("NewSourceIndex() error = %v", err)
	}
	tests := []struct {
		tier int
		name string
		want bool
	}{
		{1, "TestUnit", true},
		{2, "TestE2E", true},
		{3, "TestJourney", true},
		{2, "run.sh:policy B: creator allowlist", true},
		{2, "run.sh:setup", true},
		{1, "TestE2E", false},
		{3, "TestE2E", false},
		{2, "TestUnit", false},
		{2, "TestJourney", false},
		{1, "TestJourney", false},
		{2, "TestIntegration", true},
		{1, "TestIntegration", false},
		{3, "TestIntegration", false},
		{1, "TestOtherTag", false},
		{2, "TestOtherTag", false},
		{3, "TestOtherTag", false},
		{1, "TestBench", false},
		{1, "helperTest", false},
		{1, "TestMethod", false},
		{1, "TestNotInTestFile", false},
		{1, "TestHidden", false},
		{1, "TestVendored", false},
		{2, "run.sh:policy B", false},
		{2, "run.sh:kubectl apply -f x", false},
		{2, "run.sh:", false},
		{1, "run.sh:setup", false},
		{3, "run.sh:setup", false},
		{1, "TestNotIntegration", true},
		{2, "TestNotIntegration", false},
		{3, "TestNotIntegration", false},
		{2, "TestE2ECompound", true},
		{1, "TestE2ECompound", false},
		{1, "TestIntegrationOutsideInternal", false},
		{2, "TestIntegrationOutsideInternal", false},
		{3, "TestIntegrationOutsideInternal", false},
		{1, "TestE2EOutsideDir", false},
		{2, "TestE2EOutsideDir", false},
		{1, "TestJourneyOutsideDir", false},
		{2, "TestJourneyOutsideDir", false},
		{3, "TestJourneyOutsideDir", false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("tier %d %s", tt.tier, tt.name), func(t *testing.T) {
			if got := idx.Has(tt.tier, tt.name); got != tt.want {
				t.Errorf("Has(%d, %q) = %v, want %v", tt.tier, tt.name, got, tt.want)
			}
		})
	}
}

func TestScanWorkflowSecrets(t *testing.T) {
	tests := []struct {
		name string
		file string
		// want holds, per error in order, a substring it must contain; none
		// means the file passes. The line is the one holding the reference.
		want []string
	}{
		{name: "GITHUB_TOKEN", file: "env:\n  T: ${{ secrets.GITHUB_TOKEN }}\n"},
		{name: "github.token", file: "env:\n  T: ${{ github.token }}\n"},
		{name: "prose outside expressions", file: "# never Secrets, never secrets.FOO in a comment\nrun: echo secrets\n"},
		{
			name: "a repo secret",
			file: "on: push\nenv:\n  T: ${{ secrets.FOO }}\n",
			want: []string{"ci.yml:3: reads secrets.FOO"},
		},
		{name: "upper-case context", file: "env:\n  T: ${{ SECRETS.FOO }}\n", want: []string{"ci.yml:2: reads secrets.FOO"}},
		{name: "index syntax", file: "x: 1\nenv:\n  T: ${{ secrets['FOO'] }}\n", want: []string{"ci.yml:3"}},
		{name: "every secret", file: "run: echo '${{ toJSON(secrets) }}'\n", want: []string{"ci.yml:1"}},
		{
			name: "secrets inherit",
			file: "jobs:\n  x:\n    uses: ./.github/workflows/y.yml\n    secrets: inherit\n",
			want: []string{"ci.yml:4: reads secrets: inherit"},
		},
		{
			name: "two on one line and one later",
			file: "a: ${{ secrets.A }} ${{ secrets.GITHUB_TOKEN }} ${{ secrets.B }}\nb: 1\nc: ${{\n  secrets.C }}\n",
			want: []string{"ci.yml:1: reads secrets.A", "ci.yml:1: reads secrets.B", "ci.yml:4: reads secrets.C"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := catalog.ScanWorkflowSecrets(map[string][]byte{".github/workflows/ci.yml": []byte(tt.file)})
			if len(errs) != len(tt.want) {
				t.Fatalf("ScanWorkflowSecrets() = %v, want %d errors", errs, len(tt.want))
			}
			for i, w := range tt.want {
				if !strings.Contains(errs[i].Error(), w) {
					t.Errorf("error %d = %v, want it to name %q", i, errs[i], w)
				}
			}
		})
	}
}

func TestRepoCatalog(t *testing.T) {
	root := repoRoot(t)
	f, err := os.Open(filepath.Join(root, "test", "journeys", "catalog.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	c, err := catalog.Load(f)
	if err != nil {
		t.Fatalf("Load(test/journeys/catalog.yaml): %v", err)
	}
	spec, err := os.Open(filepath.Join(root, "docs", "design", "user-secrets-spec.md"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = spec.Close() }()
	ids, err := catalog.SpecJourneyIDs(spec)
	if err != nil {
		t.Fatalf("SpecJourneyIDs(docs/design/user-secrets-spec.md): %v", err)
	}
	idx, err := catalog.NewSourceIndex(root)
	if err != nil {
		t.Fatalf("NewSourceIndex: %v", err)
	}
	for _, e := range c.Validate(idx, ids) {
		t.Errorf("catalog: %v", e)
	}

	workflows, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(workflows) == 0 {
		t.Fatal("no .github/workflows/*.yml found")
	}
	files := map[string][]byte{}
	for _, p := range workflows {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, p)
		files[filepath.ToSlash(rel)] = b
	}
	for _, e := range catalog.ScanWorkflowSecrets(files) {
		t.Errorf("workflow: %v", e)
	}

	var want bytes.Buffer
	if err := catalog.RenderCoverage(c, &want); err != nil {
		t.Fatalf("RenderCoverage: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "docs", "ci", "coverage.md"))
	if err != nil {
		t.Fatalf("read docs/ci/coverage.md (run make coverage-doc): %v", err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Errorf("docs/ci/coverage.md is stale: run make coverage-doc")
	}
}
