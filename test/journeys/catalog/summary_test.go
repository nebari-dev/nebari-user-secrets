package catalog_test

import (
	"bytes"
	"maps"
	"strings"
	"testing"

	"github.com/nebari-dev/nebari-user-secrets/test/journeys/catalog"
)

func TestRenderSummary(t *testing.T) {
	pins := catalog.Pins{"KIND_VERSION": "v9.9.1", "POLICY_K8S_VERSIONS": "v9.1.0 v9.2.0"}
	pinRows := []string{"| `KIND_VERSION` | `v9.9.1` |", "| `POLICY_K8S_VERSIONS` | `v9.1.0 v9.2.0` |"}
	tests := []struct {
		name    string
		in      catalog.SummaryInput
		want    []string
		notWant []string
		// wantFirst is the expected first line of the output.
		wantFirst string
		wantErr   bool
	}{
		{
			name: "tier 1 pull_request",
			in:   catalog.SummaryInput{Tier: 1, Commit: "abc123", Results: catalog.Results{"TestUnit": "pass"}},
			want: append([]string{
				"`abc123`",
				"| J1.1 | covered | pass | `TestUnit`: pass | - | - |",
			}, pinRows...),
			notWant:   []string{"Merge queue", "J1.2", "J2.1", "J3.1", "P3.1", "NIC release", "BLOCKING"},
			wantFirst: "## Tier 1",
		},
		{
			name: "tier 1 failure",
			in:   catalog.SummaryInput{Tier: 1, Commit: "abc123", Results: catalog.Results{"TestUnit": "fail"}},
			want: []string{"| J1.1 | covered | fail | `TestUnit`: fail | - | - |"},
		},
		{
			name: "tier 1 test absent from results",
			in:   catalog.SummaryInput{Tier: 1, Commit: "abc123", Results: catalog.Results{"TestOther": "pass"}},
			want: []string{"| J1.1 | covered | not run | `TestUnit`: not run | - | - |"},
		},
		{
			name: "tier 2 merge_group, one test of a check failed and one absent",
			in: catalog.SummaryInput{Tier: 2, Commit: "abc123", QueueHead: "head456", QueueBase: "base789",
				Results: catalog.Results{"TestE2E": "fail"}},
			want: append([]string{
				"`head456`", "`base789`",
				"| J1.2 | covered | fail | `TestE2E`: fail, `run.sh:policy B`: not run | - | - |",
			}, pinRows...),
			notWant: []string{"J1.1", "J3.1"},
		},
		{
			name: "tier 2 all tests of a check pass",
			in: catalog.SummaryInput{Tier: 2, Commit: "abc123",
				Results: catalog.Results{"TestE2E": "pass", "run.sh:policy B": "pass"}},
			want: []string{"| J1.2 | covered | pass |"},
		},
		{
			name: "tier 2 skipped test",
			in: catalog.SummaryInput{Tier: 2, Commit: "abc123",
				Results: catalog.Results{"TestE2E": "skip", "run.sh:policy B": "pass"}},
			want: []string{"| J1.2 | covered | skip |"},
		},
		{
			name: "tier 3 non-blocking with timing, resources and the skip note",
			in: catalog.SummaryInput{Tier: 3, Commit: "abc123", QueueHead: "head456", QueueBase: "base789",
				Results: catalog.Results{"TestJourney": "pass"},
				NIC:     &catalog.NICInfo{Tag: "v0.18.0", Commit: "1234abcd"},
				Timing:  "| step | s |\n|---|---|\n| kind | 41 |", Resources: "peak memory 9.1 GiB, disk 11 GiB",
				Note: "> merge_group: NIC v0.18.0 lacks the required commit; steps skipped."},
			want: append([]string{
				"`v0.18.0`", "`1234abcd`", "NON-BLOCKING",
				"| step | s |\n|---|---|\n| kind | 41 |", "peak memory 9.1 GiB, disk 11 GiB",
				"| J3.1 | covered | pass | `TestJourney`: pass | - | - |",
				"| P3.1 | covered | pass | `TestJourney`: pass | - | - |",
				"| J2.1 | planned | - | `TestLater` | needs a cluster | Slice 8 |",
			}, pinRows...),
			notWant:   []string{"J3.2", "J1.1"},
			wantFirst: "> merge_group: NIC v0.18.0 lacks the required commit; steps skipped.",
		},
		{
			name: "tier 3 blocking",
			in: catalog.SummaryInput{Tier: 3, Commit: "abc123",
				NIC: &catalog.NICInfo{Tag: "v0.19.0", Commit: "5678ef", Blocking: true}},
			want:    []string{"`v0.19.0`", "`5678ef`", "BLOCKING", "| J3.1 | covered | not run |"},
			notWant: []string{"NON-BLOCKING"},
		},
		{name: "tier out of range", in: catalog.SummaryInput{Tier: 4, Commit: "abc123"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := catalog.RenderSummary(notCoveredCatalog(), pins, tt.in, &buf)
			if tt.wantErr {
				if err == nil {
					t.Fatal("RenderSummary: want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("RenderSummary: %v", err)
			}
			got := buf.String()
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("output lacks %q\n%s", w, got)
				}
			}
			for _, nw := range tt.notWant {
				if strings.Contains(got, nw) {
					t.Errorf("output holds %q\n%s", nw, got)
				}
			}
			if tt.wantFirst != "" {
				if first, _, _ := strings.Cut(got, "\n"); first != tt.wantFirst {
					t.Errorf("first line = %q, want %q", first, tt.wantFirst)
				}
			}
		})
	}
}

// notCoveredCatalog is validCatalog plus a tier 3 not-covered check, so each
// tier 3 status is present; J3.2 (no tier) must never be listed.
func notCoveredCatalog() *catalog.Catalog {
	c := validCatalog()
	c.Journeys[2].Checks = append(c.Journeys[2].Checks,
		catalog.Check{ID: "J3.3", Tier: 3, Status: "not-covered", Reason: "needs a browser", Until: "a headless client"})
	return c
}

func TestRenderSummaryNotCovered(t *testing.T) {
	tests := []struct {
		name string
		tier int
		want string
	}{
		{name: "tier 3 lists the not-covered check with its reason", tier: 3,
			want: "| J3.3 | not-covered | - | - | needs a browser | a headless client |"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			in := catalog.SummaryInput{Tier: tt.tier, Commit: "c"}
			if err := catalog.RenderSummary(notCoveredCatalog(), catalog.Pins{}, in, &buf); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(buf.String(), tt.want) {
				t.Errorf("output lacks %q\n%s", tt.want, buf.String())
			}
		})
	}
}

func TestParseTestJSON(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    catalog.Results
		wantErr bool
	}{
		{
			name: "pass, fail, skip; subtests and package events ignored",
			in: `{"Action":"run","Package":"p","Test":"TestA"}
{"Action":"output","Package":"p","Test":"TestA","Output":"=== RUN TestA\n"}
{"Action":"pass","Package":"p","Test":"TestA/sub","Elapsed":0}
{"Action":"fail","Package":"p","Test":"TestA/other","Elapsed":0}
{"Action":"pass","Package":"p","Test":"TestA","Elapsed":0}
{"Action":"fail","Package":"p","Test":"TestB","Elapsed":0}
{"Action":"skip","Package":"p","Test":"TestC","Elapsed":0}
{"Action":"fail","Package":"p","Elapsed":0}
`,
			want: catalog.Results{"TestA": "pass", "TestB": "fail", "TestC": "skip"},
		},
		{
			name: "same name in two packages: fail wins over pass, pass over skip",
			in: `{"Action":"pass","Package":"p","Test":"TestA"}
{"Action":"fail","Package":"q","Test":"TestA"}
{"Action":"skip","Package":"p","Test":"TestB"}
{"Action":"pass","Package":"q","Test":"TestB"}
`,
			want: catalog.Results{"TestA": "fail", "TestB": "pass"},
		},
		{name: "non-JSON lines are skipped", in: "go: downloading x\n{\"Action\":\"pass\",\"Test\":\"TestA\"}\n",
			want: catalog.Results{"TestA": "pass"}},
		{name: "empty", in: "", want: catalog.Results{}},
		{name: "malformed JSON", in: "{\"Action\":\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := catalog.ParseTestJSON(strings.NewReader(tt.in))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseTestJSON: want error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTestJSON: %v", err)
			}
			if !maps.Equal(got, tt.want) {
				t.Errorf("ParseTestJSON = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePolicyTranscript(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want catalog.Results
	}{
		{
			name: "sections by their PASS and FAIL lines",
			in: `### v9.1.0
== setup
== policy B: creator allowlist
PASS  hub creates labelled pod
PASS  mallory denied
== pods/binding
PASS  binding carrying annotations
FAIL  plain binding (want allow, got deny)
      denied
== TokenReview extras
      authenticated: True

RESULT: 3 passed, 1 failed
`,
			want: catalog.Results{"run.sh:policy B: creator allowlist": "pass", "run.sh:pods/binding": "fail"},
		},
		{
			name: "a repeated section fails if any of its runs failed",
			in:   "== a\nFAIL  x (want deny, got allow)\n== b\nPASS  y\n== a\nPASS  z\n",
			want: catalog.Results{"run.sh:a": "fail", "run.sh:b": "pass"},
		},
		{name: "empty transcript", in: "", want: catalog.Results{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := catalog.ParsePolicyTranscript(strings.NewReader(tt.in))
			if err != nil {
				t.Fatalf("ParsePolicyTranscript: %v", err)
			}
			if !maps.Equal(got, tt.want) {
				t.Errorf("ParsePolicyTranscript = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResultsMerge(t *testing.T) {
	tests := []struct {
		name      string
		dst, src  catalog.Results
		wantAfter catalog.Results
	}{
		{name: "disjoint", dst: catalog.Results{"A": "pass"}, src: catalog.Results{"B": "fail"},
			wantAfter: catalog.Results{"A": "pass", "B": "fail"}},
		{name: "fail wins", dst: catalog.Results{"A": "pass"}, src: catalog.Results{"A": "fail"},
			wantAfter: catalog.Results{"A": "fail"}},
		{name: "fail kept", dst: catalog.Results{"A": "fail"}, src: catalog.Results{"A": "pass"},
			wantAfter: catalog.Results{"A": "fail"}},
		{name: "pass over skip", dst: catalog.Results{"A": "skip"}, src: catalog.Results{"A": "pass"},
			wantAfter: catalog.Results{"A": "pass"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.dst.Merge(tt.src)
			if !maps.Equal(tt.dst, tt.wantAfter) {
				t.Errorf("after Merge = %v, want %v", tt.dst, tt.wantAfter)
			}
		})
	}
}
