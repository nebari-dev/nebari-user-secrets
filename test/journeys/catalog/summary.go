package catalog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Results are test outcomes by top-level test name (or run.sh:<section>):
// pass, fail or skip.
type Results map[string]string

// Test outcomes, and the summary's word for a test that did not report.
const (
	ResultPass   = "pass"
	ResultFail   = "fail"
	ResultSkip   = "skip"
	ResultNotRun = "not run"
)

// rank orders outcomes when one name reports more than once (the same test
// name in two packages, or a repeated policy section): fail wins over pass,
// pass over skip.
var rank = map[string]int{ResultSkip: 1, ResultPass: 2, ResultFail: 3}

// Merge adds src to r; for a name in both, the worse outcome is kept.
func (r Results) Merge(src Results) {
	for name, res := range src {
		r.add(name, res)
	}
}

func (r Results) add(name, res string) {
	if rank[res] > rank[r[name]] {
		r[name] = res
	}
}

// testEvent is the part of a go test -json event (cmd/test2json) read here.
type testEvent struct {
	Action string `json:"Action"`
	Test   string `json:"Test"`
}

// ParseTestJSON reads go test -json output and returns the outcome of every
// top-level test; subtests and package-level events are ignored. Lines that
// are not JSON objects (for example go: downloading ...) are skipped.
func ParseTestJSON(r io.Reader) (Results, error) {
	res := Results{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev testEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("go test -json line %d: %w", n, err)
		}
		if ev.Test == "" || strings.Contains(ev.Test, "/") {
			continue
		}
		switch ev.Action {
		case ResultPass, ResultFail, ResultSkip:
			res.add(ev.Test, ev.Action)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read go test -json: %w", err)
	}
	return res, nil
}

// ParsePolicyTranscript reads a test/policy/run.sh transcript and returns
// run.sh:<label> for every section that ran at least one expect: fail if any
// of its expects failed, else pass. Sections without expects are left out.
func ParsePolicyTranscript(r io.Reader) (Results, error) {
	res := Results{}
	section := ""
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if label, ok := strings.CutPrefix(line, "== "); ok {
			section = strings.TrimSpace(label)
			continue
		}
		if section == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "PASS  "):
			res.add(PolicyPrefix+section, ResultPass)
		case strings.HasPrefix(line, "FAIL  "):
			res.add(PolicyPrefix+section, ResultFail)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read policy transcript: %w", err)
	}
	return res, nil
}

// NICInfo is the NIC release a Tier 3 run installed, and whether it contains
// NIC_REQUIRED_COMMIT (so whether the run blocks).
type NICInfo struct {
	Tag, Commit string
	Blocking    bool
}

// SummaryInput is everything a job summary shows besides the catalog and
// the pins. Note, Timing and Resources are printed verbatim.
type SummaryInput struct {
	Tier                         int
	Commit, QueueHead, QueueBase string
	Results                      Results
	NIC                          *NICInfo
	Timing, Resources, Note      string
}

// RenderSummary writes a job summary in Markdown: the note, the commit (and
// merge queue head and base), the NIC release when given, every pin, and
// every check of the tier with its result or its reason. It reads nothing
// from the environment.
func RenderSummary(c *Catalog, pins Pins, in SummaryInput, w io.Writer) error {
	if in.Tier < 1 || in.Tier > 3 {
		return fmt.Errorf("summary: tier %d, want 1, 2 or 3", in.Tier)
	}
	bw := bufio.NewWriter(w)
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(bw, format, a...) }

	if in.Note != "" {
		p("%s\n\n", in.Note)
	}
	p("## Tier %d\n\n", in.Tier)
	p("**Commit under test:** %s\n\n", code(in.Commit))
	if in.QueueHead != "" || in.QueueBase != "" {
		p("**Merge queue:** head %s, base %s\n\n", code(in.QueueHead), code(in.QueueBase))
	}
	if in.NIC != nil {
		gate := "NON-BLOCKING"
		if in.NIC.Blocking {
			gate = "BLOCKING"
		}
		p("**NIC release:** %s at %s: **%s**\n\n", code(in.NIC.Tag), code(in.NIC.Commit), gate)
	}

	p("### Pins (ci/pins.env)\n\n| Pin | Value |\n|---|---|\n")
	keys := make([]string, 0, len(pins))
	for k := range pins {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		p("| %s | %s |\n", code(k), code(pins[k]))
	}

	p("\n### Checks (test/journeys/catalog.yaml)\n\n")
	p("| Check | Status | Result | Tests | Reason | Until |\n|---|---|---|---|---|---|\n")
	row := func(ch Check) {
		if ch.Tier != in.Tier {
			return
		}
		result, list := "-", tests(ch.Tests)
		if ch.Status == StatusCovered {
			result, list = checkResult(ch.Tests, in.Results)
		}
		p("| %s | %s | %s | %s | %s | %s |\n", cell(ch.ID), cell(ch.Status), result, list, cell(ch.Reason), cell(ch.Until))
	}
	for _, j := range c.Journeys {
		for _, ch := range j.Checks {
			row(ch)
		}
	}
	for _, ch := range c.PlatformChecks {
		row(ch)
	}

	if in.Timing != "" {
		p("\n### Timing\n\n%s\n", in.Timing)
	}
	if in.Resources != "" {
		p("\n### Resources\n\n%s\n", in.Resources)
	}
	return bw.Flush()
}

// checkResult returns a covered check's result and its tests with their
// results: fail if any test failed, else not run if any did not report, else
// skip if any skipped, else pass.
func checkResult(names []string, res Results) (string, string) {
	var failed, notRun, skipped bool
	parts := make([]string, len(names))
	for i, n := range names {
		r, ok := res[n]
		switch {
		case !ok:
			r, notRun = ResultNotRun, true
		case r == ResultFail:
			failed = true
		case r == ResultSkip:
			skipped = true
		}
		parts[i] = code(n) + ": " + r
	}
	result := ResultPass
	switch {
	case failed:
		result = ResultFail
	case notRun:
		result = ResultNotRun
	case skipped:
		result = ResultSkip
	}
	return result, strings.Join(parts, ", ")
}

// code formats s as inline code inside a Markdown table cell.
func code(s string) string {
	if s == "" {
		return "-"
	}
	return "`" + strings.ReplaceAll(s, "|", `\|`) + "`"
}
