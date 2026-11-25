// Command summary appends a CI job summary to $GITHUB_STEP_SUMMARY (stdout
// when unset): the commit, every pin from ci/pins.env and the tier's checks
// from test/journeys/catalog.yaml with their results. Run it from the repo
// root.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nebari-dev/nebari-user-secrets/test/journeys/catalog"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "summary:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("summary", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var in catalog.SummaryInput
	var results, policyResults, nicTag, nicCommit string
	var blocking bool
	fs.IntVar(&in.Tier, "tier", 0, "tier: 1, 2 or 3")
	fs.StringVar(&in.Commit, "commit", "", "commit under test (github.sha)")
	fs.StringVar(&in.QueueHead, "queue-head", "", "merge_group head SHA")
	fs.StringVar(&in.QueueBase, "queue-base", "", "merge_group base SHA")
	fs.StringVar(&results, "results", "", "comma-separated go test -json files, merged")
	fs.StringVar(&policyResults, "policy-results", "", "comma-separated test/policy/run.sh transcripts, merged")
	fs.StringVar(&nicTag, "nic-tag", "", "Tier 3: NIC release tag")
	fs.StringVar(&nicCommit, "nic-commit", "", "Tier 3: the NIC release's commit")
	fs.BoolVar(&blocking, "blocking", false, "Tier 3: the NIC release contains NIC_REQUIRED_COMMIT")
	fs.StringVar(&in.Timing, "timing", "", "Tier 3: timing report, printed verbatim")
	fs.StringVar(&in.Resources, "resources", "", "Tier 3: resource summary, printed verbatim")
	fs.StringVar(&in.Note, "note", "", "line printed verbatim at the top")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if nicTag != "" || nicCommit != "" {
		in.NIC = &catalog.NICInfo{Tag: nicTag, Commit: nicCommit, Blocking: blocking}
	}

	pins, err := loadPins("ci/pins.env")
	if err != nil {
		return err
	}
	c, err := loadCatalog("test/journeys/catalog.yaml")
	if err != nil {
		return err
	}
	in.Results = catalog.Results{}
	if err := mergeFiles(in.Results, results, catalog.ParseTestJSON, stderr); err != nil {
		return err
	}
	if err := mergeFiles(in.Results, policyResults, catalog.ParsePolicyTranscript, stderr); err != nil {
		return err
	}

	out := stdout
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		out = f
	}
	return catalog.RenderSummary(c, pins, in, out)
}

func loadPins(path string) (catalog.Pins, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return catalog.LoadPins(f)
}

func loadCatalog(path string) (*catalog.Catalog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return catalog.Load(f)
}

// mergeFiles parses each comma-separated file with parse and merges it into
// dst. A missing file (its step never ran) is reported on stderr and its
// tests show as not run; any other error fails.
func mergeFiles(dst catalog.Results, list string, parse func(io.Reader) (catalog.Results, error),
	stderr io.Writer) error {
	for _, p := range strings.Split(list, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		f, err := os.Open(p)
		if os.IsNotExist(err) {
			_, _ = fmt.Fprintf(stderr, "summary: %s not found; its tests show as not run\n", p)
			continue
		}
		if err != nil {
			return err
		}
		res, err := parse(f)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		dst.Merge(res)
	}
	return nil
}
