package catalog

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// RenderCoverage writes docs/ci/coverage.md: the features, every journey
// check and the platform checks, with tier, status, tests and reasons.
func RenderCoverage(c *Catalog, w io.Writer) error {
	bw := bufio.NewWriter(w)
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(bw, format, a...) }

	feature := map[string]string{}
	for _, f := range c.Features {
		feature[f.ID] = f.Title
	}
	total, covered := 0, 0
	for _, j := range c.Journeys {
		for _, ch := range j.Checks {
			total++
			if ch.Status == StatusCovered {
				covered++
			}
		}
	}

	p("# CI journey coverage\n\n")
	p("<!-- Generated from test/journeys/catalog.yaml by `make coverage-doc`. Do not edit by hand. -->\n\n")
	p("Journey checks covered in CI: %d of %d. `planned` and `not-covered` checks count as not covered. ", covered, total)
	p("Tier 1 runs unit and chart tests, Tier 2 the kind suite (build tags `e2e` and `integration`) and the ")
	p("policy matrix (`run.sh:<section>`), Tier 3 real Nebari (build tag `journeys`). ")
	p("Platform checks are not journeys and are listed apart.\n\n")

	p("## Features\n\n")
	p("| ID | Feature | Source | Status |\n|---|---|---|---|\n")
	for _, f := range c.Features {
		p("| %s | %s | %s | %s |\n", cell(f.ID), cell(f.Title), cell(f.Source), cell(f.Status))
	}

	p("\n## Journey checks\n\n")
	p("| Check | Feature | Tier | Status | Tests | Reason | Until |\n|---|---|---|---|---|---|---|\n")
	for _, j := range c.Journeys {
		for _, ch := range j.Checks {
			p("| %s | %s | %s | %s | %s | %s | %s |\n", cell(ch.ID), cell(j.Feature), tier(ch.Tier), cell(ch.Status),
				tests(ch.Tests), cell(ch.Reason), cell(ch.Until))
		}
	}

	p("\n## Platform checks\n\n")
	p("| Check | Tier | Status | Tests | Reason | Until |\n|---|---|---|---|---|---|\n")
	for _, ch := range c.PlatformChecks {
		p("| %s | %s | %s | %s | %s | %s |\n", cell(ch.ID), tier(ch.Tier), cell(ch.Status), tests(ch.Tests),
			cell(ch.Reason), cell(ch.Until))
	}
	return bw.Flush()
}

// cell makes s safe inside a Markdown table cell.
func cell(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return "-"
	}
	return strings.ReplaceAll(s, "|", `\|`)
}

func tier(t int) string {
	if t == 0 {
		return "-"
	}
	return strconv.Itoa(t)
}

func tests(names []string) string {
	if len(names) == 0 {
		return "-"
	}
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = "`" + strings.ReplaceAll(n, "|", `\|`) + "`"
	}
	return strings.Join(quoted, ", ")
}
