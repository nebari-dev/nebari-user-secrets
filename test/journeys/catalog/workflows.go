package catalog

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

var (
	// expression is a GitHub Actions ${{ ... }} expression, possibly
	// spanning lines.
	expression = regexp.MustCompile(`(?s)\$\{\{.*?\}\}`)
	// secretsRef is a use of the secrets context (contexts are
	// case-insensitive), with the property name when it is a dot access.
	secretsRef = regexp.MustCompile(`(?i)\bsecrets\b(?:\s*\.\s*([A-Za-z0-9_-]+))?`)
	// inheritSecrets passes every secret to a called workflow.
	inheritSecrets = regexp.MustCompile(`(?im)^\s*secrets\s*:\s*inherit\b`)
)

// ScanWorkflowSecrets returns an error for every use of the secrets context
// other than secrets.GITHUB_TOKEN, and every secrets: inherit, in the given
// workflow files (path -> content). Errors name file:line, in path order.
func ScanWorkflowSecrets(files map[string][]byte) []error {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	var errs []error
	for _, p := range paths {
		b := files[p]
		lineOf := func(off int) int { return 1 + strings.Count(string(b[:off]), "\n") }
		type finding struct {
			off int
			msg string
		}
		var found []finding
		for _, loc := range expression.FindAllIndex(b, -1) {
			expr := b[loc[0]:loc[1]]
			for _, m := range secretsRef.FindAllSubmatchIndex(expr, -1) {
				name := ""
				if m[2] >= 0 {
					name = string(expr[m[2]:m[3]])
				}
				if strings.EqualFold(name, "GITHUB_TOKEN") {
					continue
				}
				what := "the secrets context"
				if name != "" {
					what = "secrets." + name
				}
				found = append(found, finding{loc[0] + m[0], what})
			}
		}
		for _, loc := range inheritSecrets.FindAllIndex(b, -1) {
			found = append(found, finding{loc[0], "secrets: inherit"})
		}
		slices.SortStableFunc(found, func(a, b finding) int { return a.off - b.off })
		for _, f := range found {
			errs = append(errs, fmt.Errorf("%s:%d: reads %s; required checks may use only secrets.GITHUB_TOKEN",
				p, lineOf(f.off), f.msg))
		}
	}
	return errs
}
