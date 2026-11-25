// Command coverage writes docs/ci/coverage.md from test/journeys/catalog.yaml
// to stdout; run it from the repo root (make coverage-doc).
package main

import (
	"fmt"
	"os"

	"github.com/nebari-dev/nebari-user-secrets/test/journeys/catalog"
)

func main() {
	f, err := os.Open("test/journeys/catalog.yaml")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = f.Close() }()
	c, err := catalog.Load(f)
	if err == nil {
		err = catalog.RenderCoverage(c, os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
