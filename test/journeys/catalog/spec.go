package catalog

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var journeyRow = regexp.MustCompile(`^\|\s*(\d+)\s*\|`)

// SpecJourneyIDs reads the spec's "## Journeys" table and returns J<n> for
// each row, in order.
func SpecJourneyIDs(spec io.Reader) ([]string, error) {
	var ids []string
	seen := map[string]bool{}
	in, found := false, false
	sc := bufio.NewScanner(spec)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "## ") {
			in = strings.TrimSpace(strings.TrimPrefix(line, "## ")) == "Journeys"
			found = found || in
			continue
		}
		if !in {
			continue
		}
		m := journeyRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		id := "J" + m[1]
		if seen[id] {
			return nil, fmt.Errorf("spec Journeys table: duplicate row %s", id)
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("spec has no ## Journeys section")
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("spec ## Journeys table has no rows")
	}
	return ids, nil
}
