// Package catalog reads the CI pins file and the journey catalog that the CI
// tiers test against.
package catalog

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Pins are the external versions from ci/pins.env, by key.
type Pins map[string]string

var pinKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// shellExpansions are rejected in values: every reader (bash, make,
// $GITHUB_ENV) must see the same literal text.
var shellExpansions = []string{"$(", "`", "${"}

// LoadPins parses ci/pins.env: KEY=value lines, lines starting with # and
// empty lines skipped. Keys are upper case and unique; values are literal and
// may hold spaces (POLICY_K8S_VERSIONS).
func LoadPins(r io.Reader) (Pins, error) {
	pins := Pins{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("pins line %d: want KEY=value, got %q", n, line)
		}
		if !pinKey.MatchString(key) {
			return nil, fmt.Errorf("pins line %d: key %q is not upper case [A-Z][A-Z0-9_]*", n, key)
		}
		for _, s := range shellExpansions {
			if strings.Contains(value, s) {
				return nil, fmt.Errorf("pins line %d: %s value holds %q; values must be literal", n, key, s)
			}
		}
		if _, dup := pins[key]; dup {
			return nil, fmt.Errorf("pins line %d: duplicate key %s", n, key)
		}
		pins[key] = value
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read pins: %w", err)
	}
	return pins, nil
}

// Require returns an error naming every key that is missing or empty.
func (p Pins) Require(keys ...string) error {
	var missing []string
	for _, k := range keys {
		if p[k] == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("ci/pins.env is missing %s", strings.Join(missing, ", "))
	}
	return nil
}
