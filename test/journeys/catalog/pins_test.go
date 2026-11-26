package catalog_test

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/nebari-dev/nebari-user-secrets/internal/guard"
	"github.com/nebari-dev/nebari-user-secrets/test/journeys/catalog"
)

func TestLoadPins(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    catalog.Pins
		wantErr string
	}{
		{
			name: "comments and blank lines are skipped",
			in:   "# source: somewhere\n\nA_PIN=v1.2.3\n\n# another\nB=x\n",
			want: catalog.Pins{"A_PIN": "v1.2.3", "B": "x"},
		},
		{
			name: "KEY=value parses, value may contain = : @ /",
			in:   "IMG=registry.example/x:1@sha256:abc=\n",
			want: catalog.Pins{"IMG": "registry.example/x:1@sha256:abc="},
		},
		{
			// Fake versions: the real ones may appear only in ci/pins.env.
			name: "space-separated value keeps its spaces",
			in:   "POLICY_K8S_VERSIONS=v9.1.1 v9.2.2 v9.3.3\n",
			want: catalog.Pins{"POLICY_K8S_VERSIONS": "v9.1.1 v9.2.2 v9.3.3"},
		},
		{
			name: "empty input is an empty set",
			in:   "",
			want: catalog.Pins{},
		},
		{name: "duplicate key", in: "A=1\n# c\nA=2\n", wantErr: "line 3"},
		{name: "line without =", in: "A=1\nNOEQUALS\n", wantErr: "line 2"},
		{name: "lowercase key", in: "lower=1\n", wantErr: "line 1"},
		{name: "indented comment", in: "A=1\n  # c\n", wantErr: "line 2"},
		{name: "command substitution", in: "A=1\nB=$(id)\n", wantErr: "line 2"},
		{name: "backtick", in: "A=`id`\n", wantErr: "line 1"},
		{name: "parameter expansion", in: "A=1\n\nB=${HOME}\n", wantErr: "line 3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := catalog.LoadPins(strings.NewReader(tt.in))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("LoadPins() error = %v, want one naming %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadPins() error = %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("LoadPins() = %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("LoadPins()[%s] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestPinsRequire(t *testing.T) {
	pins := catalog.Pins{"A": "1", "EMPTY": ""}
	tests := []struct {
		name    string
		keys    []string
		wantErr []string
	}{
		{name: "present", keys: []string{"A"}},
		{name: "no keys", keys: nil},
		{name: "missing key is named", keys: []string{"A", "MISSING"}, wantErr: []string{"MISSING"}},
		{name: "empty value counts as missing", keys: []string{"EMPTY"}, wantErr: []string{"EMPTY"}},
		{name: "every missing key is named", keys: []string{"X", "Y"}, wantErr: []string{"X", "Y"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pins.Require(tt.keys...)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("Require() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Require() = nil, want an error naming %v", tt.wantErr)
			}
			for _, k := range tt.wantErr {
				if !strings.Contains(err.Error(), k) {
					t.Errorf("Require() error = %v, want it to name %s", err, k)
				}
			}
		})
	}
}

// pinKeys are the keys ci/pins.env must hold.
var pinKeys = []string{
	"GOLANGCI_LINT_VERSION", "HELM_VERSION", "KIND_VERSION", "KIND_NODE_IMAGE", "POLICY_K8S_VERSIONS",
	"CALICO_VERSION", "GATEWAY_API_VERSION", "CERT_MANAGER_VERSION", "TRUST_MANAGER_VERSION",
	"NIC_FIXTURES_REF", "NIC_REQUIRED_COMMIT", "KEYCLOAK_IMAGE", "CURL_IMAGE", "GO_BUILDER_IMAGE",
	"PAUSE_IMAGE", "DEPLOY_ACTION_REF",
}

// copyCheckedKeys are the pins whose values the "no other copy" scan looks
// for. Every value here is distinctive enough that a match outside the
// excluded paths is a real second copy: full three-part versions (not
// a Go language version like 1.26), image references with tag and digest, and
// the 40-hex NIC commit. go.mod and go.sum are excluded because module
// versions are a different namespace that can collide with these. Values
// holding several versions (POLICY_K8S_VERSIONS) are checked word by word.
// DEPLOY_ACTION_REF (v0.3.0) is left out: it is too generic to scan for, and
// its only legitimate copies, the workflow uses: refs, are cross-checked below.
var copyCheckedKeys = []string{
	"GOLANGCI_LINT_VERSION", "HELM_VERSION", "KIND_VERSION", "KIND_NODE_IMAGE", "POLICY_K8S_VERSIONS",
	"CALICO_VERSION", "GATEWAY_API_VERSION", "CERT_MANAGER_VERSION", "TRUST_MANAGER_VERSION",
	"NIC_FIXTURES_REF", "NIC_REQUIRED_COMMIT", "KEYCLOAK_IMAGE", "CURL_IMAGE", "GO_BUILDER_IMAGE",
	"PAUSE_IMAGE",
}

// crossChecked are the sources that cannot read ci/pins.env and so hold their
// own copy, which TestPinsMatchSources compares with the pin.
var crossChecked = map[string]string{
	"Dockerfile":              "GO_BUILDER_IMAGE",
	"internal/guard/probe.go": "PAUSE_IMAGE",
}

var (
	dockerfileArg = regexp.MustCompile(`(?m)^ARG GO_BUILDER_IMAGE=(\S*)\s*$`)
	deployRef     = regexp.MustCompile(`nebari-dev/deploy-nebari-action(?:/[^@\s]*)?@([^\s"'#]+)`)
)

func TestPinsMatchSources(t *testing.T) {
	root := repoRoot(t)
	f, err := os.Open(filepath.Join(root, "ci", "pins.env"))
	if err != nil {
		t.Fatalf("open pins: %v", err)
	}
	defer func() { _ = f.Close() }()
	pins, err := catalog.LoadPins(f)
	if err != nil {
		t.Fatalf("LoadPins(ci/pins.env): %v", err)
	}
	if err := pins.Require(pinKeys...); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  string
		// copies returns the source's copies of the pin; an error fails the test.
		copies func(root string) ([]string, error)
		// wantAtLeast is how many copies the source must hold.
		wantAtLeast int
	}{
		{
			name:        "guard.PauseImage",
			key:         "PAUSE_IMAGE",
			copies:      func(string) ([]string, error) { return []string{guard.PauseImage}, nil },
			wantAtLeast: 1,
		},
		{
			name:        "Dockerfile ARG GO_BUILDER_IMAGE default",
			key:         "GO_BUILDER_IMAGE",
			copies:      dockerfileBuilderArgs,
			wantAtLeast: 1,
		},
		{
			// The Tier 3 workflow (journeys.yml) holds them.
			name:        "workflow deploy-nebari-action refs",
			key:         "DEPLOY_ACTION_REF",
			copies:      workflowDeployRefs,
			wantAtLeast: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.copies(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) < tt.wantAtLeast {
				t.Fatalf("found %d copies, want at least %d", len(got), tt.wantAtLeast)
			}
			for _, v := range got {
				if v != pins[tt.key] {
					t.Errorf("%s = %q, want %s from ci/pins.env = %q", tt.name, v, tt.key, pins[tt.key])
				}
			}
		})
	}

	t.Run("no other copy of a pin value", func(t *testing.T) {
		for _, c := range pinCopies(t, os.DirFS(root), pins) {
			t.Errorf("%s holds %s's value %q: read it from ci/pins.env instead", c.where, c.key, c.value)
		}
	})
}

func dockerfileBuilderArgs(root string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		return nil, err
	}
	m := dockerfileArg.FindAllSubmatch(b, -1)
	if len(m) != 1 {
		return nil, fmt.Errorf("Dockerfile: want exactly one ARG GO_BUILDER_IMAGE=<default>, found %d", len(m))
	}
	return []string{string(m[0][1])}, nil
}

func workflowDeployRefs(root string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		return nil, err
	}
	var refs []string
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		for _, m := range deployRef.FindAllSubmatch(b, -1) {
			refs = append(refs, string(m[1]))
		}
	}
	return refs, nil
}

type pinCopy struct{ where, key, value string }

// skipDirs are never scanned: VCS data, local tool state, build output and
// generated test state, plus the directories allowed to hold pin values (docs,
// policy transcripts and the vendored NIC templates).
var skipDirs = map[string]bool{
	".git": true, ".superpowers": true, "bin": true, ".kube": true, ".tmp": true,
	"test/e2e/.tmp": true, "docs": true, "test/policy/results": true, "test/e2e/fixtures/nic": true,
}

// skipFile reports the files allowed to hold pin values: the pins
// file, docs (any *.md), Go module files and binaries.
func skipFile(p string, content []byte) bool {
	base := path.Base(p)
	return p == "ci/pins.env" || strings.HasSuffix(p, ".md") || base == "go.sum" || base == "go.mod" ||
		bytes.IndexByte(content, 0) >= 0
}

// pinCopies walks fsys and returns every line outside the allowed places that
// holds the value of a copy-checked pin.
func pinCopies(t *testing.T, fsys fs.FS, pins catalog.Pins) []pinCopy {
	t.Helper()
	var found []pinCopy
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if skipDirs[p] || (p == ".git" && !d.IsDir()) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		if skipFile(p, b) {
			return nil
		}
		for i, line := range strings.Split(string(b), "\n") {
			for _, key := range copyCheckedKeys {
				if crossChecked[p] == key {
					continue
				}
				for _, v := range strings.Fields(pins[key]) {
					if containsPin(line, v) {
						found = append(found, pinCopy{where: fmt.Sprintf("%s:%d", p, i+1), key: key, value: v})
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return found
}

// containsPin reports whether line holds v as a whole token: v9.8.7 must not
// match inside v9.8.70 or xv9.8.7.
func containsPin(line, v string) bool {
	for i := 0; ; {
		j := strings.Index(line[i:], v)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(v)
		if (start == 0 || !isTokenByte(line[start-1])) && (end == len(line) || !continuesToken(line[end:])) {
			return true
		}
		i = start + 1
	}
}

func isTokenByte(c byte) bool {
	return c == '_' || c == '.' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// continuesToken reports whether rest (the text after a match) extends the
// matched value: a letter, digit or underscore, or a dot followed by a digit.
func continuesToken(rest string) bool {
	c := rest[0]
	if c == '.' {
		return len(rest) > 1 && rest[1] >= '0' && rest[1] <= '9'
	}
	return isTokenByte(c)
}

func TestContainsPin(t *testing.T) {
	tests := []struct {
		line, v string
		want    bool
	}{
		{"CERT_MANAGER_VERSION=v9.8.7", "v9.8.7", true},
		{"helm --version v9.8.7 --wait", "v9.8.7", true},
		{"image: kindest/node:v9.1.1", "v9.1.1", true},
		{"see results/v9.1.1.txt", "v9.1.1", true},
		{"end of sentence v9.8.7.", "v9.8.7", true},
		{"github.com/x/y v9.8.70", "v9.8.7", false},
		{"v9.8.7.1", "v9.8.7", false},
		{"xv9.8.7", "v9.8.7", false},
		{"v9.8.70 then v9.8.7", "v9.8.7", true},
		{"nothing here", "v9.8.7", false},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			if got := containsPin(tt.line, tt.v); got != tt.want {
				t.Errorf("containsPin(%q, %q) = %v, want %v", tt.line, tt.v, got, tt.want)
			}
		})
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "..")
}
