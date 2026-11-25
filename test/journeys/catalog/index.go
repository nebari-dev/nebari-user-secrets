package catalog

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// PolicyPrefix marks a tier 2 test name that is a section of the policy
// matrix: run.sh:<label> for a section run.sh opens with echo "== <label>".
const PolicyPrefix = "run.sh:"

// policyScript is the policy matrix, relative to the repo root.
const policyScript = "test/policy/run.sh"

// tierTags are the build tags that select each cluster tier's tests, in
// tier order, each with the directory (relative to the index root, slash
// separated) that CI runs with that tag. Tier 1 is every _test.go file that
// builds with no tags set; Tier 2 runs both the kind suite (e2e) and the
// store-level integration tests against the same kind cluster. A tagged test
// outside its tag's directory runs in no tier, so it is not indexed.
var tierTags = []struct {
	tier int
	tag  string
	dir  string
}{{2, "e2e", "test/e2e"}, {2, "integration", "internal"}, {3, "journeys", "test/journeys"}}

// SourceIndex is the set of test functions under a source tree, by the tier
// whose build tags select their file, plus the policy matrix's sections.
type SourceIndex struct {
	tests map[int]map[string]bool
}

// NewSourceIndex parses every _test.go file under root (skipping hidden
// directories, vendor and testdata) and the section labels of
// test/policy/run.sh, if present.
func NewSourceIndex(root string) (*SourceIndex, error) {
	idx := &SourceIndex{tests: map[int]map[string]bool{1: {}, 2: {}, 3: {}}}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if p != root && (strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, "_test.go") || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		return idx.addFile(fset, p, filepath.ToSlash(rel))
	})
	if err != nil {
		return nil, fmt.Errorf("index tests under %s: %w", root, err)
	}
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(policyScript)))
	switch {
	case err == nil:
		for _, label := range policySections(b) {
			idx.tests[2][PolicyPrefix+label] = true
		}
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("read %s: %w", policyScript, err)
	}
	return idx, nil
}

// Has reports whether name runs in tier.
func (s *SourceIndex) Has(tier int, name string) bool {
	return s.tests[tier][name]
}

// addFile indexes the test functions of the file at path, whose path
// relative to the index root is rel (slash separated).
func (s *SourceIndex) addFile(fset *token.FileSet, path, rel string) error {
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return err
	}
	tier, err := fileTier(f, rel)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if tier == 0 {
		return nil
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && isTestFunc(fn) {
			s.tests[tier][fn.Name.Name] = true
		}
	}
	return nil
}

// fileTier returns the tier that runs the file at rel (slash separated,
// relative to the index root): 1 when it builds with no tags set; 2 or 3 when
// it builds with only one of that tier's tags set, does not build with no
// tags, and sits under that tag's directory; 0 otherwise (for example
// //go:build linux, or an integration test outside internal/).
func fileTier(f *ast.File, rel string) (int, error) {
	var expr constraint.Expr
	for _, g := range f.Comments {
		if g.Pos() >= f.Package {
			break
		}
		for _, c := range g.List {
			if !constraint.IsGoBuild(c.Text) {
				continue
			}
			e, err := constraint.Parse(c.Text)
			if err != nil {
				return 0, err
			}
			expr = e
		}
	}
	if expr == nil || expr.Eval(func(string) bool { return false }) {
		return 1, nil
	}
	for _, tt := range tierTags {
		if expr.Eval(func(t string) bool { return t == tt.tag }) && strings.HasPrefix(rel, tt.dir+"/") {
			return tt.tier, nil
		}
	}
	return 0, nil
}

// isTestFunc reports whether fn is func TestXxx(t *testing.T).
func isTestFunc(fn *ast.FuncDecl) bool {
	if fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
		return false
	}
	params := fn.Type.Params.List
	if len(params) != 1 || len(params[0].Names) > 1 {
		return false
	}
	star, ok := params[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "T" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "testing"
}

// policySections returns the labels of run.sh's echo "== <label>" lines.
func policySections(b []byte) []string {
	var labels []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		rest, ok := strings.CutPrefix(line, `echo "== `)
		if !ok {
			continue
		}
		if label, ok := strings.CutSuffix(rest, `"`); ok && label != "" {
			labels = append(labels, label)
		}
	}
	return labels
}
