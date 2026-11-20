package registry

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

const mutated = "mutated"

const validYAML = `
apps:
  - id: notebook
    workloads:
      - {namespace: hub-ns, serviceAccount: nb}
  - id: jhub-apps
    workloads:
      - {namespace: hub-ns, serviceAccount: jhub}
      - {namespace: other, serviceAccount: jhub}
creators:
  - username: system:serviceaccount:hub-ns:hub
    namespaces: [hub-ns]
    apps: [notebook, jhub-apps]
`

func TestLoadRejects(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"duplicate app id", "apps: [{id: a}, {id: a}]"},
		{"app id uppercase", "apps: [{id: Bad}]"},
		{"app id too long", "apps: [{id: a" + strings.Repeat("b", 32) + "}]"},
		{"app id empty", "apps: [{id: \"\"}]"},
		{"creator username not a service account", "apps: [{id: a}]\ncreators: [{username: alice, namespaces: [ns], apps: [a]}]"},
		{"creator username wrong shape", "apps: [{id: a}]\ncreators: [{username: 'system:serviceaccount:ns', namespaces: [ns], apps: [a]}]"},
		{"creator username namespace with dot", "apps: [{id: a}]\ncreators: [{username: 'system:serviceaccount:n.s:sa', namespaces: [ns], apps: [a]}]"},
		{"creator username name with dot", "apps: [{id: a}]\ncreators: [{username: 'system:serviceaccount:ns:s.a', namespaces: [ns], apps: [a]}]"},
		{"creator namespace with dot", "apps: [{id: a}]\ncreators: [{username: 'system:serviceaccount:ns:sa', namespaces: [n.s], apps: [a]}]"},
		{"creator namespace with separator", "apps: [{id: a}]\ncreators: [{username: 'system:serviceaccount:ns:sa', namespaces: ['a,b'], apps: [a]}]"},
		{"creator empty namespaces", "apps: [{id: a}]\ncreators: [{username: 'system:serviceaccount:ns:sa', apps: [a]}]"},
		{"creator empty apps", "apps: [{id: a}]\ncreators: [{username: 'system:serviceaccount:ns:sa', namespaces: [ns]}]"},
		{"creator undefined app", "apps: [{id: a}]\ncreators: [{username: 'system:serviceaccount:ns:sa', namespaces: [ns], apps: [b]}]"},
		{"duplicate creator", "apps: [{id: a}]\ncreators:\n - {username: 'system:serviceaccount:ns:sa', namespaces: [ns], apps: [a]}\n - {username: 'system:serviceaccount:ns:sa', namespaces: [ns], apps: [a]}"},
		{"workload namespace with dot", "apps: [{id: a, workloads: [{namespace: n.s, serviceAccount: sa}]}]"},
		{"workload namespace uppercase", "apps: [{id: a, workloads: [{namespace: NS, serviceAccount: sa}]}]"},
		{"workload serviceAccount empty", "apps: [{id: a, workloads: [{namespace: ns, serviceAccount: \"\"}]}]"},
		{"workload serviceAccount with dot", "apps: [{id: a, workloads: [{namespace: ns, serviceAccount: s.a}]}]"},
		{"unknown top-level field", "apps: [{id: a}]\nextra: 1"},
		{"unknown nested field", "apps: [{id: a, bogus: 1}]"},
		{"malformed yaml", "apps: [ {"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if r, err := Load(strings.NewReader(tt.yaml)); err == nil {
				t.Fatalf("expected error, got registry %+v", r)
			}
		})
	}
}

func TestLoadAcceptsEmpty(t *testing.T) {
	r, err := Load(strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.Apps()) != 0 || len(r.Creators()) != 0 || len(r.CreatorsConfigMapData()) != 0 {
		t.Fatalf("expected empty registry")
	}
}

func TestWorkloadAllowed(t *testing.T) {
	r, err := Load(strings.NewReader(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		app    model.AppID
		ns, sa string
		want   bool
	}{
		{"registered", "notebook", "hub-ns", "nb", true},
		{"second workload", "jhub-apps", "other", "jhub", true},
		{"wrong service account", "notebook", "hub-ns", "jhub", false},
		{"wrong namespace", "notebook", "other", "nb", false},
		{"other app's workload", "jhub-apps", "hub-ns", "nb", false},
		{"unknown app", "nope", "hub-ns", "nb", false},
		{"empty", "", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.WorkloadAllowed(tt.app, tt.ns, tt.sa); got != tt.want {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}

func TestAppsAndCreators(t *testing.T) {
	r, err := Load(strings.NewReader(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := r.Apps(), []model.AppID{"jhub-apps", "notebook"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("apps got %v want %v", got, want)
	}
	want := []model.Creator{{Username: "system:serviceaccount:hub-ns:hub", Namespaces: []string{"hub-ns"}, Apps: []model.AppID{"notebook", "jhub-apps"}}}
	if got := r.Creators(); !reflect.DeepEqual(got, want) {
		t.Fatalf("creators got %v want %v", got, want)
	}
}

func TestAccessorsReturnCopies(t *testing.T) {
	r, err := Load(strings.NewReader(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	r.Apps()[0] = mutated
	c := r.Creators()
	c[0].Namespaces[0] = mutated
	c[0].Apps[0] = mutated
	if r.Apps()[0] != "jhub-apps" || r.Creators()[0].Namespaces[0] != "hub-ns" || r.Creators()[0].Apps[0] != "notebook" {
		t.Fatal("registry state was mutated through an accessor")
	}
}

func TestCreatorsConfigMapData(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want map[string]string
	}{
		{"sorted lists", validYAML, map[string]string{"hub-ns.hub": "namespaces=hub-ns;apps=jhub-apps,notebook"}},
		{"multiple creators and namespaces", `
apps: [{id: b}, {id: a}]
creators:
  - {username: 'system:serviceaccount:z:y', namespaces: [n2, n1], apps: [b, a]}
  - {username: 'system:serviceaccount:x:w', namespaces: [n1], apps: [a]}
`, map[string]string{
			"z.y": "namespaces=n1,n2;apps=a,b",
			"x.w": "namespaces=n1;apps=a",
		}},
		{"no creators", "apps: [{id: a}]", map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Load(strings.NewReader(tt.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if got := r.CreatorsConfigMapData(); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}
