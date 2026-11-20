// Package registry holds the apps that may receive secrets and the creators
// allowed to name users for given namespaces and apps.
package registry

import (
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

var appIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Config is the on-disk registry document.
type Config struct {
	Apps     []App           `json:"apps"`
	Creators []model.Creator `json:"creators"`
}

// App is a registered app and the workload identities that may resolve for it.
type App struct {
	ID        model.AppID `json:"id"`
	Workloads []Workload  `json:"workloads"`
}

// Workload is a namespace and ServiceAccount pair.
type Workload struct {
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
}

type workloadKey struct {
	app       model.AppID
	namespace string
	sa        string
}

// Registry is immutable after Load and safe for concurrent reads.
type Registry struct {
	apps      []model.AppID // sorted
	workloads map[workloadKey]struct{}
	creators  []model.Creator
}

// Load parses and validates a registry document. Unknown fields are rejected.
func Load(r io.Reader) (*Registry, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read registry: %w", err)
	}
	var cfg Config
	if err := yaml.UnmarshalStrict(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse registry: %w", err)
	}

	reg := &Registry{workloads: map[workloadKey]struct{}{}}
	defined := map[model.AppID]struct{}{}
	for _, a := range cfg.Apps {
		if !appIDRE.MatchString(string(a.ID)) {
			return nil, fmt.Errorf("registry: invalid app id %q", a.ID)
		}
		if _, dup := defined[a.ID]; dup {
			return nil, fmt.Errorf("registry: duplicate app id %q", a.ID)
		}
		defined[a.ID] = struct{}{}
		reg.apps = append(reg.apps, a.ID)
		for _, w := range a.Workloads {
			if err := validLabel("workload namespace", w.Namespace); err != nil {
				return nil, fmt.Errorf("registry: app %q: %w", a.ID, err)
			}
			if err := validLabel("workload serviceAccount", w.ServiceAccount); err != nil {
				return nil, fmt.Errorf("registry: app %q: %w", a.ID, err)
			}
			reg.workloads[workloadKey{a.ID, w.Namespace, w.ServiceAccount}] = struct{}{}
		}
	}
	slices.Sort(reg.apps)

	seen := map[string]struct{}{}
	for _, c := range cfg.Creators {
		ns, name, ok := splitServiceAccount(c.Username)
		if !ok {
			return nil, fmt.Errorf("registry: creator username %q is not system:serviceaccount:<namespace>:<name>", c.Username)
		}
		if err := validLabel("creator username namespace", ns); err != nil {
			return nil, fmt.Errorf("registry: creator %q: %w", c.Username, err)
		}
		if err := validLabel("creator username name", name); err != nil {
			return nil, fmt.Errorf("registry: creator %q: %w", c.Username, err)
		}
		if _, dup := seen[c.Username]; dup {
			return nil, fmt.Errorf("registry: duplicate creator %q", c.Username)
		}
		seen[c.Username] = struct{}{}
		if len(c.Namespaces) == 0 {
			return nil, fmt.Errorf("registry: creator %q has no namespaces", c.Username)
		}
		for _, n := range c.Namespaces {
			if err := validLabel("creator namespace", n); err != nil {
				return nil, fmt.Errorf("registry: creator %q: %w", c.Username, err)
			}
		}
		if len(c.Apps) == 0 {
			return nil, fmt.Errorf("registry: creator %q has no apps", c.Username)
		}
		for _, a := range c.Apps {
			if _, ok := defined[a]; !ok {
				return nil, fmt.Errorf("registry: creator %q names undefined app %q", c.Username, a)
			}
		}
		reg.creators = append(reg.creators, model.Creator{
			Username:   c.Username,
			Namespaces: slices.Clone(c.Namespaces),
			Apps:       slices.Clone(c.Apps),
		})
	}
	return reg, nil
}

// validLabel requires a DNS-1123 label, which also excludes '.', ',' and ';'
// so values are safe in the creators ConfigMap encoding.
func validLabel(what, v string) error {
	if errs := validation.IsDNS1123Label(v); len(errs) > 0 {
		return fmt.Errorf("%s %q is not a DNS-1123 label: %s", what, v, strings.Join(errs, "; "))
	}
	return nil
}

func splitServiceAccount(u string) (ns, name string, ok bool) {
	parts := strings.Split(u, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
		return "", "", false
	}
	return parts[2], parts[3], true
}

// WorkloadAllowed reports whether the app is registered for the namespace and
// ServiceAccount.
func (r *Registry) WorkloadAllowed(app model.AppID, namespace, serviceAccount string) bool {
	_, ok := r.workloads[workloadKey{app, namespace, serviceAccount}]
	return ok
}

// Creators returns a copy of the creator allowlist in declared order.
func (r *Registry) Creators() []model.Creator {
	out := make([]model.Creator, len(r.creators))
	for i, c := range r.creators {
		out[i] = model.Creator{
			Username:   c.Username,
			Namespaces: slices.Clone(c.Namespaces),
			Apps:       slices.Clone(c.Apps),
		}
	}
	return out
}

// Apps returns the registered app ids, sorted.
func (r *Registry) Apps() []model.AppID { return slices.Clone(r.apps) }

// CreatorsConfigMapData renders the data of the user-secrets-creators
// ConfigMap read by the creators admission policy: key "<ns>.<sa>", value
// "namespaces=<a,b>;apps=<x,y>", lists sorted.
func (r *Registry) CreatorsConfigMapData() map[string]string {
	out := make(map[string]string, len(r.creators))
	for _, c := range r.creators {
		ns, name, _ := splitServiceAccount(c.Username)
		namespaces := slices.Clone(c.Namespaces)
		slices.Sort(namespaces)
		apps := make([]string, len(c.Apps))
		for i, a := range c.Apps {
			apps[i] = string(a)
		}
		slices.Sort(apps)
		out[ns+"."+name] = "namespaces=" + strings.Join(namespaces, ",") + ";apps=" + strings.Join(apps, ",")
	}
	return out
}
