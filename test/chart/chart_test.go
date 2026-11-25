package chart_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/nebari-dev/nebari-user-secrets/internal/config"
	"github.com/nebari-dev/nebari-user-secrets/internal/registry"
)

const (
	chartDir   = "../../chart"
	valuesFile = "../../chart/ci/lint-values.yaml"
	releaseNS  = "us-system"
	kindRole   = "Role"
)

// object is the part of a manifest these tests inspect.
type object struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec map[string]any    `json:"spec"`
	Data map[string]string `json:"data"`
	Raw  []byte            `json:"-"`
}

// helmTemplate renders the chart with the test values plus extra --set args.
func helmTemplate(t *testing.T, sets ...string) (string, error) {
	t.Helper()
	args := []string{"template", "user-secrets", chartDir, "--namespace", releaseNS, "-f", valuesFile}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	var out, errb bytes.Buffer
	cmd := exec.Command("helm", args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("helm template: %w: %s", err, errb.String())
	}
	return out.String(), nil
}

// helmTemplateDefaults renders the chart with its own values only.
func helmTemplateDefaults() error {
	cmd := exec.Command("helm", "template", "user-secrets", chartDir, "--namespace", releaseNS)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("helm template: %w: %s", err, errb.String())
	}
	return nil
}

func render(t *testing.T) []object {
	t.Helper()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatal(err)
	}
	return parse(t, out)
}

func parse(t *testing.T, manifest string) []object {
	t.Helper()
	dec := yaml.NewYAMLOrJSONDecoder(strings.NewReader(manifest), 4096)
	var objs []object
	for {
		var raw map[string]any
		if err := dec.Decode(&raw); err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("decode: %v", err)
		}
		if len(raw) == 0 {
			continue
		}
		b, err := sigsyaml.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		var o object
		if err := sigsyaml.Unmarshal(b, &o); err != nil {
			t.Fatal(err)
		}
		o.Raw = b
		objs = append(objs, o)
	}
	return objs
}

func find(t *testing.T, objs []object, kind string) object {
	t.Helper()
	for _, o := range objs {
		if o.Kind == kind {
			return o
		}
	}
	t.Fatalf("no %s rendered", kind)
	return object{}
}

func TestNoExternalSurface(t *testing.T) {
	objs := render(t)
	forbidden := map[string]bool{"NebariApp": true, "HTTPRoute": true, "Ingress": true}
	for _, o := range objs {
		if forbidden[o.Kind] {
			t.Errorf("forbidden kind %s/%s rendered", o.Kind, o.Metadata.Name)
		}
		if o.Kind == "Service" {
			if typ, _ := o.Spec["type"].(string); typ == "LoadBalancer" || typ == "NodePort" {
				t.Errorf("service %s has type %s", o.Metadata.Name, typ)
			}
		}
	}
}

func TestNetworkPolicyPorts(t *testing.T) {
	tests := []struct {
		name          string
		sets          []string
		wantResolveNS []string // nil: no 8443 rule
	}{
		{name: "registered workload namespaces, unique and sorted", wantResolveNS: []string{"dask-gateway", "jupyterhub"}},
		{name: "one workload namespace", sets: []string{"registry.apps[1].workloads=null"},
			wantResolveNS: []string{"jupyterhub"}},
		{name: "no workloads, no resolve rule", sets: []string{"registry.apps=null", "registry.creators=null"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := helmTemplate(t, tt.sets...)
			if err != nil {
				t.Fatal(err)
			}
			objs := parse(t, out)
			nps := 0
			for _, o := range objs {
				if o.Kind == "NetworkPolicy" {
					nps++
				}
			}
			if nps != 1 {
				t.Fatalf("want exactly one NetworkPolicy, got %d", nps)
			}
			np := find(t, objs, "NetworkPolicy")
			var whole struct {
				Spec struct {
					PolicyTypes []string `json:"policyTypes"`
					Ingress     []npRule `json:"ingress"`
				} `json:"spec"`
			}
			if err := sigsyaml.Unmarshal(np.Raw, &whole); err != nil {
				t.Fatal(err)
			}
			spec := whole.Spec
			if len(spec.PolicyTypes) != 1 || spec.PolicyTypes[0] != "Ingress" {
				t.Fatalf("policyTypes = %v, want [Ingress]", spec.PolicyTypes)
			}
			wantRules := 1
			if tt.wantResolveNS != nil {
				wantRules = 2
			}
			if len(spec.Ingress) != wantRules {
				t.Fatalf("want %d ingress rules, got %d", wantRules, len(spec.Ingress))
			}
			byPort := map[int]npRule{}
			for _, r := range spec.Ingress {
				if len(r.Ports) != 1 || r.Ports[0].Protocol != "TCP" {
					t.Fatalf("rule ports = %+v, want one TCP port per rule", r.Ports)
				}
				byPort[r.Ports[0].Port] = r
			}

			checkManagementRule(t, byPort)
			checkResolveRule(t, byPort, tt.wantResolveNS)
		})
	}
}

// npRule is the part of a NetworkPolicy ingress rule the tests inspect.
type npRule struct {
	From []struct {
		NamespaceSelector *struct {
			MatchLabels      map[string]string `json:"matchLabels"`
			MatchExpressions []struct {
				Key      string   `json:"key"`
				Operator string   `json:"operator"`
				Values   []string `json:"values"`
			} `json:"matchExpressions"`
		} `json:"namespaceSelector"`
		PodSelector *struct {
			MatchLabels map[string]string `json:"matchLabels"`
		} `json:"podSelector"`
	} `json:"from"`
	Ports []struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	} `json:"ports"`
}

// checkManagementRule: 8444 from the landing pods only, unchanged.
func checkManagementRule(t *testing.T, byPort map[int]npRule) {
	t.Helper()
	m, ok := byPort[8444]
	if !ok || len(m.From) != 1 {
		t.Fatalf("8444 rule = %+v, want one from entry", m)
	}
	f := m.From[0]
	if f.NamespaceSelector == nil || f.PodSelector == nil {
		t.Fatalf("8444 from = %+v, want namespace and pod selectors", f)
	}
	nsSel := f.NamespaceSelector
	if nsSel.MatchLabels["kubernetes.io/metadata.name"] != "nebari-system" || len(nsSel.MatchExpressions) != 0 {
		t.Errorf("namespace selector = %+v, want nebari-system", nsSel)
	}
	if got := f.PodSelector.MatchLabels["app.kubernetes.io/name"]; got != "nebari-landing" {
		t.Errorf("pod selector = %v, want the landing selector", f.PodSelector.MatchLabels)
	}
}

// checkResolveRule: 8443 from any pod in the registered workload namespaces,
// and no rule at all when there are none.
func checkResolveRule(t *testing.T, byPort map[int]npRule, wantNS []string) {
	t.Helper()
	res, ok := byPort[8443]
	if wantNS == nil {
		if ok {
			t.Fatalf("unexpected 8443 rule %+v", res)
		}
		return
	}
	if !ok || len(res.From) != 1 {
		t.Fatalf("8443 rule = %+v, want one from entry", res)
	}
	rf := res.From[0]
	if rf.PodSelector != nil || rf.NamespaceSelector == nil || len(rf.NamespaceSelector.MatchLabels) != 0 ||
		len(rf.NamespaceSelector.MatchExpressions) != 1 {
		t.Fatalf("8443 from = %+v, want one namespace match expression only", rf)
	}
	e := rf.NamespaceSelector.MatchExpressions[0]
	if e.Key != "kubernetes.io/metadata.name" || e.Operator != "In" || !slices.Equal(e.Values, wantNS) {
		t.Errorf("8443 namespace expression = %+v, want In %v", e, wantNS)
	}
}

func TestPodReaderRoles(t *testing.T) {
	type meta struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	}
	type rule struct {
		APIGroups     []string `json:"apiGroups"`
		Resources     []string `json:"resources"`
		ResourceNames []string `json:"resourceNames"`
		Verbs         []string `json:"verbs"`
	}
	type rbacObj struct {
		Metadata meta   `json:"metadata"`
		Rules    []rule `json:"rules"`
		RoleRef  struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"roleRef"`
		Subjects []struct {
			Kind      string `json:"kind"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"subjects"`
	}
	tests := []struct {
		name   string
		sets   []string
		wantNS []string
	}{
		{name: "one per unique registered workload namespace", wantNS: []string{"dask-gateway", "jupyterhub"}},
		{name: "one workload namespace", sets: []string{"registry.apps[1].workloads=null"}, wantNS: []string{"jupyterhub"}},
		{name: "none without workloads", sets: []string{"registry.apps=null", "registry.creators=null"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := helmTemplate(t, tt.sets...)
			if err != nil {
				t.Fatal(err)
			}
			var roles, bindings []string
			for _, o := range parse(t, out) {
				if o.Metadata.Name != "user-secrets-pod-reader" {
					continue
				}
				var r rbacObj
				if err := sigsyaml.Unmarshal(o.Raw, &r); err != nil {
					t.Fatal(err)
				}
				switch o.Kind {
				case kindRole:
					roles = append(roles, r.Metadata.Namespace)
					want := rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}
					if len(r.Rules) != 1 || !slices.Equal(r.Rules[0].APIGroups, want.APIGroups) ||
						!slices.Equal(r.Rules[0].Resources, want.Resources) || !slices.Equal(r.Rules[0].Verbs, want.Verbs) ||
						len(r.Rules[0].ResourceNames) != 0 {
						t.Errorf("role %s rules = %+v, want only pods get", r.Metadata.Namespace, r.Rules)
					}
				case "RoleBinding":
					bindings = append(bindings, r.Metadata.Namespace)
					sub := r.Subjects
					if r.RoleRef.Kind != kindRole || r.RoleRef.Name != "user-secrets-pod-reader" || len(sub) != 1 ||
						sub[0].Kind != "ServiceAccount" || sub[0].Name != "user-secrets" || sub[0].Namespace != releaseNS {
						t.Errorf("binding %s = %+v, want the service ServiceAccount", r.Metadata.Namespace, r)
					}
				default:
					t.Errorf("unexpected %s named user-secrets-pod-reader", o.Kind)
				}
			}
			if !slices.Equal(roles, tt.wantNS) || !slices.Equal(bindings, tt.wantNS) {
				t.Fatalf("roles in %v, bindings in %v, want %v", roles, bindings, tt.wantNS)
			}
		})
	}
}

func TestCreatorsConfigMapMatchesGo(t *testing.T) {
	var vals struct {
		Registry registry.Config `json:"registry"`
	}
	raw, err := os.ReadFile(valuesFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := sigsyaml.Unmarshal(raw, &vals); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	b, _ := sigsyaml.Marshal(vals.Registry)
	buf.Write(b)
	reg, err := registry.Load(&buf)
	if err != nil {
		t.Fatal(err)
	}
	want := reg.CreatorsConfigMapData()

	var got map[string]string
	for _, o := range render(t) {
		if o.Kind == "ConfigMap" && o.Metadata.Name == "user-secrets-creators" {
			got = o.Data
		}
	}
	if got == nil {
		t.Fatal("user-secrets-creators ConfigMap not rendered")
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("key %q: got %q, want %q", k, got[k], v)
		}
	}
}

func TestValidateFails(t *testing.T) {
	wlNS := "registry.apps[0].workloads[0].namespace=" + releaseNS
	crUser := "registry.creators[0].username=system:serviceaccount:" + releaseNS + ":hub"
	allowShared, unverified := "guard.allowSharedNamespace=true", "guard.mode=unverified"
	badUser := "must be exactly system:serviceaccount"
	crNS := "registry.creators[0].namespaces[0]=" + releaseNS
	badQPS := "kubernetes.qps must be a number greater than 0"
	badBurst := "kubernetes.burst must be a whole number of at least 1"
	burstBelowQPS := "kubernetes.burst must be at least kubernetes.qps"
	tests := []struct {
		name     string
		sets     []string
		wantErr  string // empty means the render must succeed
		defaults bool   // render with the chart defaults only
	}{
		{"baseline renders", nil, "", false},
		{"chart defaults alone fail on the first required value", nil, "clientID", true},
		{"service ns is a workload namespace", []string{wlNS}, "allowSharedNamespace", false},
		{"service ns is a creator namespace", []string{crNS}, "allowSharedNamespace", false},
		{"shared ns allowed with unverified", []string{wlNS, allowShared, unverified}, "", false},
		{"allowSharedNamespace without unverified", []string{"guard.allowSharedNamespace=true"}, "unverified", false},
		{"creator username in service ns", []string{crUser}, "allowSharedNamespace", false},
		{"empty clientID", []string{"keycloak.clientID="}, "clientID", false},
		{"empty jwksURL", []string{"keycloak.jwksURL="}, "keycloak.jwksURL is required", false},
		{"no issuers", []string{"keycloak.issuers=null"}, "keycloak.issuers needs", false},
		{"empty landing namespace", []string{"landing.namespace="}, "landing.namespace is required", false},
		{"empty landing podSelector", []string{"landing.podSelector=null"}, "landing.podSelector is required", false},
		{"malformed creator username", []string{"registry.creators[0].username=bad"}, badUser, false},
		{"five-part creator username", []string{"registry.creators[0].username=system:serviceaccount:a:b:c"}, badUser, false},
		{"kubernetes client override renders", []string{"kubernetes.qps=7.5", "kubernetes.burst=8"}, "", false},
		{"kubernetes qps zero", []string{"kubernetes.qps=0"}, badQPS, false},
		{"kubernetes qps negative", []string{"kubernetes.qps=-1"}, badQPS, false},
		{"kubernetes qps not a number", []string{"kubernetes.qps=fast"}, badQPS, false},
		{"kubernetes section removed", []string{"kubernetes=null"}, badQPS, false},
		{"kubernetes burst zero", []string{"kubernetes.burst=0"}, badBurst, false},
		{"kubernetes burst fractional", []string{"kubernetes.burst=60.5"}, badBurst, false},
		{"kubernetes burst below qps", []string{"kubernetes.burst=40"}, burstBelowQPS, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.defaults {
				err = helmTemplateDefaults()
			} else {
				_, err = helmTemplate(t, tc.sets...)
			}
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected failure: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatal("render succeeded, want failure")
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestCertificateWithinNICConstraints(t *testing.T) {
	cert := find(t, render(t), "Certificate")
	var spec struct {
		SecretName string   `json:"secretName"`
		DNSNames   []string `json:"dnsNames"`
		IPs        []string `json:"ipAddresses"`
		IssuerRef  struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"issuerRef"`
	}
	b, _ := sigsyaml.Marshal(cert.Spec)
	if err := sigsyaml.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.IssuerRef.Kind != "ClusterIssuer" || spec.IssuerRef.Name != "nebari-ca-issuer" {
		t.Errorf("issuerRef = %+v, want ClusterIssuer nebari-ca-issuer", spec.IssuerRef)
	}
	if spec.SecretName != "user-secrets-tls" {
		t.Errorf("secretName = %q", spec.SecretName)
	}
	wantNames := []string{"user-secrets." + releaseNS + ".svc", "user-secrets." + releaseNS + ".svc.cluster.local"}
	if strings.Join(spec.DNSNames, ",") != strings.Join(wantNames, ",") {
		t.Errorf("dnsNames = %v, want %v", spec.DNSNames, wantNames)
	}
	for _, n := range spec.DNSNames {
		if !strings.HasSuffix(n, ".svc") && !strings.HasSuffix(n, ".svc.cluster.local") {
			t.Errorf("dnsName %q is outside .svc / .svc.cluster.local", n)
		}
	}
	if len(spec.IPs) != 0 {
		t.Errorf("ipAddresses = %v, the root CA excludes every IP", spec.IPs)
	}
}

func TestPodSecurityRestricted(t *testing.T) {
	dep := find(t, render(t), "Deployment")
	var d struct {
		Spec struct {
			Template struct {
				Metadata metav1.ObjectMeta `json:"metadata"`
				Spec     corev1.PodSpec    `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := sigsyaml.Unmarshal(dep.Raw, &d); err != nil {
		t.Fatal(err)
	}
	ev, err := policy.NewEvaluator(policy.DefaultChecks(), nil)
	if err != nil {
		t.Fatal(err)
	}
	lv := api.LevelVersion{Level: api.LevelRestricted, Version: api.LatestVersion()}
	results := ev.EvaluatePod(lv, &d.Spec.Template.Metadata, &d.Spec.Template.Spec)
	for _, r := range results {
		if !r.Allowed {
			t.Errorf("restricted check failed: %s: %s", r.ForbiddenReason, r.ForbiddenDetail)
		}
	}
}

func TestConfigMapLoads(t *testing.T) {
	var cfgYAML string
	for _, o := range render(t) {
		if o.Kind == "ConfigMap" && o.Metadata.Name == "user-secrets-config" {
			cfgYAML = o.Data["config.yaml"]
		}
	}
	if cfgYAML == "" {
		t.Fatal("user-secrets-config ConfigMap has no config.yaml")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v\n%s", err, cfgYAML)
	}
	if cfg.Namespace != releaseNS {
		t.Errorf("namespace = %q, want %q", cfg.Namespace, releaseNS)
	}
	if cfg.Keycloak.ClientID != "landing-spa" {
		t.Errorf("clientID = %q", cfg.Keycloak.ClientID)
	}
	if cfg.Kubernetes != (config.Kubernetes{QPS: 50, Burst: 100}) {
		t.Errorf("kubernetes = %+v, want the chart defaults qps 50 burst 100", cfg.Kubernetes)
	}
	if _, err := cfg.BuildRegistry(); err != nil {
		t.Errorf("BuildRegistry: %v", err)
	}
}

// TestRoleRules: the namespaced Role grants the secrets store its verbs and
// the guard exactly what it needs, ConfigMap reads and updates by name.
func TestRoleRules(t *testing.T) {
	type rule struct {
		APIGroups     []string `json:"apiGroups"`
		Resources     []string `json:"resources"`
		ResourceNames []string `json:"resourceNames"`
		Verbs         []string `json:"verbs"`
	}
	var role struct {
		Rules []rule `json:"rules"`
	}
	var found bool
	for _, o := range render(t) {
		if o.Kind == "Role" && o.Metadata.Name == "user-secrets" {
			if err := sigsyaml.Unmarshal(o.Raw, &role); err != nil {
				t.Fatal(err)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("Role user-secrets not rendered")
	}
	want := []rule{
		{APIGroups: []string{""}, Resources: []string{"secrets"},
			Verbs: []string{"get", "list", "create", "update", "delete"}},
		{APIGroups: []string{""}, Resources: []string{"configmaps"},
			ResourceNames: []string{"user-secrets-creators", "user-secrets-guard-state"},
			Verbs:         []string{"get", "list", "watch"}},
		{APIGroups: []string{""}, Resources: []string{"configmaps"},
			ResourceNames: []string{"user-secrets-guard-state"}, Verbs: []string{"update"}},
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"create"}},
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}},
	}
	if len(role.Rules) != len(want) {
		t.Fatalf("%d rules, want %d: %+v", len(role.Rules), len(want), role.Rules)
	}
	for i, w := range want {
		t.Run(fmt.Sprintf("rule %d %v %v", i, w.Resources, w.Verbs), func(t *testing.T) {
			g := role.Rules[i]
			if !slices.Equal(g.APIGroups, w.APIGroups) || !slices.Equal(g.Resources, w.Resources) ||
				!slices.Equal(g.ResourceNames, w.ResourceNames) || !slices.Equal(g.Verbs, w.Verbs) {
				t.Errorf("got %+v, want %+v", g, w)
			}
		})
	}
}
