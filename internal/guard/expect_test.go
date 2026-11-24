package guard

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

const testNS = "us-system"

var wantCM = map[string]string{"jhub.hub": "namespaces=a,b;apps=notebook"}

func creatorsCM() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "user-secrets-creators", Namespace: testNS},
		Data:       map[string]string{"jhub.hub": "namespaces=a,b;apps=notebook"},
	}
}

// live returns fresh copies of the expected objects, as a test starting point.
func live(t *testing.T) (Policies, Bindings) {
	t.Helper()
	e, err := NewExpectation(testNS)
	if err != nil {
		t.Fatal(err)
	}
	return Policies{Guard: e.guardPolicy.DeepCopy(), Creators: e.creatorsPolicy.DeepCopy()},
		Bindings{Guard: e.guardBinding.DeepCopy(), Creators: e.creatorsBinding.DeepCopy()}
}

// serverDefaulted sets what the API server fills in for the unmodified bundle,
// written out by hand (not via the code under test).
func serverDefaulted(p Policies, b Bindings) (Policies, Bindings) {
	equiv := admissionregistrationv1.Equivalent
	fail := admissionregistrationv1.Fail
	all := admissionregistrationv1.AllScopes
	for _, pol := range []*admissionregistrationv1.ValidatingAdmissionPolicy{p.Guard, p.Creators} {
		pol.Spec.FailurePolicy = &fail
		mc := pol.Spec.MatchConstraints
		mc.MatchPolicy = &equiv
		mc.NamespaceSelector = &metav1.LabelSelector{}
		mc.ObjectSelector = &metav1.LabelSelector{}
		for _, rules := range [][]admissionregistrationv1.NamedRuleWithOperations{mc.ResourceRules, mc.ExcludeResourceRules} {
			for i := range rules {
				rules[i].Scope = &all
			}
		}
	}
	mr := b.Creators.Spec.MatchResources
	mr.MatchPolicy = &equiv
	mr.NamespaceSelector = &metav1.LabelSelector{}
	for _, rules := range [][]admissionregistrationv1.NamedRuleWithOperations{mr.ResourceRules, mr.ExcludeResourceRules} {
		for i := range rules {
			rules[i].Scope = &all
		}
	}
	return p, b
}

func TestCompare(t *testing.T) {
	deny := []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}
	tests := []struct {
		name       string
		mutate     func(p *Policies, b *Bindings, cm **corev1.ConfigMap)
		wantOK     bool
		wantReason string
	}{
		{name: "good", wantOK: true},
		{
			name: "server-defaulted copy of the expectation",
			mutate: func(p *Policies, b *Bindings, _ **corev1.ConfigMap) {
				*p, *b = serverDefaulted(*p, *b)
				// Binding A as stored with an empty (defaulted) matchResources.
				equiv := admissionregistrationv1.Equivalent
				b.Guard.Spec.MatchResources = &admissionregistrationv1.MatchResources{
					MatchPolicy: &equiv, NamespaceSelector: &metav1.LabelSelector{}, ObjectSelector: &metav1.LabelSelector{},
				}
			},
			wantOK: true,
		},
		{
			name: "policy spec edited",
			mutate: func(p *Policies, _ *Bindings, _ **corev1.ConfigMap) {
				p.Guard.Spec.Validations[0].Expression = "true"
			},
			wantReason: "policy user-secrets-pod-guard: spec differs",
		},
		{
			name: "creators policy failurePolicy Ignore",
			mutate: func(p *Policies, _ *Bindings, _ **corev1.ConfigMap) {
				ign := admissionregistrationv1.Ignore
				p.Creators.Spec.FailurePolicy = &ign
			},
			wantReason: "policy user-secrets-creators: spec differs",
		},
		{
			name:       "guard policy missing",
			mutate:     func(p *Policies, _ *Bindings, _ **corev1.ConfigMap) { p.Guard = nil },
			wantReason: "policy user-secrets-pod-guard: missing",
		},
		{
			name:       "creators policy missing",
			mutate:     func(p *Policies, _ *Bindings, _ **corev1.ConfigMap) { p.Creators = nil },
			wantReason: "policy user-secrets-creators: missing",
		},
		{
			name:       "guard binding missing",
			mutate:     func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) { b.Guard = nil },
			wantReason: "binding user-secrets-pod-guard: missing",
		},
		{
			name:       "creators binding missing",
			mutate:     func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) { b.Creators = nil },
			wantReason: "binding user-secrets-creators: missing",
		},
		{
			name: "binding A gains paramRef",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Guard.Spec.ParamRef = &admissionregistrationv1.ParamRef{Name: "x"}
			},
			wantReason: "binding user-secrets-pod-guard: paramRef set",
		},
		{
			name: "binding A matchResources set",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Guard.Spec.MatchResources = &admissionregistrationv1.MatchResources{
					ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
				}
			},
			wantReason: "binding user-secrets-pod-guard: matchResources set",
		},
		{
			name: "binding A policyName changed",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Guard.Spec.PolicyName = "other"
			},
			wantReason: "binding user-secrets-pod-guard: policyName differs",
		},
		{
			name: "binding B paramRef name",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Creators.Spec.ParamRef.Name = "other"
			},
			wantReason: "binding user-secrets-creators: paramRef differs",
		},
		{
			name: "binding B paramRef namespace",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Creators.Spec.ParamRef.Namespace = "elsewhere"
			},
			wantReason: "binding user-secrets-creators: paramRef differs",
		},
		{
			name: "binding B parameterNotFoundAction Allow",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				a := admissionregistrationv1.AllowAction
				b.Creators.Spec.ParamRef.ParameterNotFoundAction = &a
			},
			wantReason: "binding user-secrets-creators: paramRef differs",
		},
		{
			name: "binding B paramRef gains selector",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Creators.Spec.ParamRef.Name = ""
				b.Creators.Spec.ParamRef.Selector = &metav1.LabelSelector{}
			},
			wantReason: "binding user-secrets-creators: paramRef differs",
		},
		{
			name: "binding B paramRef missing",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Creators.Spec.ParamRef = nil
			},
			wantReason: "binding user-secrets-creators: paramRef differs",
		},
		{
			name: "binding B objectSelector changed",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Creators.Spec.MatchResources.ObjectSelector.MatchLabels["nebari.dev/user-secrets"] = "false"
			},
			wantReason: "binding user-secrets-creators: matchResources differs",
		},
		{
			name: "binding B namespaceSelector set",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Creators.Spec.MatchResources.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"x": "y"}}
			},
			wantReason: "binding user-secrets-creators: matchResources differs",
		},
		{
			name: "binding B excludeResourceRules set",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Creators.Spec.MatchResources.ExcludeResourceRules = []admissionregistrationv1.NamedRuleWithOperations{{
					RuleWithOperations: admissionregistrationv1.RuleWithOperations{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
						Rule:       admissionregistrationv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods"}},
					},
				}}
			},
			wantReason: "binding user-secrets-creators: matchResources differs",
		},
		{
			name: "binding B matchResources missing",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Creators.Spec.MatchResources = nil
			},
			wantReason: "binding user-secrets-creators: matchResources differs",
		},
		{
			name: "binding A Warn",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Guard.Spec.ValidationActions = []admissionregistrationv1.ValidationAction{admissionregistrationv1.Warn}
			},
			wantReason: "binding user-secrets-pod-guard: validationActions lacks Deny",
		},
		{
			name: "binding A Audit",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Guard.Spec.ValidationActions = []admissionregistrationv1.ValidationAction{admissionregistrationv1.Audit}
			},
			wantReason: "binding user-secrets-pod-guard: validationActions lacks Deny",
		},
		{
			name: "binding B Warn and Audit",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Creators.Spec.ValidationActions = []admissionregistrationv1.ValidationAction{admissionregistrationv1.Warn, admissionregistrationv1.Audit}
			},
			wantReason: "binding user-secrets-creators: validationActions lacks Deny",
		},
		{
			name: "binding B Warn",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Creators.Spec.ValidationActions = []admissionregistrationv1.ValidationAction{admissionregistrationv1.Warn}
			},
			wantReason: "binding user-secrets-creators: validationActions lacks Deny",
		},
		{
			name: "binding A Deny and Audit passes",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Guard.Spec.ValidationActions = append(deny, admissionregistrationv1.Audit)
			},
			wantOK: true,
		},
		{
			name: "binding B Audit and Deny passes",
			mutate: func(_ *Policies, b *Bindings, _ **corev1.ConfigMap) {
				b.Creators.Spec.ValidationActions = []admissionregistrationv1.ValidationAction{admissionregistrationv1.Audit, admissionregistrationv1.Deny}
			},
			wantOK: true,
		},
		{
			name: "configmap data drift",
			mutate: func(_ *Policies, _ *Bindings, cm **corev1.ConfigMap) {
				(*cm).Data["jhub.hub"] = "namespaces=a,b,c;apps=notebook"
			},
			wantReason: "configmap user-secrets-creators: data differs at keys: jhub.hub",
		},
		{
			name: "configmap extra key",
			mutate: func(_ *Policies, _ *Bindings, cm **corev1.ConfigMap) {
				(*cm).Data["evil.sa"] = "namespaces=*;apps=*"
			},
			wantReason: "configmap user-secrets-creators: data differs at keys: evil.sa",
		},
		{
			name: "configmap key missing",
			mutate: func(_ *Policies, _ *Bindings, cm **corev1.ConfigMap) {
				(*cm).Data = nil
			},
			wantReason: "configmap user-secrets-creators: data differs at keys: jhub.hub",
		},
		{
			name: "configmap drift capped at five keys",
			mutate: func(_ *Policies, _ *Bindings, cm **corev1.ConfigMap) {
				for _, k := range []string{"a.1", "a.2", "a.3", "a.4", "a.5", "a.6", "a.7"} {
					(*cm).Data[k] = "x"
				}
			},
			wantReason: "configmap user-secrets-creators: data differs at keys: a.1,a.2,a.3,a.4,a.5,+2 more",
		},
		{
			name:       "configmap missing",
			mutate:     func(_ *Policies, _ *Bindings, cm **corev1.ConfigMap) { *cm = nil },
			wantReason: "configmap user-secrets-creators: missing",
		},
	}
	e, err := NewExpectation(testNS)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, b := live(t)
			cm := creatorsCM()
			if tt.mutate != nil {
				tt.mutate(&p, &b, &cm)
			}
			ok, reason := e.Compare(p, b, cm, wantCM)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v (reason %q), want %v", ok, reason, tt.wantOK)
			}
			if tt.wantOK && reason != "" {
				t.Errorf("reason = %q, want empty when ok", reason)
			}
			if !tt.wantOK && reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestCompareZeroExpectation(t *testing.T) {
	p, b := live(t)
	ok, reason := Expectation{}.Compare(p, b, creatorsCM(), wantCM)
	if ok || reason != "expectation not initialised" {
		t.Errorf("got (%v, %q), want (false, \"expectation not initialised\")", ok, reason)
	}
}

func TestCompareDoesNotMutateInputs(t *testing.T) {
	e, err := NewExpectation(testNS)
	if err != nil {
		t.Fatal(err)
	}
	p, b := live(t)
	pc, bc := Policies{p.Guard.DeepCopy(), p.Creators.DeepCopy()}, Bindings{b.Guard.DeepCopy(), b.Creators.DeepCopy()}
	e.Compare(p, b, creatorsCM(), wantCM)
	if !equalSemantic(p.Guard, pc.Guard) || !equalSemantic(p.Creators, pc.Creators) ||
		!equalSemantic(b.Guard, bc.Guard) || !equalSemantic(b.Creators, bc.Creators) {
		t.Error("Compare mutated its inputs")
	}
}

func TestNewExpectationNamespace(t *testing.T) {
	tests := []struct {
		ns      string
		wantErr bool
	}{
		{ns: "us-system"},
		{ns: "other-ns"},
		{ns: "", wantErr: true},
		{ns: "bad:ns", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.ns, func(t *testing.T) {
			e, err := NewExpectation(tt.ns)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			var expr string
			for _, v := range e.guardPolicy.Spec.Variables {
				if v.Name == "serviceAccount" {
					expr = v.Expression
				}
			}
			if want := "'system:serviceaccount:" + tt.ns + ":user-secrets'"; expr != want {
				t.Errorf("serviceAccount = %q, want %q", expr, want)
			}
			if got := e.creatorsBinding.Spec.ParamRef.Namespace; got != tt.ns {
				t.Errorf("paramRef.namespace = %q, want %q", got, tt.ns)
			}
		})
	}
}

// kustomize renders cluster/ with the install namespace set to ns, in a copy.
func kustomize(t *testing.T, ns string) []byte {
	t.Helper()
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Fatalf("kubectl is required on PATH: %v", err)
	}
	src := filepath.Join("..", "..", "cluster")
	dst := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		if en.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, en.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if en.Name() == "install-config.yaml" {
			if !strings.Contains(string(data), "namespace: us-system") {
				t.Fatal("install-config.yaml no longer sets namespace: us-system")
			}
			data = []byte(strings.ReplaceAll(string(data), "namespace: us-system", "namespace: "+ns))
		}
		if err := os.WriteFile(filepath.Join(dst, en.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var stderr bytes.Buffer
	cmd := exec.Command(kubectl, "kustomize", dst)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("kubectl kustomize: %v\n%s", err, stderr.String())
	}
	return out
}

func TestExpectationMatchesKustomize(t *testing.T) {
	for _, ns := range []string{"us-system", "us-test"} {
		t.Run(ns, func(t *testing.T) {
			out := kustomize(t, ns)
			var (
				p   Policies
				b   Bindings
				crb = map[string]rbacv1.ClusterRoleBinding{}
			)
			for _, doc := range strings.Split(string(out), "\n---\n") {
				var tm metav1.TypeMeta
				if err := yaml.Unmarshal([]byte(doc), &tm); err != nil {
					t.Fatal(err)
				}
				switch tm.Kind {
				case "ValidatingAdmissionPolicy":
					v := &admissionregistrationv1.ValidatingAdmissionPolicy{}
					if err := yaml.UnmarshalStrict([]byte(doc), v); err != nil {
						t.Fatal(err)
					}
					switch v.Name {
					case "user-secrets-pod-guard":
						p.Guard = v
					case "user-secrets-creators":
						p.Creators = v
					default:
						t.Fatalf("unexpected policy %q", v.Name)
					}
				case "ValidatingAdmissionPolicyBinding":
					v := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}
					if err := yaml.UnmarshalStrict([]byte(doc), v); err != nil {
						t.Fatal(err)
					}
					switch v.Name {
					case "user-secrets-pod-guard":
						b.Guard = v
					case "user-secrets-creators":
						b.Creators = v
					default:
						t.Fatalf("unexpected binding %q", v.Name)
					}
				case "ClusterRoleBinding":
					v := rbacv1.ClusterRoleBinding{}
					if err := yaml.UnmarshalStrict([]byte(doc), &v); err != nil {
						t.Fatal(err)
					}
					crb[v.Name] = v
				}
			}
			e, err := NewExpectation(ns)
			if err != nil {
				t.Fatal(err)
			}
			cm := creatorsCM()
			cm.Namespace = ns
			if ok, reason := e.Compare(p, b, cm, wantCM); !ok {
				t.Errorf("kustomize output does not match the embedded expectation: %s", reason)
			}
			// Guard against a vacuous pass: the namespace really is the one under test.
			if got := b.Creators.Spec.ParamRef.Namespace; got != ns {
				t.Errorf("rendered paramRef.namespace = %q, want %q", got, ns)
			}
			for _, name := range []string{"user-secrets-auth-delegator", "user-secrets-guard-reader"} {
				r, found := crb[name]
				if !found {
					t.Errorf("ClusterRoleBinding %s not rendered", name)
					continue
				}
				if len(r.Subjects) != 1 || r.Subjects[0].Name != "user-secrets" || r.Subjects[0].Namespace != ns {
					t.Errorf("%s subjects = %+v, want ServiceAccount user-secrets in %s", name, r.Subjects, ns)
				}
			}
		})
	}
}
