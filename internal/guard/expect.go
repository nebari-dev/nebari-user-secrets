package guard

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"

	"github.com/nebari-dev/nebari-user-secrets/cluster"
)

const (
	guardName    = "user-secrets-pod-guard"
	creatorsName = "user-secrets-creators"
)

// Policies are the two live policies; a nil field means the object is missing.
type Policies struct {
	Guard, Creators *admissionregistrationv1.ValidatingAdmissionPolicy
}

// Bindings are the two live bindings; a nil field means the object is missing.
type Bindings struct {
	Guard, Creators *admissionregistrationv1.ValidatingAdmissionPolicyBinding
}

// Expectation is what the guard objects must look like, built from the
// policies embedded in the binary. Every object is stored in API-server
// defaulted form.
type Expectation struct {
	guardPolicy     *admissionregistrationv1.ValidatingAdmissionPolicy
	creatorsPolicy  *admissionregistrationv1.ValidatingAdmissionPolicy
	guardBinding    *admissionregistrationv1.ValidatingAdmissionPolicyBinding
	creatorsBinding *admissionregistrationv1.ValidatingAdmissionPolicyBinding
}

// NewExpectation parses the embedded cluster/policies.yaml and applies the two
// substitutions cluster/kustomization.yaml makes for the service namespace:
// index 2 of the ':'-delimited serviceAccount variable in policy A, and
// binding B's paramRef.namespace.
func NewExpectation(namespace string) (Expectation, error) {
	if errs := validation.IsDNS1123Label(namespace); len(errs) > 0 {
		return Expectation{}, fmt.Errorf("invalid namespace %q: %s", namespace, strings.Join(errs, "; "))
	}
	var e Expectation
	for _, doc := range strings.Split(string(cluster.Policies), "\n---\n") {
		var tm metav1.TypeMeta
		if err := yaml.Unmarshal([]byte(doc), &tm); err != nil {
			return Expectation{}, fmt.Errorf("parse embedded policies: %w", err)
		}
		switch tm.Kind {
		case "ValidatingAdmissionPolicy":
			p := &admissionregistrationv1.ValidatingAdmissionPolicy{}
			if err := yaml.UnmarshalStrict([]byte(doc), p); err != nil {
				return Expectation{}, fmt.Errorf("parse embedded policy: %w", err)
			}
			switch p.Name {
			case guardName:
				e.guardPolicy = p
			case creatorsName:
				e.creatorsPolicy = p
			}
		case "ValidatingAdmissionPolicyBinding":
			b := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}
			if err := yaml.UnmarshalStrict([]byte(doc), b); err != nil {
				return Expectation{}, fmt.Errorf("parse embedded binding: %w", err)
			}
			switch b.Name {
			case guardName:
				e.guardBinding = b
			case creatorsName:
				e.creatorsBinding = b
			}
		}
	}
	if e.guardPolicy == nil || e.creatorsPolicy == nil || e.guardBinding == nil || e.creatorsBinding == nil {
		return Expectation{}, fmt.Errorf("embedded policies.yaml lacks one of the two policies or two bindings")
	}

	substituted := false
	for i := range e.guardPolicy.Spec.Variables {
		v := &e.guardPolicy.Spec.Variables[i]
		if v.Name != "serviceAccount" {
			continue
		}
		parts := strings.Split(v.Expression, ":")
		if len(parts) != 4 {
			return Expectation{}, fmt.Errorf("serviceAccount variable %q does not have the expected 4 ':'-delimited parts", v.Expression)
		}
		parts[2] = namespace
		v.Expression = strings.Join(parts, ":")
		substituted = true
	}
	if !substituted {
		return Expectation{}, fmt.Errorf("policy %s has no serviceAccount variable", guardName)
	}
	if e.creatorsBinding.Spec.ParamRef == nil {
		return Expectation{}, fmt.Errorf("binding %s has no paramRef", creatorsName)
	}
	e.creatorsBinding.Spec.ParamRef.Namespace = namespace

	defaultPolicy(e.guardPolicy)
	defaultPolicy(e.creatorsPolicy)
	defaultBinding(e.guardBinding)
	defaultBinding(e.creatorsBinding)
	return e, nil
}

// Compare reports whether the live objects match the expectation. A freshly
// applied, unmodified bundle matches: both sides are normalised with the API
// server's defaulting before they are compared. The reason is short and stable
// and never contains ConfigMap values, only keys. The inputs are not modified.
func (e Expectation) Compare(p Policies, b Bindings, cm *corev1.ConfigMap, wantCM map[string]string) (ok bool, reason string) {
	if e.guardPolicy == nil || e.creatorsPolicy == nil || e.guardBinding == nil || e.creatorsBinding == nil {
		return false, "expectation not initialised"
	}
	if r := comparePolicy(guardName, e.guardPolicy, p.Guard); r != "" {
		return false, r
	}
	if r := comparePolicy(creatorsName, e.creatorsPolicy, p.Creators); r != "" {
		return false, r
	}
	if r := e.compareGuardBinding(b.Guard); r != "" {
		return false, r
	}
	if r := e.compareCreatorsBinding(b.Creators); r != "" {
		return false, r
	}
	if cm == nil {
		return false, "configmap " + creatorsName + ": missing"
	}
	if keys := differingKeys(cm.Data, wantCM); len(keys) > 0 {
		return false, "configmap " + creatorsName + ": data differs at keys: " + capKeys(keys)
	}
	return true, ""
}

func comparePolicy(name string, want, got *admissionregistrationv1.ValidatingAdmissionPolicy) string {
	if got == nil {
		return "policy " + name + ": missing"
	}
	got = got.DeepCopy()
	defaultPolicy(got)
	if !equalSemantic(want.Spec, got.Spec) {
		return "policy " + name + ": spec differs"
	}
	return ""
}

func (e Expectation) compareGuardBinding(got *admissionregistrationv1.ValidatingAdmissionPolicyBinding) string {
	pre := "binding " + guardName + ": "
	if got == nil {
		return pre + "missing"
	}
	got = got.DeepCopy()
	defaultBinding(got)
	switch {
	case got.Spec.PolicyName != e.guardBinding.Spec.PolicyName:
		return pre + "policyName differs"
	case got.Spec.ParamRef != nil:
		return pre + "paramRef set"
	case got.Spec.MatchResources != nil && !equalSemantic(got.Spec.MatchResources, defaultedEmptyMatchResources()):
		return pre + "matchResources set"
	case !slices.Contains(got.Spec.ValidationActions, admissionregistrationv1.Deny):
		return pre + "validationActions lacks Deny"
	}
	return ""
}

func (e Expectation) compareCreatorsBinding(got *admissionregistrationv1.ValidatingAdmissionPolicyBinding) string {
	pre := "binding " + creatorsName + ": "
	if got == nil {
		return pre + "missing"
	}
	got = got.DeepCopy()
	defaultBinding(got)
	want := e.creatorsBinding
	switch {
	case got.Spec.PolicyName != want.Spec.PolicyName:
		return pre + "policyName differs"
	case !equalSemantic(got.Spec.ParamRef, want.Spec.ParamRef):
		return pre + "paramRef differs"
	case !equalSemantic(got.Spec.MatchResources, want.Spec.MatchResources):
		return pre + "matchResources differs"
	case !slices.Contains(got.Spec.ValidationActions, admissionregistrationv1.Deny):
		return pre + "validationActions lacks Deny"
	}
	return ""
}

// maxReasonKeys bounds how many drifted key names a reason lists.
const maxReasonKeys = 5

// capKeys joins at most maxReasonKeys keys, then "+N more".
func capKeys(keys []string) string {
	if len(keys) <= maxReasonKeys {
		return strings.Join(keys, ",")
	}
	return fmt.Sprintf("%s,+%d more", strings.Join(keys[:maxReasonKeys], ","), len(keys)-maxReasonKeys)
}

// differingKeys returns the sorted keys whose value differs or that exist on
// only one side. Values never leave this function.
func differingKeys(got, want map[string]string) []string {
	var keys []string
	for k, v := range want {
		if gv, ok := got[k]; !ok || gv != v {
			keys = append(keys, k)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// equalSemantic compares like the API machinery does: nil and empty slices and
// maps are equal.
func equalSemantic(a, b any) bool { return apiequality.Semantic.DeepEqual(a, b) }

// The functions below reproduce the admissionregistration/v1 defaulting the API
// server applies on write, so the expectation and the live objects are compared
// in the same (defaulted) form. Source: k8s.io/kubernetes v1.35.0,
// pkg/apis/admissionregistration/v1/defaults.go:
//   - SetDefaults_ValidatingAdmissionPolicySpec, lines 98-103: failurePolicy Fail
//   - SetDefaults_MatchResources, lines 106-119: matchPolicy Equivalent, empty
//     namespaceSelector and objectSelector
//   - SetDefaults_Rule, lines 83-88: scope "*"
//
// and zz_generated.defaults.go (same directory, same tag), which applies them:
// SetObjectDefaults_ValidatingAdmissionPolicy lines 81-94 (spec, then
// matchConstraints and each resource and exclude rule) and
// SetObjectDefaults_ValidatingAdmissionPolicyBinding lines 96-108 (only when
// matchResources is non-nil).
func defaultPolicy(p *admissionregistrationv1.ValidatingAdmissionPolicy) {
	if p.Spec.FailurePolicy == nil {
		fail := admissionregistrationv1.Fail
		p.Spec.FailurePolicy = &fail
	}
	if p.Spec.MatchConstraints != nil {
		defaultMatchResources(p.Spec.MatchConstraints)
	}
}

func defaultBinding(b *admissionregistrationv1.ValidatingAdmissionPolicyBinding) {
	if b.Spec.MatchResources != nil {
		defaultMatchResources(b.Spec.MatchResources)
	}
}

func defaultMatchResources(m *admissionregistrationv1.MatchResources) {
	if m.MatchPolicy == nil {
		equiv := admissionregistrationv1.Equivalent
		m.MatchPolicy = &equiv
	}
	if m.NamespaceSelector == nil {
		m.NamespaceSelector = &metav1.LabelSelector{}
	}
	if m.ObjectSelector == nil {
		m.ObjectSelector = &metav1.LabelSelector{}
	}
	for _, rules := range [][]admissionregistrationv1.NamedRuleWithOperations{m.ResourceRules, m.ExcludeResourceRules} {
		for i := range rules {
			if rules[i].Scope == nil {
				all := admissionregistrationv1.AllScopes
				rules[i].Scope = &all
			}
		}
	}
}

func defaultedEmptyMatchResources() *admissionregistrationv1.MatchResources {
	m := &admissionregistrationv1.MatchResources{}
	defaultMatchResources(m)
	return m
}
