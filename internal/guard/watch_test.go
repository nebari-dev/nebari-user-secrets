package guard

import (
	"context"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func vapObj(name string) *admissionregistrationv1.ValidatingAdmissionPolicy {
	return &admissionregistrationv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func bindingObj(name string) *admissionregistrationv1.ValidatingAdmissionPolicyBinding {
	return &admissionregistrationv1.ValidatingAdmissionPolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestInformerWatcher(t *testing.T) {
	cases := []struct {
		name         string
		objs         []string // which of the five objects exist
		wantPolicies bool
		wantBindings bool
		wantCreators bool
	}{
		{"all present", []string{"pg", "pc", "bg", "bc", "cm"}, true, true, true},
		{"nothing", nil, false, false, false},
		{"one policy missing", []string{"pg", "bg", "bc", "cm"}, false, true, true},
		{"one binding missing", []string{"pg", "pc", "bg", "cm"}, true, false, true},
		{"configmap missing", []string{"pg", "pc", "bg", "bc"}, true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewClientset()
			for _, o := range tc.objs {
				var err error
				switch o {
				case "pg":
					_, err = cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(context.Background(), vapObj(guardName), metav1.CreateOptions{})
				case "pc":
					_, err = cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(context.Background(), vapObj(creatorsName), metav1.CreateOptions{})
				case "bg":
					_, err = cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(context.Background(), bindingObj(guardName), metav1.CreateOptions{})
				case "bc":
					_, err = cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(context.Background(), bindingObj(creatorsName), metav1.CreateOptions{})
				case "cm":
					_, err = cs.CoreV1().ConfigMaps(testNS).Create(context.Background(), creatorsCM(), metav1.CreateOptions{})
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			w := NewInformerWatcher(cs, testNS)
			if w.Synced() {
				t.Error("Synced before Start")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w.Start(ctx)
			waitFor(t, "sync", w.Synced)

			pg, pc, ok := w.Policies()
			if ok != tc.wantPolicies || (ok && (pg.Name != guardName || pc.Name != creatorsName)) {
				t.Errorf("Policies ok=%v", ok)
			}
			bg, bc, ok := w.Bindings()
			if ok != tc.wantBindings || (ok && (bg.Name != guardName || bc.Name != creatorsName)) {
				t.Errorf("Bindings ok=%v", ok)
			}
			cm, ok := w.Creators()
			if ok != tc.wantCreators || (ok && cm.Data["jhub.hub"] == "") {
				t.Errorf("Creators ok=%v", ok)
			}
		})
	}
}

func TestInformerWatcherAccessorsReturnCopies(t *testing.T) {
	cs := fake.NewClientset(vapObj(guardName), vapObj(creatorsName), creatorsCM())
	w := NewInformerWatcher(cs, testNS)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	waitFor(t, "sync", w.Synced)

	cm, _ := w.Creators()
	cm.Data["jhub.hub"] = "mutated"
	cm2, _ := w.Creators()
	if cm2.Data["jhub.hub"] == "mutated" {
		t.Error("Creators returned a shared object")
	}
	pg, _, _ := w.Policies()
	pg.Labels = map[string]string{"x": "y"}
	pg2, _, _ := w.Policies()
	if pg2.Labels != nil {
		t.Error("Policies returned a shared object")
	}
}

func TestInformerWatcherChanged(t *testing.T) {
	cs := fake.NewClientset(vapObj(guardName))
	w := NewInformerWatcher(cs, testNS)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	waitFor(t, "sync", w.Synced)

	drain := func() {
		for {
			select {
			case <-w.Changed():
			default:
				return
			}
		}
	}
	drain()

	upd := vapObj(guardName)
	upd.Labels = map[string]string{"a": "b"}
	if _, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Update(ctx, upd, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.Changed():
	case <-time.After(5 * time.Second):
		t.Fatal("no Changed signal after update")
	}

	// Events coalesce: several updates leave at most one pending signal, and the
	// send never blocks the informer.
	drain()
	for i := 0; i < 5; i++ {
		upd.Labels = map[string]string{"a": string(rune('c' + i))}
		if _, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Update(ctx, upd, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "last update visible", func() bool {
		return len(w.Changed()) == 1
	})
	if n := len(w.Changed()); n != 1 {
		t.Errorf("pending signals = %d, want 1", n)
	}
}

// The fake clientset does not honour field selectors on list or watch, so
// whether the API server would filter by name cannot be asserted here. What is
// testable, and asserted, is that every list and watch the watcher issues
// carries the metadata.name selector (RBAC resourceNames depend on it) and that
// the ConfigMap request is scoped to the service namespace.
func TestInformerWatcherRequestsCarryNameSelector(t *testing.T) {
	cs := fake.NewClientset()
	w := NewInformerWatcher(cs, testNS)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	waitFor(t, "sync", w.Synced)
	waitFor(t, "five watches", func() bool {
		n := 0
		for _, a := range cs.Actions() {
			if a.GetVerb() == "watch" {
				n++
			}
		}
		return n == 5
	})

	type key struct{ resource, sel, ns string }
	got := map[key]map[string]bool{}
	for _, a := range cs.Actions() {
		var sel string
		switch x := a.(type) {
		case k8stesting.ListActionImpl:
			sel = x.GetListRestrictions().Fields.String()
		case k8stesting.WatchActionImpl:
			sel = x.GetWatchRestrictions().Fields.String()
		default:
			continue
		}
		k := key{a.GetResource().Resource, sel, a.GetNamespace()}
		if got[k] == nil {
			got[k] = map[string]bool{}
		}
		got[k][a.GetVerb()] = true
	}
	want := []key{
		{"validatingadmissionpolicies", "metadata.name=" + guardName, ""},
		{"validatingadmissionpolicies", "metadata.name=" + creatorsName, ""},
		{"validatingadmissionpolicybindings", "metadata.name=" + guardName, ""},
		{"validatingadmissionpolicybindings", "metadata.name=" + creatorsName, ""},
		{"configmaps", "metadata.name=" + creatorsName, testNS},
	}
	for _, k := range want {
		if !got[k]["list"] || !got[k]["watch"] {
			t.Errorf("missing list+watch for %+v (got %v)", k, got[k])
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected requests: %v", got)
	}
}

var _ AdmissionWatcher = (*InformerWatcher)(nil)
var _ Prober = (*DryRunProber)(nil)
