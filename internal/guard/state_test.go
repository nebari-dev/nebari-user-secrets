package guard

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

var cmGR = schema.GroupResource{Resource: "configmaps"}

const (
	verbCreate = "create"
	verbUpdate = "update"
)

func stateCM(fp, vs string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: guardStateName, Namespace: testNS, ResourceVersion: "5"},
		Data:       map[string]string{"fingerprint": fp, "verifiedSince": vs},
	}
}

// withMarker stores a bad-seen marker value.
func withMarker(cm *corev1.ConfigMap, m string) *corev1.ConfigMap {
	cm.Data["badMarker"] = m
	return cm
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func TestConfigMapStateStoreAdvance(t *testing.T) {
	later := server0.Add(time.Hour)
	cases := []struct {
		name      string
		existing  *corev1.ConfigMap
		react     func(cs *fake.Clientset) // extra reactors, prepended
		fp        string
		vs        time.Time
		observed  string // the marker the caller saw before ServerNow
		want      StoredState
		wantErr   bool
		wantWrite string // "create" or "update"
	}{
		{
			name: "absent: created", fp: "fp1", vs: server0,
			want: StoredState{Fingerprint: "fp1", VerifiedSince: server0}, wantWrite: "create",
		},
		{
			name: "earlier stored: moved forward", existing: stateCM("fp0", rfc(server0.Add(-time.Hour))),
			fp: "fp1", vs: server0, want: StoredState{Fingerprint: "fp1", VerifiedSince: server0}, wantWrite: "update",
		},
		{
			name: "later stored: kept (never backwards), fingerprint replaced", existing: stateCM("fp0", rfc(later)),
			fp: "fp1", vs: server0, want: StoredState{Fingerprint: "fp1", VerifiedSince: later}, wantWrite: "update",
		},
		{
			name: "observed marker cleared by the move", existing: withMarker(stateCM("fp0", rfc(server0.Add(-time.Hour))), "m1"),
			fp: "fp0", vs: server0, observed: "m1",
			want: StoredState{Fingerprint: "fp0", VerifiedSince: server0}, wantWrite: "update",
		},
		{
			name: "marker changed since observed: move written, newer marker kept", existing: withMarker(stateCM("fp0", rfc(server0.Add(-time.Hour))), "m2"),
			fp: "fp1", vs: server0, observed: "m1",
			want: StoredState{Fingerprint: "fp1", VerifiedSince: server0, BadMarker: "m2"}, wantWrite: "update",
		},
		{
			name: "marker appeared since observed absent: kept", existing: withMarker(stateCM("fp0", rfc(server0.Add(-time.Hour))), "m2"),
			fp: "fp1", vs: server0, observed: "",
			want: StoredState{Fingerprint: "fp1", VerifiedSince: server0, BadMarker: "m2"}, wantWrite: "update",
		},
		{
			name: "observed marker gone (cleared elsewhere): nothing to clear", existing: stateCM("fp0", rfc(server0.Add(-time.Hour))),
			fp: "fp1", vs: server0, observed: "m1",
			want: StoredState{Fingerprint: "fp1", VerifiedSince: server0}, wantWrite: "update",
		},
		{
			name:     "conflict: another replica marked after observation, re-read keeps its marker",
			existing: withMarker(stateCM("fp0", rfc(server0.Add(-time.Hour))), "m1"),
			react: func(cs *fake.Clientset) {
				first := true
				cs.PrependReactor("update", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
					if !first {
						return false, nil, nil
					}
					first = false
					other := withMarker(stateCM("fp0", rfc(server0.Add(-time.Hour))), "m2")
					other.ResourceVersion = "6"
					if err := cs.Tracker().Update(corev1.SchemeGroupVersion.WithResource("configmaps"), other, testNS); err != nil {
						t.Fatal(err)
					}
					return true, nil, apierrors.NewConflict(cmGR, guardStateName, errors.New("rv"))
				})
			},
			fp: "fp1", vs: server0, observed: "m1",
			want: StoredState{Fingerprint: "fp1", VerifiedSince: server0, BadMarker: "m2"}, wantWrite: "update",
		},
		{
			name: "create races another replica's marking: AlreadyExists, re-read keeps its marker",
			react: func(cs *fake.Clientset) {
				cs.PrependReactor("create", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
					other := &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Name: guardStateName, Namespace: testNS, ResourceVersion: "5"},
						Data:       map[string]string{"badMarker": "m3"},
					}
					if err := cs.Tracker().Add(other); err != nil {
						t.Fatal(err)
					}
					return true, nil, apierrors.NewAlreadyExists(cmGR, guardStateName)
				})
			},
			fp: "fp1", vs: server0,
			want: StoredState{Fingerprint: "fp1", VerifiedSince: server0, BadMarker: "m3"}, wantWrite: "update",
		},
		{
			name: "unparseable stored value: replaced", existing: stateCM("fp0", "yesterday"),
			fp: "fp1", vs: server0, want: StoredState{Fingerprint: "fp1", VerifiedSince: server0}, wantWrite: "update",
		},
		{
			name:     "resourceVersion conflict: re-read and max applied to another replica's later value",
			existing: stateCM("fp0", rfc(server0.Add(-time.Hour))),
			react: func(cs *fake.Clientset) {
				first := true
				cs.PrependReactor("update", "configmaps", func(a k8stesting.Action) (bool, runtime.Object, error) {
					if !first {
						return false, nil, nil
					}
					first = false
					// Another replica wrote a later value in between.
					other := stateCM("fp-other", rfc(later))
					other.ResourceVersion = "6"
					if err := cs.Tracker().Update(corev1.SchemeGroupVersion.WithResource("configmaps"), other, testNS); err != nil {
						t.Fatal(err)
					}
					return true, nil, apierrors.NewConflict(cmGR, guardStateName, errors.New("rv"))
				})
			},
			fp: "fp1", vs: server0, want: StoredState{Fingerprint: "fp1", VerifiedSince: later}, wantWrite: "update",
		},
		{
			name: "create races another replica: AlreadyExists, then update with max",
			react: func(cs *fake.Clientset) {
				cs.PrependReactor("create", "configmaps", func(a k8stesting.Action) (bool, runtime.Object, error) {
					other := stateCM("fp-other", rfc(later))
					if err := cs.Tracker().Add(other); err != nil {
						t.Fatal(err)
					}
					return true, nil, apierrors.NewAlreadyExists(cmGR, guardStateName)
				})
			},
			fp: "fp1", vs: server0, want: StoredState{Fingerprint: "fp1", VerifiedSince: later}, wantWrite: "update",
		},
		{
			name:     "persistent conflict: error",
			existing: stateCM("fp0", rfc(server0)),
			react: func(cs *fake.Clientset) {
				cs.PrependReactor("update", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewConflict(cmGR, guardStateName, errors.New("rv"))
				})
			},
			fp: "fp1", vs: server0, wantErr: true,
		},
		{
			name: "get fails: error",
			react: func(cs *fake.Clientset) {
				cs.PrependReactor("get", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewForbidden(cmGR, guardStateName, errors.New("no"))
				})
			},
			fp: "fp1", vs: server0, wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var objs []runtime.Object
			if c.existing != nil {
				objs = append(objs, c.existing)
			}
			cs := fake.NewClientset(objs...)
			if c.react != nil {
				c.react(cs)
			}
			s := NewConfigMapStateStore(cs, testNS)
			got, err := s.Advance(context.Background(), c.fp, c.vs, c.observed)
			if c.wantErr {
				if err == nil {
					t.Fatalf("Advance = %+v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Fingerprint != c.want.Fingerprint || !got.VerifiedSince.Equal(c.want.VerifiedSince) {
				t.Errorf("Advance = %+v, want %+v", got, c.want)
			}
			cm, err := cs.CoreV1().ConfigMaps(testNS).Get(context.Background(), guardStateName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if cm.Data["badMarker"] != c.want.BadMarker {
				t.Errorf("stored marker = %q, want %q", cm.Data["badMarker"], c.want.BadMarker)
			}
			if got.BadMarker != c.want.BadMarker {
				t.Errorf("Advance returned marker %q, want %q", got.BadMarker, c.want.BadMarker)
			}
			if cm.Data["fingerprint"] != c.want.Fingerprint || cm.Data["verifiedSince"] != rfc(c.want.VerifiedSince) {
				t.Errorf("stored data = %v, want %+v", cm.Data, c.want)
			}
			// Every update carries the resourceVersion it read.
			var sawWrite bool
			for _, a := range cs.Actions() {
				switch a.GetVerb() {
				case verbUpdate:
					sawWrite = sawWrite || c.wantWrite == "update"
					if o := a.(k8stesting.UpdateAction).GetObject().(*corev1.ConfigMap); o.ResourceVersion == "" {
						t.Errorf("update without resourceVersion")
					}
				case verbCreate:
					sawWrite = sawWrite || c.wantWrite == "create"
				}
			}
			if !sawWrite {
				t.Errorf("no %s action in %v", c.wantWrite, cs.Actions())
			}
		})
	}
}

func TestConfigMapStateStoreMarkBad(t *testing.T) {
	cases := []struct {
		name      string
		existing  *corev1.ConfigMap
		react     func(cs *fake.Clientset)
		wantData  map[string]string // badMarker is checked separately
		wantErr   bool
		wantWrite string // "create" or "update"
	}{
		{
			name:     "absent: created with only a marker",
			wantData: map[string]string{}, wantWrite: "create",
		},
		{
			name: "present: marker added, fingerprint and verifiedSince kept", existing: stateCM("fp", rfc(server0)),
			wantData:  map[string]string{"fingerprint": "fp", "verifiedSince": rfc(server0)},
			wantWrite: "update",
		},
		{
			name: "already marked: replaced by a fresh marker", existing: withMarker(stateCM("fp", rfc(server0)), "old"),
			wantData:  map[string]string{"fingerprint": "fp", "verifiedSince": rfc(server0)},
			wantWrite: "update",
		},
		{
			name: "conflict: re-read keeps another replica's later verifiedSince", existing: stateCM("fp", rfc(server0)),
			react: func(cs *fake.Clientset) {
				first := true
				cs.PrependReactor("update", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
					if !first {
						return false, nil, nil
					}
					first = false
					other := withMarker(stateCM("fp2", rfc(server0.Add(time.Hour))), "old")
					other.ResourceVersion = "6"
					if err := cs.Tracker().Update(corev1.SchemeGroupVersion.WithResource("configmaps"), other, testNS); err != nil {
						t.Fatal(err)
					}
					return true, nil, apierrors.NewConflict(cmGR, guardStateName, errors.New("rv"))
				})
			},
			wantData:  map[string]string{"fingerprint": "fp2", "verifiedSince": rfc(server0.Add(time.Hour))},
			wantWrite: "update",
		},
		{
			name: "persistent conflict: error", existing: stateCM("fp", rfc(server0)),
			react: func(cs *fake.Clientset) {
				cs.PrependReactor("update", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewConflict(cmGR, guardStateName, errors.New("rv"))
				})
			},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var objs []runtime.Object
			if c.existing != nil {
				objs = append(objs, c.existing)
			}
			cs := fake.NewClientset(objs...)
			if c.react != nil {
				c.react(cs)
			}
			s := NewConfigMapStateStore(cs, testNS)
			err := s.MarkBad(context.Background())
			if c.wantErr {
				if err == nil {
					t.Fatal("MarkBad succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cm, err := cs.CoreV1().ConfigMaps(testNS).Get(context.Background(), guardStateName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			first := cm.Data["badMarker"]
			if first == "" || first == "old" {
				t.Errorf("marker = %q, want a fresh value", first)
			}
			if len(cm.Data) != len(c.wantData)+1 {
				t.Errorf("data = %v, want %v plus the marker", cm.Data, c.wantData)
			}
			for k, v := range c.wantData {
				if cm.Data[k] != v {
					t.Errorf("data[%s] = %q, want %q", k, cm.Data[k], v)
				}
			}
			var writes []string
			for _, a := range cs.Actions() {
				switch a.GetVerb() {
				case verbUpdate:
					writes = append(writes, verbUpdate)
					if o := a.(k8stesting.UpdateAction).GetObject().(*corev1.ConfigMap); o.ResourceVersion == "" {
						t.Errorf("update without resourceVersion")
					}
				case verbCreate:
					writes = append(writes, verbCreate)
				}
			}
			if len(writes) == 0 || writes[len(writes)-1] != c.wantWrite {
				t.Errorf("writes %v, want a final %s", writes, c.wantWrite)
			}
			// Each marking is distinguishable from the last.
			if err := s.MarkBad(context.Background()); err != nil {
				t.Fatal(err)
			}
			cm, err = cs.CoreV1().ConfigMaps(testNS).Get(context.Background(), guardStateName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if second := cm.Data["badMarker"]; second == "" || second == first {
				t.Errorf("second marking %q, first %q: want a different value", second, first)
			}
		})
	}
}

func TestConfigMapStateStoreServerNow(t *testing.T) {
	cases := []struct {
		name    string
		react   k8stesting.ReactionFunc
		want    time.Time
		wantErr bool
	}{
		{
			name: "creationTimestamp of the dry-run create",
			react: func(a k8stesting.Action) (bool, runtime.Object, error) {
				o := a.(k8stesting.CreateAction).GetObject().(*corev1.ConfigMap).DeepCopy()
				o.Name = o.GenerateName + "abcde"
				o.CreationTimestamp = metav1.NewTime(server0)
				return true, o, nil
			},
			want: server0,
		},
		{
			name: "no creationTimestamp: error, no local fallback",
			react: func(a k8stesting.Action) (bool, runtime.Object, error) {
				return true, a.(k8stesting.CreateAction).GetObject(), nil
			},
			wantErr: true,
		},
		{
			name: "create refused: error",
			react: func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, apierrors.NewForbidden(cmGR, "", errors.New("no"))
			},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cs := fake.NewClientset()
			cs.PrependReactor("create", "configmaps", c.react)
			got, err := NewConfigMapStateStore(cs, testNS).ServerNow(context.Background())
			if c.wantErr != (err != nil) {
				t.Fatalf("ServerNow = %v, %v; wantErr %v", got, err, c.wantErr)
			}
			if !got.Equal(c.want) {
				t.Errorf("ServerNow = %v, want %v", got, c.want)
			}
			acts := cs.Actions()
			if len(acts) != 1 {
				t.Fatalf("actions = %v, want one create", acts)
			}
			ca := acts[0].(k8stesting.CreateActionImpl)
			if len(ca.CreateOptions.DryRun) != 1 || ca.CreateOptions.DryRun[0] != metav1.DryRunAll {
				t.Errorf("dryRun = %v", ca.CreateOptions.DryRun)
			}
			o := ca.GetObject().(*corev1.ConfigMap)
			if o.Name != "" || o.GenerateName == "" || ca.GetNamespace() != testNS {
				t.Errorf("dry-run object name %q generateName %q ns %q", o.Name, o.GenerateName, ca.GetNamespace())
			}
		})
	}
}

func TestConfigMapStateStoreWatch(t *testing.T) {
	cases := []struct {
		name     string
		existing *corev1.ConfigMap
		update   *corev1.ConfigMap // applied after sync, as another replica would
		want     StoredState
		wantOK   bool
	}{
		{name: "absent", wantOK: false},
		{
			name: "present", existing: stateCM("fp", rfc(server0)),
			want: StoredState{Fingerprint: "fp", VerifiedSince: server0}, wantOK: true,
		},
		{
			name: "another replica's write is observed", existing: stateCM("fp", rfc(server0)),
			update: stateCM("fp2", rfc(server0.Add(time.Hour))),
			want:   StoredState{Fingerprint: "fp2", VerifiedSince: server0.Add(time.Hour)}, wantOK: true,
		},
		{
			name: "bad-seen marker parsed", existing: withMarker(stateCM("fp", rfc(server0)), "m1"),
			want: StoredState{Fingerprint: "fp", VerifiedSince: server0, BadMarker: "m1"}, wantOK: true,
		},
		{
			name: "unparseable verifiedSince: zero time", existing: stateCM("fp", "nonsense"),
			want: StoredState{Fingerprint: "fp"}, wantOK: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var objs []runtime.Object
			if c.existing != nil {
				objs = append(objs, c.existing)
			}
			cs := fake.NewClientset(objs...)
			s := NewConfigMapStateStore(cs, testNS)
			if s.Synced() {
				t.Fatal("synced before Start")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.Start(ctx)
			waitFor(t, "sync", s.Synced)
			if c.update != nil {
				if _, err := cs.CoreV1().ConfigMaps(testNS).Update(ctx, c.update, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			waitFor(t, "stored state", func() bool {
				got, ok := s.Stored()
				return ok == c.wantOK && got.Fingerprint == c.want.Fingerprint &&
					got.VerifiedSince.Equal(c.want.VerifiedSince) && got.BadMarker == c.want.BadMarker
			})
		})
	}
}

var (
	_ StateStore = (*ConfigMapStateStore)(nil)
	_ StateStore = (*fakeStore)(nil)
)
