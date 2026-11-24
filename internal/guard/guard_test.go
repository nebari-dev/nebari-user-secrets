package guard

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

// t0 is the fake local clock's start. The fake API server's clock is
// deliberately different, so a test fails if the guard uses the local clock
// for verifiedSince.
var (
	t0       = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	server0  = time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	enforced = model.GuardMode("enforced")
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fakeWatcher struct {
	mu      sync.Mutex
	synced  bool
	p       Policies
	b       Bindings
	cm      *corev1.ConfigMap
	changed chan struct{}
	// onCreators, when set, runs after each Creators() read, outside w.mu.
	onCreators func()
}

func (w *fakeWatcher) Policies() (g, c *admissionregistrationv1.ValidatingAdmissionPolicy, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.p.Guard == nil || w.p.Creators == nil {
		return nil, nil, false
	}
	return w.p.Guard.DeepCopy(), w.p.Creators.DeepCopy(), true
}

func (w *fakeWatcher) Bindings() (g, c *admissionregistrationv1.ValidatingAdmissionPolicyBinding, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.b.Guard == nil || w.b.Creators == nil {
		return nil, nil, false
	}
	return w.b.Guard.DeepCopy(), w.b.Creators.DeepCopy(), true
}

func (w *fakeWatcher) Creators() (*corev1.ConfigMap, bool) {
	w.mu.Lock()
	hook := w.onCreators
	var cm *corev1.ConfigMap
	if w.cm != nil {
		cm = w.cm.DeepCopy()
	}
	w.mu.Unlock()
	if hook != nil {
		hook()
	}
	return cm, cm != nil
}

func (w *fakeWatcher) Synced() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.synced }

func (w *fakeWatcher) Changed() <-chan struct{} { return w.changed }

type fakeProber struct {
	mu    sync.Mutex
	res   ProbeResult
	err   error
	calls int
	hook  func()
}

func (p *fakeProber) Probe(context.Context) (ProbeResult, error) {
	p.mu.Lock()
	p.calls++
	res, err, hook := p.res, p.err, p.hook
	p.mu.Unlock()
	if hook != nil {
		hook()
	}
	return res, err
}

var (
	pAsDesigned = ProbeOutcome{Outcome: OutcomeDeniedAsExpected}
	pAdmitted   = ProbeOutcome{Outcome: OutcomeAdmitted}
	pDenied     = ProbeOutcome{Outcome: OutcomeDenied}

	probesPass         = ProbeResult{Labelled: pAsDesigned, Unlabelled: pAsDesigned, Canary: pAdmitted}
	labelledAdmitted   = ProbeResult{Labelled: pAdmitted, Unlabelled: pAsDesigned, Canary: pAdmitted}
	unlabelledAdmitted = ProbeResult{Labelled: pAsDesigned, Unlabelled: pAdmitted, Canary: pAdmitted}
	canaryDenied       = ProbeResult{Labelled: pAsDesigned, Unlabelled: pAsDesigned, Canary: pDenied}
	bothAdmitted       = ProbeResult{Labelled: pAdmitted, Unlabelled: pAdmitted, Canary: pAdmitted}
)

func pInc(class string) ProbeOutcome {
	return ProbeOutcome{Outcome: OutcomeInconclusive, Detail: class}
}

// fakeStore stands in for the guard-state ConfigMap. serverNow is the fake API
// server's clock: it plays the creationTimestamp of the dry-run create that
// ConfigMapStateStore.ServerNow makes.
type fakeStore struct {
	mu        sync.Mutex
	synced    bool
	stored    *StoredState
	serverNow time.Time
	nowErr    error
	advErr    error
	advances  int
	markErr   error
	marks     int
	// onServerNow, when set, runs in ServerNow outside s.mu: another replica
	// acting between this replica's observation and its write.
	onServerNow func()
	// onMark, when set, runs at the start of MarkBad.
	onMark func()
}

func (s *fakeStore) Synced() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.synced }

func (s *fakeStore) Stored() (StoredState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stored == nil {
		return StoredState{}, false
	}
	return *s.stored, true
}

func (s *fakeStore) ServerNow(context.Context) (time.Time, error) {
	s.mu.Lock()
	hook := s.onServerNow
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serverNow, s.nowErr
}

func (s *fakeStore) Advance(_ context.Context, fp string, vs time.Time, observed string) (StoredState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.advErr != nil {
		return StoredState{}, s.advErr
	}
	s.advances++
	next := StoredState{Fingerprint: fp, VerifiedSince: vs}
	if s.stored != nil {
		if s.stored.VerifiedSince.After(vs) {
			next.VerifiedSince = s.stored.VerifiedSince
		}
		if s.stored.BadMarker != observed { // a newer marking is kept
			next.BadMarker = s.stored.BadMarker
		}
	}
	s.stored = &next
	return next, nil
}

func (s *fakeStore) MarkBad(context.Context) error {
	s.mu.Lock()
	hook := s.onMark
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.markErr != nil {
		return s.markErr
	}
	s.marks++
	if s.stored == nil {
		s.stored = &StoredState{}
	}
	s.stored.BadMarker = fmt.Sprintf("m%d", s.marks)
	return nil
}

// mark plays another replica's MarkBad.
func (s *fakeStore) mark(m string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stored == nil {
		s.stored = &StoredState{}
	}
	s.stored.BadMarker = m
}

func (s *fakeStore) set(st *StoredState) { s.mu.Lock(); defer s.mu.Unlock(); s.stored = st }

type guardLine struct{ state, mode, reason string }

type fakeAudit struct {
	mu     sync.Mutex
	lines  []guardLine
	notify chan guardLine // optional; receives every line
}

func (a *fakeAudit) SecretRead(context.Context, string, string, string, model.PodClaim, model.GuardMode) {
}
func (a *fakeAudit) ResolveDenied(context.Context, model.PodIdentity, string)    {}
func (a *fakeAudit) SecretWrite(context.Context, string, string, string, string) {}
func (a *fakeAudit) KeyEvent(context.Context, string, string, string, string)    {}
func (a *fakeAudit) GuardChanged(_ context.Context, state, mode, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lines = append(a.lines, guardLine{state, mode, reason})
	if a.notify != nil {
		a.notify <- guardLine{state, mode, reason}
	}
}

func (a *fakeAudit) all() []guardLine {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]guardLine(nil), a.lines...)
}

type env struct {
	w     *fakeWatcher
	p     *fakeProber
	s     *fakeStore
	a     *fakeAudit
	clock *fakeClock
	exp   Expectation
	mode  model.GuardMode
	g     *Guard
}

// restart replaces the guard with a fresh one over the same watcher, prober,
// store, audit sink and clock: a replica restart, or another replica.
func (e *env) restart() {
	e.g = NewGuard(e.w, e.p, e.exp, wantCM, e.s, e.a, e.mode, 2*time.Minute, e.clock.now)
}

// newEnv builds a guard over a matching, synced bundle with passing probes and
// an empty, synced guard-state store. Every guard object carries a uid and a
// generation (the ConfigMap a resourceVersion) for the fingerprint.
func newEnv(t *testing.T, mode model.GuardMode) *env {
	t.Helper()
	p, b := live(t)
	p.Guard.UID, p.Guard.Generation = "uid-pa", 1
	p.Creators.UID, p.Creators.Generation = "uid-pb", 1
	b.Guard.UID, b.Guard.Generation = "uid-ba", 1
	b.Creators.UID, b.Creators.Generation = "uid-bb", 1
	cm := creatorsCM()
	cm.UID, cm.ResourceVersion = "uid-cm", "100"
	e := &env{
		w:     &fakeWatcher{synced: true, p: p, b: b, cm: cm, changed: make(chan struct{}, 1)},
		p:     &fakeProber{res: probesPass},
		s:     &fakeStore{synced: true, serverNow: server0},
		a:     &fakeAudit{},
		clock: &fakeClock{t: t0},
	}
	exp, err := NewExpectation(testNS)
	if err != nil {
		t.Fatal(err)
	}
	e.exp, e.mode = exp, mode
	e.restart()
	return e
}

// mutations, shared by the table.
func (e *env) watch(f func(w *fakeWatcher)) { e.w.mu.Lock(); defer e.w.mu.Unlock(); f(e.w) }
func (e *env) probe(r ProbeResult, err error) {
	e.p.mu.Lock()
	defer e.p.mu.Unlock()
	e.p.res, e.p.err = r, err
}
func (e *env) serverAt(d time.Duration) {
	e.s.mu.Lock()
	defer e.s.mu.Unlock()
	e.s.serverNow = server0.Add(d)
}

type step struct {
	name string
	do   func(e *env)
	wait time.Duration // advance the local clock before the step
	eval bool          // run Evaluate (else only read Allows/State/VerifiedSince)

	wantState      string
	wantReason     string // substring; "" skips
	wantAllows     bool
	wantVerified   *time.Time // nil skips
	wantAudits     int        // total GuardChanged calls so far
	wantAdvances   int        // total store writes so far; -1 skips
	wantProbeCalls int        // -1 skips
	wantBadSeen    *bool      // the stored bad-seen marker; nil skips
	wantMarks      *int       // total MarkBad writes so far; nil skips
}

func boolp(b bool) *bool { return &b }
func intp(i int) *int    { return &i }

func at(d time.Duration) *time.Time { t := server0.Add(d); return &t }

// verifiedStart is the first step of most rows: a fresh guard verifies and,
// with nothing stored, stores the fingerprint and server0 + 30 s.
var verifiedStart = step{
	name: "start", eval: true, wantState: "verified", wantAllows: true,
	wantVerified: at(30 * time.Second), wantAudits: 1, wantAdvances: 1, wantProbeCalls: -1,
}

func TestGuard(t *testing.T) {
	warnAudit := []admissionregistrationv1.ValidationAction{admissionregistrationv1.Warn, admissionregistrationv1.Audit}
	badCauses := []struct {
		name   string
		do     func(e *env)
		reason string
	}{
		{"binding A removed", func(e *env) { e.watch(func(w *fakeWatcher) { w.b.Guard = nil }) }, "missing"},
		{"binding B removed", func(e *env) { e.watch(func(w *fakeWatcher) { w.b.Creators = nil }) }, "missing"},
		{"binding A at Warn, Audit", func(e *env) {
			e.watch(func(w *fakeWatcher) { w.b.Guard.Spec.ValidationActions = warnAudit; w.b.Guard.Generation++ })
		}, "binding user-secrets-pod-guard"},
		{"binding B at Warn, Audit", func(e *env) {
			e.watch(func(w *fakeWatcher) { w.b.Creators.Spec.ValidationActions = warnAudit; w.b.Creators.Generation++ })
		}, "binding user-secrets-creators"},
		{"binding B narrowed", func(e *env) {
			e.watch(func(w *fakeWatcher) {
				w.b.Creators.Spec.MatchResources.ObjectSelector.MatchLabels["nebari.dev/user-secrets"] = "false"
			})
		}, "binding user-secrets-creators: matchResources differs"},
		{"binding B paramRef changed", func(e *env) {
			e.watch(func(w *fakeWatcher) { w.b.Creators.Spec.ParamRef.Name = "renamed" })
		}, "binding user-secrets-creators: paramRef differs"},
		{"paramRef added to binding A", func(e *env) {
			e.watch(func(w *fakeWatcher) {
				w.b.Guard.Spec.ParamRef = &admissionregistrationv1.ParamRef{Name: "x"}
			})
		}, "binding user-secrets-pod-guard: paramRef set"},
		{"policy edited", func(e *env) {
			e.watch(func(w *fakeWatcher) { w.p.Guard.Spec.Validations[0].Expression = "1 == 1" })
		}, "policy user-secrets-pod-guard: spec differs"},
		{"ConfigMap drifted", func(e *env) {
			e.watch(func(w *fakeWatcher) { w.cm.Data["jhub.hub"] = "namespaces=evil;apps=notebook" })
		}, "configmap user-secrets-creators: data differs at keys: jhub.hub"},
		{"ConfigMap missing", func(e *env) { e.watch(func(w *fakeWatcher) { w.cm = nil }) }, "configmap user-secrets-creators: missing"},
		{"labelled probe admitted", func(e *env) {
			e.probe(labelledAdmitted, nil)
		}, "labelled probe admitted"},
		{"unlabelled probe admitted", func(e *env) {
			e.probe(unlabelledAdmitted, nil)
		}, "unlabelled probe admitted"},
		{"canary denied", func(e *env) {
			e.probe(canaryDenied, nil)
		}, "canary probe denied"},
	}

	type row struct {
		name  string
		mode  model.GuardMode
		setup func(e *env)
		steps []step
	}
	rows := make([]row, 0, len(badCauses)+32)
	for _, c := range badCauses {
		rows = append(rows, row{
			name: "confirmed bad: " + c.name,
			steps: []step{verifiedStart, {
				name: "cause", do: c.do, eval: true, wantState: "confirmed_bad", wantReason: c.reason,
				wantAllows: false, wantVerified: at(30 * time.Second), wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1,
			}, {
				name: "denies at once, even 1 s later", wait: time.Second, wantState: "confirmed_bad",
				wantAllows: false, wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1,
			}},
		})
	}
	inconclusivePS := ProbeResult{Labelled: pInc("pod_security"), Unlabelled: pAsDesigned, Canary: pAdmitted}
	apiDown := ProbeResult{Labelled: pInc("transport"), Unlabelled: pInc("transport"), Canary: pInc("transport")}
	canaryUnreachable := ProbeResult{Labelled: pAsDesigned, Unlabelled: pAsDesigned, Canary: pInc("transport")}
	unlabelledUnreachable := ProbeResult{Labelled: pAsDesigned, Unlabelled: pInc("transport"), Canary: pAdmitted}

	rows = append(rows,
		row{
			name: "API unreachable: allowed for 119 s, denied at 120 s",
			steps: []step{verifiedStart,
				{name: "probe unreachable", do: func(e *env) { e.probe(apiDown, nil) }, eval: true,
					wantState: "unknown", wantReason: "probe inconclusive: labelled probe: transport",
					wantAllows: true, wantAudits: 2, wantAdvances: 1, wantProbeCalls: 2},
				{name: "119 s", wait: 119 * time.Second, wantState: "unknown", wantAllows: true, wantAudits: 2, wantAdvances: 1, wantProbeCalls: 2},
				{name: "re-evaluated, still unknown, grace not reset", eval: true, wantState: "unknown", wantAllows: true,
					wantAudits: 2, wantAdvances: 1, wantProbeCalls: 3},
				{name: "120 s", wait: time.Second, wantState: "unknown", wantAllows: false, wantAudits: 2, wantAdvances: 1, wantProbeCalls: 3},
			},
		},
		row{
			name: "watch not synced after verified: grace applies",
			steps: []step{verifiedStart,
				{name: "unsynced", do: func(e *env) { e.watch(func(w *fakeWatcher) { w.synced = false }) }, eval: true,
					wantState: "unknown", wantReason: "watch not synced", wantAllows: true, wantAudits: 2, wantAdvances: 1, wantProbeCalls: 1},
				{name: "120 s", wait: 120 * time.Second, wantState: "unknown", wantAllows: false, wantAudits: 2, wantAdvances: 1, wantProbeCalls: 1},
			},
		},
		row{
			name: "probe error: unknown",
			steps: []step{verifiedStart,
				{name: "probe error", do: func(e *env) { e.probe(ProbeResult{}, context.Canceled) }, eval: true,
					wantState: "unknown", wantReason: "probe", wantAllows: true, wantAudits: 2, wantAdvances: 1, wantProbeCalls: 2},
			},
		},
		row{
			name: "Pod Security denied probe: unknown, not confirmed bad",
			steps: []step{verifiedStart,
				{name: "pod security", do: func(e *env) { e.probe(inconclusivePS, nil) }, eval: true,
					wantState: "unknown", wantReason: "probe inconclusive: labelled probe: pod_security", wantAllows: true,
					wantAudits: 2, wantAdvances: 1, wantProbeCalls: 2},
				{name: "120 s", wait: 120 * time.Second, wantState: "unknown", wantAllows: false, wantAudits: 2, wantAdvances: 1, wantProbeCalls: 2},
			},
		},
		row{
			name:  "unknown at startup denies at once",
			setup: func(e *env) { e.watch(func(w *fakeWatcher) { w.synced = false }) },
			steps: []step{
				{name: "before any evaluation", wantState: "unknown", wantAllows: false, wantAudits: 0, wantAdvances: 0, wantProbeCalls: 0},
				{name: "unsynced", eval: true, wantState: "unknown", wantReason: "watch not synced", wantAllows: false,
					wantAudits: 1, wantAdvances: 0, wantProbeCalls: 0},
			},
		},
		row{
			name:  "guard-state store not synced: unknown",
			setup: func(e *env) { e.s.synced = false },
			steps: []step{
				{name: "unsynced store", eval: true, wantState: "unknown", wantReason: "guard state not synced", wantAllows: false,
					wantAudits: 1, wantAdvances: 0, wantProbeCalls: 0},
			},
		},
		row{
			name:  "unknown at startup from a probe denies at once",
			setup: func(e *env) { e.probe(inconclusivePS, nil) },
			steps: []step{
				{name: "inconclusive", eval: true, wantState: "unknown", wantAllows: false, wantAudits: 1, wantAdvances: 0, wantProbeCalls: 1},
			},
		},
		row{
			name: "unknown after confirmed bad denies at once",
			steps: []step{verifiedStart,
				{name: "bad", do: func(e *env) { e.probe(bothAdmitted, nil) }, eval: true,
					wantState: "confirmed_bad", wantAllows: false, wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1},
				{name: "inconclusive", do: func(e *env) { e.probe(inconclusivePS, nil) }, eval: true,
					wantState: "unknown", wantAllows: false, wantAudits: 3, wantAdvances: 1, wantProbeCalls: -1},
			},
		},
		row{
			name: "recovery after confirmed bad moves verifiedSince to server write time + 30 s",
			steps: []step{verifiedStart,
				{name: "labelled admitted", do: func(e *env) { e.probe(labelledAdmitted, nil) },
					eval: true, wantState: "confirmed_bad", wantAllows: false, wantVerified: at(30 * time.Second),
					wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1},
				{name: "fixed", do: func(e *env) { e.probe(probesPass, nil); e.serverAt(10 * time.Minute) }, wait: time.Minute,
					eval: true, wantState: "verified", wantReason: "", wantAllows: true, wantVerified: at(10*time.Minute + 30*time.Second),
					wantAudits: 3, wantAdvances: 2, wantProbeCalls: -1},
				{name: "steady: no further move", do: func(e *env) { e.serverAt(20 * time.Minute) }, eval: true,
					wantState: "verified", wantAllows: true, wantVerified: at(10*time.Minute + 30*time.Second),
					wantAudits: 3, wantAdvances: 2, wantProbeCalls: -1},
			},
		},
		row{
			name: "recovery via unknown after confirmed bad still moves verifiedSince",
			steps: []step{verifiedStart,
				{name: "bad", do: func(e *env) { e.probe(canaryDenied, nil) },
					eval: true, wantState: "confirmed_bad", wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1},
				{name: "inconclusive", do: func(e *env) { e.probe(inconclusivePS, nil) }, eval: true,
					wantState: "unknown", wantAudits: 3, wantAdvances: 1, wantProbeCalls: -1},
				{name: "fixed", do: func(e *env) { e.probe(probesPass, nil); e.serverAt(5 * time.Minute) }, eval: true,
					wantState: "verified", wantAllows: true, wantVerified: at(5*time.Minute + 30*time.Second),
					wantAudits: 4, wantAdvances: 2, wantProbeCalls: -1},
			},
		},
		row{
			name: "binding generation +2 ([Warn] and back) moves verifiedSince only once probes pass",
			steps: []step{verifiedStart,
				{name: "generation +2, probe inconclusive", do: func(e *env) {
					e.watch(func(w *fakeWatcher) { w.b.Creators.Generation += 2 })
					e.probe(inconclusivePS, nil)
					e.serverAt(3 * time.Minute)
				}, eval: true, wantState: "unknown", wantAllows: false, wantVerified: at(30 * time.Second),
					wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1},
				{name: "probes pass", do: func(e *env) { e.probe(probesPass, nil); e.serverAt(4 * time.Minute) }, eval: true,
					wantState: "verified", wantAllows: true, wantVerified: at(4*time.Minute + 30*time.Second),
					wantAudits: 3, wantAdvances: 2, wantProbeCalls: -1},
			},
		},
		row{
			name: "ConfigMap resourceVersion change moves verifiedSince once probes pass",
			steps: []step{verifiedStart,
				{name: "rv changed, canary denied", do: func(e *env) {
					e.watch(func(w *fakeWatcher) { w.cm.ResourceVersion = "101" })
					e.probe(canaryDenied, nil)
					e.serverAt(2 * time.Minute)
				}, eval: true, wantState: "confirmed_bad", wantAllows: false, wantVerified: at(30 * time.Second),
					wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1},
				{name: "probes pass", do: func(e *env) { e.probe(probesPass, nil); e.serverAt(3 * time.Minute) }, eval: true,
					wantState: "verified", wantAllows: true, wantVerified: at(3*time.Minute + 30*time.Second),
					wantAudits: 3, wantAdvances: 2, wantProbeCalls: -1},
			},
		},
		row{
			name: "policy uid change (delete and re-create) moves verifiedSince",
			steps: []step{verifiedStart,
				{name: "uid changed", do: func(e *env) {
					e.watch(func(w *fakeWatcher) { w.p.Guard.UID = types.UID("uid-pa-2") })
					e.serverAt(time.Hour)
				}, eval: true, wantState: "verified", wantAllows: true, wantVerified: at(time.Hour + 30*time.Second),
					wantAudits: 1, wantAdvances: 2, wantProbeCalls: -1},
			},
		},
		row{
			name: "fingerprint change: unknown denies at once, grace does not cover a stale verifiedSince",
			steps: []step{verifiedStart,
				{name: "binding A generation +2, probe inconclusive", do: func(e *env) {
					e.watch(func(w *fakeWatcher) { w.b.Guard.Generation += 2 })
					e.probe(apiDown, nil)
				}, eval: true, wantState: "unknown", wantAllows: false, wantVerified: at(30 * time.Second),
					wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1},
			},
		},
		row{
			name: "fingerprint change: store write fails -> unknown, denied, nothing moved",
			steps: []step{verifiedStart,
				{name: "cm rv changed, store down", do: func(e *env) {
					e.watch(func(w *fakeWatcher) { w.cm.ResourceVersion = "102" })
					e.s.mu.Lock()
					e.s.advErr = errors.New("conflict")
					e.s.mu.Unlock()
				}, eval: true, wantState: "unknown", wantReason: "guard state write failed", wantAllows: false,
					wantVerified: at(30 * time.Second), wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1},
			},
		},
		row{
			name:  "server time unavailable: unknown, never the local clock",
			setup: func(e *env) { e.s.nowErr = errors.New("forbidden") },
			steps: []step{
				{name: "start", eval: true, wantState: "unknown", wantReason: "server time unavailable", wantAllows: false,
					wantVerified: &time.Time{}, wantAudits: 1, wantAdvances: 0, wantProbeCalls: 1},
			},
		},
		row{
			name: "startup with matching stored fingerprint keeps the stored verifiedSince",
			setup: func(e *env) {
				e.s.stored = &StoredState{Fingerprint: e.g.fingerprintNow(t), VerifiedSince: server0.Add(-time.Hour)}
			},
			steps: []step{
				{name: "start", eval: true, wantState: "verified", wantAllows: true, wantVerified: at(-time.Hour),
					wantAudits: 1, wantAdvances: 0, wantProbeCalls: 1},
			},
		},
		row{
			name: "startup with a different stored fingerprint moves verifiedSince",
			setup: func(e *env) {
				e.s.stored = &StoredState{Fingerprint: "stale", VerifiedSince: server0.Add(-time.Hour)}
			},
			steps: []step{
				{name: "start", eval: true, wantState: "verified", wantAllows: true, wantVerified: at(30 * time.Second),
					wantAudits: 1, wantAdvances: 1, wantProbeCalls: 1},
			},
		},
		row{
			name: "never backwards: a server time earlier than the stored value keeps the stored value",
			setup: func(e *env) {
				e.s.stored = &StoredState{Fingerprint: "stale", VerifiedSince: server0.Add(time.Hour)}
			},
			steps: []step{
				{name: "start", eval: true, wantState: "verified", wantAllows: true, wantVerified: at(time.Hour),
					wantAudits: 1, wantAdvances: 1, wantProbeCalls: 1},
			},
		},
		row{
			name: "another replica's later stored value is adopted without an evaluation; an earlier one is ignored",
			steps: []step{verifiedStart,
				{name: "later stored", do: func(e *env) {
					e.s.set(&StoredState{Fingerprint: "other", VerifiedSince: server0.Add(time.Hour)})
				}, wantState: "verified", wantAllows: true, wantVerified: at(time.Hour), wantAudits: 1, wantAdvances: 1, wantProbeCalls: 1},
				{name: "earlier stored", do: func(e *env) {
					e.s.set(&StoredState{Fingerprint: "other", VerifiedSince: server0})
				}, wantState: "verified", wantAllows: true, wantVerified: at(time.Hour), wantAudits: 1, wantAdvances: 1, wantProbeCalls: 1},
				{name: "stored value gone", do: func(e *env) { e.s.set(nil) },
					wantState: "verified", wantAllows: true, wantVerified: at(time.Hour), wantAudits: 1, wantAdvances: 1, wantProbeCalls: 1},
			},
		},
		row{
			name: "labelled admitted while the canary is inconclusive is confirmed bad; recovery needs every probe",
			steps: []step{verifiedStart,
				{name: "labelled admitted, canary unreachable", do: func(e *env) {
					e.probe(ProbeResult{Labelled: pAdmitted, Unlabelled: pAsDesigned, Canary: pInc("transport")}, nil)
				}, eval: true, wantState: "confirmed_bad", wantReason: "labelled probe admitted", wantAllows: false,
					wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1},
				{name: "flaw cleared, unlabelled still inconclusive", do: func(e *env) {
					e.probe(unlabelledUnreachable, nil)
					e.serverAt(time.Minute)
				}, eval: true, wantState: "unknown", wantReason: "unlabelled probe: transport", wantAllows: false,
					wantVerified: at(30 * time.Second), wantAudits: 3, wantAdvances: 1, wantProbeCalls: -1},
				{name: "all probes pass", do: func(e *env) { e.probe(probesPass, nil); e.serverAt(2 * time.Minute) }, eval: true,
					wantState: "verified", wantAllows: true, wantVerified: at(2*time.Minute + 30*time.Second),
					wantAudits: 4, wantAdvances: 2, wantProbeCalls: -1},
			},
		},
		row{
			name: "unlabelled admitted while the labelled probe is inconclusive is confirmed bad",
			steps: []step{verifiedStart,
				{name: "unlabelled admitted", do: func(e *env) {
					e.probe(ProbeResult{Labelled: pInc("pod_security"), Unlabelled: pAdmitted, Canary: pAdmitted}, nil)
				}, eval: true, wantState: "confirmed_bad", wantReason: "unlabelled probe admitted", wantAllows: false,
					wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1},
			},
		},
		row{
			name: "canary denied while a guarded probe is inconclusive is confirmed bad",
			steps: []step{verifiedStart,
				{name: "canary denied", do: func(e *env) {
					e.probe(ProbeResult{Labelled: pInc("timeout"), Unlabelled: pAsDesigned, Canary: pDenied}, nil)
				}, eval: true, wantState: "confirmed_bad", wantReason: "canary probe denied", wantAllows: false,
					wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1},
			},
		},
		row{
			name: "canary inconclusive alone is unknown with grace",
			steps: []step{verifiedStart,
				{name: "canary unreachable", do: func(e *env) { e.probe(canaryUnreachable, nil) }, eval: true,
					wantState: "unknown", wantReason: "canary probe: transport", wantAllows: true,
					wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1},
			},
		},
		row{
			name: "confirmed bad persists the bad-seen marker on every bad evaluation; recovery moves verifiedSince and clears it",
			steps: []step{verifiedStart,
				{name: "probe-only bad", do: func(e *env) { e.probe(canaryDenied, nil) }, eval: true,
					wantState: "confirmed_bad", wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1,
					wantBadSeen: boolp(true), wantMarks: intp(1)},
				{name: "still bad: marked again (one write per bad evaluation)", eval: true,
					wantState: "confirmed_bad", wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1,
					wantBadSeen: boolp(true), wantMarks: intp(2)},
				{name: "recovered", do: func(e *env) { e.probe(probesPass, nil); e.serverAt(time.Hour) }, eval: true,
					wantState: "verified", wantAllows: true, wantVerified: at(time.Hour + 30*time.Second),
					wantAudits: 3, wantAdvances: 2, wantProbeCalls: -1, wantBadSeen: boolp(false), wantMarks: intp(2)},
			},
		},
		row{
			name: "marker write fails while bad: stays confirmed bad, and the write is retried",
			steps: []step{verifiedStart,
				{name: "bad, store refuses", do: func(e *env) {
					e.probe(labelledAdmitted, nil)
					e.s.mu.Lock()
					e.s.markErr = errors.New("forbidden")
					e.s.mu.Unlock()
				}, eval: true, wantState: "confirmed_bad", wantReason: "labelled probe admitted", wantAllows: false,
					wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1, wantBadSeen: boolp(false), wantMarks: intp(0)},
				{name: "store recovers and the flaw heals: the owed marker is written, then the move clears it", do: func(e *env) {
					e.s.mu.Lock()
					e.s.markErr = nil
					e.s.mu.Unlock()
					e.probe(probesPass, nil)
					e.serverAt(time.Hour)
				}, eval: true, wantState: "verified", wantAllows: true, wantVerified: at(time.Hour + 30*time.Second),
					wantAudits: 3, wantAdvances: 2, wantProbeCalls: -1, wantBadSeen: boolp(false), wantMarks: intp(1)},
			},
		},
		row{
			name: "restart after a probe-only bad: the stored marker makes the next verified a move",
			setup: func(e *env) {
				e.s.stored = &StoredState{Fingerprint: e.g.fingerprintNow(t), VerifiedSince: server0.Add(-time.Hour), BadMarker: "m-a"}
			},
			steps: []step{
				{name: "start", eval: true, wantState: "verified", wantAllows: true, wantVerified: at(30 * time.Second),
					wantAudits: 1, wantAdvances: 1, wantProbeCalls: 1, wantBadSeen: boolp(false)},
			},
		},
		row{
			name: "another replica's marker makes this replica's next verified a move",
			steps: []step{verifiedStart,
				{name: "marker set elsewhere", do: func(e *env) {
					e.s.mark("m-other")
					e.serverAt(time.Hour)
				}, eval: true, wantState: "verified", wantAllows: true, wantVerified: at(time.Hour + 30*time.Second),
					wantAudits: 1, wantAdvances: 2, wantProbeCalls: -1, wantBadSeen: boolp(false)},
			},
		},
		row{
			name: "matching fingerprint with a zero stored verifiedSince is a pending move",
			setup: func(e *env) {
				e.s.stored = &StoredState{Fingerprint: e.g.fingerprintNow(t)}
			},
			steps: []step{
				{name: "start", eval: true, wantState: "verified", wantAllows: true, wantVerified: at(30 * time.Second),
					wantAudits: 1, wantAdvances: 1, wantProbeCalls: 1},
			},
		},
		row{
			name: "matching fingerprint with a zero stored verifiedSince and probes inconclusive: no grace",
			setup: func(e *env) {
				e.s.stored = &StoredState{Fingerprint: e.g.fingerprintNow(t)}
				e.probe(inconclusivePS, nil)
			},
			steps: []step{
				{name: "start", eval: true, wantState: "unknown", wantAllows: false, wantVerified: &time.Time{},
					wantAudits: 1, wantAdvances: 0, wantProbeCalls: 1},
			},
		},
		row{
			name: "replica B's move keeps replica A's newer marker; B is not verified; a restarted A moves",
			steps: []step{verifiedStart,
				{name: "B moves on a ConfigMap change while A marks after B observed", do: func(e *env) {
					e.watch(func(w *fakeWatcher) { w.cm.ResourceVersion = "103" })
					e.s.onServerNow = func() { e.s.mark("m-a") }
					e.serverAt(time.Hour)
				}, eval: true, wantState: "unknown", wantReason: "bad marker", wantAllows: false,
					wantVerified: at(time.Hour + 30*time.Second), wantAudits: 2, wantAdvances: 2, wantProbeCalls: -1,
					wantBadSeen: boolp(true)},
				{name: "A restarts after the flaw healed: the marker makes it move", do: func(e *env) {
					e.s.onServerNow = nil
					e.serverAt(2 * time.Hour)
					e.restart()
				}, eval: true, wantState: "verified", wantAllows: true, wantVerified: at(2*time.Hour + 30*time.Second),
					wantAudits: 3, wantAdvances: 3, wantProbeCalls: -1, wantBadSeen: boolp(false)},
			},
		},
		row{
			name: "A re-marks while still bad, so B's Advance (observed A's first marker) keeps it; a restarted A moves",
			steps: []step{verifiedStart,
				{name: "A: probe-only bad, marks m1", do: func(e *env) { e.probe(canaryDenied, nil) }, eval: true,
					wantState: "confirmed_bad", wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1,
					wantBadSeen: boolp(true), wantMarks: intp(1)},
				// B observed m1 before its ServerNow (below). A then evaluates
				// bad again with m1 cached and must still write.
				{name: "A: bad again, re-marks m2", eval: true,
					wantState: "confirmed_bad", wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1,
					wantBadSeen: boolp(true), wantMarks: intp(2)},
				{name: "B's Advance with observed m1 keeps m2", do: func(e *env) {
					st, err := e.s.Advance(context.Background(), "fp-b", server0.Add(time.Hour), "m1")
					if err != nil || st.BadMarker != "m2" {
						t.Errorf("B's Advance = %+v, %v; want marker m2 kept", st, err)
					}
				}, wantState: "confirmed_bad", wantAudits: 2, wantAdvances: 2, wantProbeCalls: -1,
					wantBadSeen: boolp(true), wantMarks: intp(2)},
				{name: "flaw heals, A restarts: m2 makes it move", do: func(e *env) {
					e.probe(probesPass, nil)
					e.serverAt(2 * time.Hour)
					e.restart()
				}, eval: true, wantState: "verified", wantAllows: true, wantVerified: at(2*time.Hour + 30*time.Second),
					wantAudits: 3, wantAdvances: 3, wantProbeCalls: -1, wantBadSeen: boolp(false), wantMarks: intp(2)},
			},
		},
		row{
			name: "after keeping a newer marker, B's next evaluation moves again and clears it",
			steps: []step{verifiedStart,
				{name: "marked during B's move", do: func(e *env) {
					e.watch(func(w *fakeWatcher) { w.cm.ResourceVersion = "104" })
					e.s.onServerNow = func() { e.s.mark("m-a") }
					e.serverAt(time.Hour)
				}, eval: true, wantState: "unknown", wantAllows: false, wantAudits: 2, wantAdvances: 2, wantProbeCalls: -1,
					wantBadSeen: boolp(true)},
				{name: "next evaluation", do: func(e *env) { e.s.onServerNow = nil; e.serverAt(2 * time.Hour) }, eval: true,
					wantState: "verified", wantAllows: true, wantVerified: at(2*time.Hour + 30*time.Second),
					wantAudits: 3, wantAdvances: 3, wantProbeCalls: -1, wantBadSeen: boolp(false)},
			},
		},
		row{
			name: "unknown within grace loses grace when the fingerprint changes",
			steps: []step{verifiedStart,
				{name: "probe inconclusive", do: func(e *env) { e.probe(inconclusivePS, nil) }, eval: true,
					wantState: "unknown", wantAllows: true, wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1},
				{name: "binding generation +2 seen by the watch", wait: 10 * time.Second, do: func(e *env) {
					e.watch(func(w *fakeWatcher) { w.b.Creators.Generation += 2 })
					e.g.onChange(context.Background())
				}, wantState: "unknown", wantAllows: false, wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1},
			},
		},
		row{
			name:  "override mode: allowed, overridden, no persistence, no probes, one audit line",
			mode:  model.GuardMode("overridden"),
			setup: func(e *env) { e.watch(func(w *fakeWatcher) { w.synced = false; w.b.Guard = nil }) },
			steps: []step{
				{name: "before evaluation", wantState: "overridden", wantAllows: true, wantVerified: &time.Time{},
					wantAudits: 0, wantAdvances: 0, wantProbeCalls: 0},
				{name: "evaluate", eval: true, wantState: "overridden", wantReason: "guard.mode is unverified", wantAllows: true,
					wantAudits: 1, wantAdvances: 0, wantProbeCalls: 0},
				{name: "evaluate again", eval: true, wait: time.Hour, wantState: "overridden", wantAllows: true,
					wantAudits: 1, wantAdvances: 0, wantProbeCalls: 0},
			},
		},
		row{
			name: "exactly one audit line per change; reason change counts, repeats do not",
			steps: []step{verifiedStart,
				{name: "verified again", eval: true, wantState: "verified", wantAllows: true, wantAudits: 1, wantAdvances: 1, wantProbeCalls: -1},
				{name: "bad: ConfigMap missing", do: func(e *env) { e.watch(func(w *fakeWatcher) { w.cm = nil }) }, eval: true,
					wantState: "confirmed_bad", wantReason: "configmap", wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1},
				{name: "same again", eval: true, wantState: "confirmed_bad", wantAudits: 2, wantAdvances: 1, wantProbeCalls: -1},
				{name: "bad, other reason", do: func(e *env) { e.watch(func(w *fakeWatcher) { w.b.Guard = nil }) }, eval: true,
					wantState: "confirmed_bad", wantReason: "binding", wantAudits: 3, wantAdvances: 1, wantProbeCalls: -1},
			},
		},
	)

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			mode := r.mode
			if mode == "" {
				mode = enforced
			}
			e := newEnv(t, mode)
			if r.setup != nil {
				r.setup(e)
			}
			for _, s := range r.steps {
				if s.do != nil {
					s.do(e)
				}
				e.clock.add(s.wait)
				if s.eval {
					got := e.g.Evaluate(context.Background())
					if got != e.g.State() {
						t.Errorf("%s: Evaluate returned %+v, State() %+v", s.name, got, e.g.State())
					}
				}
				checkStep(t, e, s, mode)
			}
		})
	}
}

// checkStep asserts one step's expectations on the env.
func checkStep(t *testing.T, e *env, s step, mode model.GuardMode) {
	t.Helper()
	st := e.g.State()
	if st.State != s.wantState {
		t.Errorf("%s: state = %q (%s), want %q", s.name, st.State, st.Reason, s.wantState)
	}
	if st.Mode != mode {
		t.Errorf("%s: mode = %q, want %q", s.name, st.Mode, mode)
	}
	if s.wantReason != "" && !strings.Contains(st.Reason, s.wantReason) {
		t.Errorf("%s: reason = %q, want it to contain %q", s.name, st.Reason, s.wantReason)
	}
	if s.wantState == "verified" && st.Reason != "" {
		t.Errorf("%s: verified with reason %q", s.name, st.Reason)
	}
	gotMode, allows := e.g.Allows()
	if allows != s.wantAllows || gotMode != mode {
		t.Errorf("%s: Allows() = (%q, %v), want (%q, %v)", s.name, gotMode, allows, mode, s.wantAllows)
	}
	if s.wantVerified != nil {
		if v := e.g.VerifiedSince(); !v.Equal(*s.wantVerified) {
			t.Errorf("%s: VerifiedSince = %v, want %v", s.name, v, *s.wantVerified)
		}
	}
	lines := e.a.all()
	if len(lines) != s.wantAudits {
		t.Errorf("%s: audit lines = %d %+v, want %d", s.name, len(lines), lines, s.wantAudits)
	} else if len(lines) > 0 && s.eval {
		last := lines[len(lines)-1]
		if last.state != st.State || last.mode != string(mode) || last.reason != st.Reason {
			t.Errorf("%s: last audit line %+v, state %+v", s.name, last, st)
		}
	}
	if s.wantAdvances >= 0 {
		e.s.mu.Lock()
		n := e.s.advances
		e.s.mu.Unlock()
		if n != s.wantAdvances {
			t.Errorf("%s: store writes = %d, want %d", s.name, n, s.wantAdvances)
		}
	}
	if s.wantBadSeen != nil {
		st, _ := e.s.Stored()
		if (st.BadMarker != "") != *s.wantBadSeen {
			t.Errorf("%s: stored marker = %q, want present %v", s.name, st.BadMarker, *s.wantBadSeen)
		}
	}
	if s.wantMarks != nil {
		e.s.mu.Lock()
		n := e.s.marks
		e.s.mu.Unlock()
		if n != *s.wantMarks {
			t.Errorf("%s: marker writes = %d, want %d", s.name, n, *s.wantMarks)
		}
	}
	if s.wantProbeCalls >= 0 {
		e.p.mu.Lock()
		n := e.p.calls
		e.p.mu.Unlock()
		if n != s.wantProbeCalls {
			t.Errorf("%s: probe calls = %d, want %d", s.name, n, s.wantProbeCalls)
		}
	}
}

// fingerprintNow is a test helper: the fingerprint of the env's live objects.
func (g *Guard) fingerprintNow(t *testing.T) string {
	t.Helper()
	pg, pc, _ := g.w.Policies()
	bg, bc, _ := g.w.Bindings()
	cm, _ := g.w.Creators()
	return fingerprint(Policies{pg, pc}, Bindings{bg, bc}, cm)
}

func TestFingerprint(t *testing.T) {
	base := newEnv(t, enforced)
	want := base.g.fingerprintNow(t)
	cases := []struct {
		name    string
		mutate  func(w *fakeWatcher)
		changed bool
	}{
		{name: "unchanged", mutate: func(*fakeWatcher) {}},
		{name: "label change (no generation bump)", mutate: func(w *fakeWatcher) {
			w.b.Guard.Labels = map[string]string{"chart": "v2"}
			w.b.Guard.ResourceVersion = "999"
		}},
		{name: "policy A generation", mutate: func(w *fakeWatcher) { w.p.Guard.Generation++ }, changed: true},
		{name: "policy B uid", mutate: func(w *fakeWatcher) { w.p.Creators.UID = "x" }, changed: true},
		{name: "binding A uid", mutate: func(w *fakeWatcher) { w.b.Guard.UID = "x" }, changed: true},
		{name: "binding B generation", mutate: func(w *fakeWatcher) { w.b.Creators.Generation += 2 }, changed: true},
		{name: "ConfigMap uid", mutate: func(w *fakeWatcher) { w.cm.UID = "x" }, changed: true},
		{name: "ConfigMap resourceVersion", mutate: func(w *fakeWatcher) { w.cm.ResourceVersion = "101" }, changed: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, enforced)
			e.watch(c.mutate)
			got := e.g.fingerprintNow(t)
			if (got != want) != c.changed {
				t.Errorf("fingerprint %q vs base %q, changed want %v", got, want, c.changed)
			}
			if strings.Contains(got, "namespaces=") {
				t.Errorf("fingerprint carries ConfigMap data: %q", got)
			}
		})
	}
}

func TestGuardRun(t *testing.T) {
	cases := []struct {
		name   string
		events int // Changed() events after the initial evaluation
	}{
		{name: "initial evaluation only", events: 0},
		{name: "one evaluation per watch event", events: 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, enforced)
			ft := useFakeTimers(e)
			probed := make(chan struct{}, 8)
			e.p.hook = func() { probed <- struct{}{} }
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- e.g.Run(ctx) }()
			recv := func(what string) {
				t.Helper()
				select {
				case <-probed:
				case <-time.After(5 * time.Second):
					t.Fatalf("no evaluation for %s", what)
				}
			}
			recv("start")
			for i := 0; i < c.events; i++ {
				e.w.changed <- struct{}{}
				// The probing evaluation waits for the settle delay.
				ft.next(t, timerSettle).fire()
				recv("event")
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Run = %v, want nil", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not return after cancel")
			}
			e.p.mu.Lock()
			defer e.p.mu.Unlock()
			if e.p.calls != 1+c.events {
				t.Errorf("evaluations = %d, want %d", e.p.calls, 1+c.events)
			}
		})
	}
}

func TestGuardRunEvaluatesOnSync(t *testing.T) {
	cases := []struct {
		name        string
		watchSynced bool
		storeSynced bool
	}{
		{name: "watcher syncs late", storeSynced: true},
		{name: "store syncs late", watchSynced: true},
		{name: "both sync late"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, enforced)
			e.w.synced = c.watchSynced
			e.s.synced = c.storeSynced
			e.a.notify = make(chan guardLine, 8)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- e.g.Run(ctx) }()
			next := func() guardLine {
				t.Helper()
				select {
				case l := <-e.a.notify:
					return l
				case <-time.After(5 * time.Second):
					t.Fatal("no audit line")
				}
				return guardLine{}
			}
			if l := next(); l.state != StateUnknown || !strings.Contains(l.reason, "not synced") {
				t.Fatalf("first line %+v, want unknown not synced", l)
			}
			e.watch(func(w *fakeWatcher) { w.synced = true })
			e.s.mu.Lock()
			e.s.synced = true
			e.s.mu.Unlock()
			// Well within EvaluateInterval: the sync, not the tick, triggers it.
			if l := next(); l.state != StateVerified {
				t.Fatalf("after sync %+v, want verified", l)
			}
			cancel()
			if err := <-done; err != nil {
				t.Errorf("Run = %v", err)
			}
		})
	}
}

// blockingProbe makes the next Probe call signal entered and wait for release.
func blockingProbe(e *env) (entered, release chan struct{}) {
	entered, release = make(chan struct{}), make(chan struct{})
	e.p.mu.Lock()
	e.p.hook = func() {
		entered <- struct{}{}
		<-release
	}
	e.p.mu.Unlock()
	return entered, release
}

func TestGuardChangeDuringEvaluation(t *testing.T) {
	cases := []struct {
		name string
		// during runs while the in-flight evaluation is blocked in Probe.
		during func(e *env)
		// After onChange, while the probe is still blocked.
		wantMidState  string
		wantMidReason string
		// After the in-flight evaluation finished.
		wantEndState  string
		wantEndAudits int
	}{
		{
			name:         "binding removed: confirmed bad at once, the in-flight verified result is not applied",
			during:       func(e *env) { e.watch(func(w *fakeWatcher) { w.b.Guard = nil }) },
			wantMidState: "confirmed_bad", wantMidReason: "binding user-secrets-pod-guard: missing",
			wantEndState: "confirmed_bad", wantEndAudits: 2,
		},
		{
			name: "generation +2 with a matching spec: denied at once, the in-flight result is stale",
			during: func(e *env) {
				e.watch(func(w *fakeWatcher) { w.b.Creators.Generation += 2 })
			},
			wantMidState: "unknown", wantMidReason: "guard objects changed",
			wantEndState: "unknown", wantEndAudits: 2,
		},
		{
			name: "binding removed and re-created: bad at once, then not verified on the stale result",
			during: func(e *env) {
				var saved = e.w.b.Guard.DeepCopy()
				e.watch(func(w *fakeWatcher) { w.b.Guard = nil })
				e.g.onChange(context.Background())
				saved.UID = "uid-ba-2"
				e.watch(func(w *fakeWatcher) { w.b.Guard = saved })
			},
			wantMidState: "confirmed_bad", wantMidReason: "binding user-secrets-pod-guard: missing",
			wantEndState: "unknown", wantEndAudits: 3,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, enforced)
			ctx := context.Background()
			if st := e.g.Evaluate(ctx); st.State != StateVerified {
				t.Fatalf("start: %+v", st)
			}
			before := e.g.VerifiedSince()
			entered, release := blockingProbe(e)
			done := make(chan GuardState, 1)
			go func() { done <- e.g.Evaluate(ctx) }()
			<-entered

			c.during(e)
			e.g.onChange(ctx)
			st := e.g.State()
			if st.State != c.wantMidState || !strings.Contains(st.Reason, c.wantMidReason) {
				t.Errorf("while probing: %+v, want %s %q", st, c.wantMidState, c.wantMidReason)
			}
			if _, ok := e.g.Allows(); ok {
				t.Error("while probing: allowed")
			}

			close(release)
			<-done
			st = e.g.State()
			if st.State != c.wantEndState {
				t.Errorf("after the in-flight evaluation: %+v, want %s", st, c.wantEndState)
			}
			if _, ok := e.g.Allows(); ok {
				t.Error("after the in-flight evaluation: allowed")
			}
			if n := len(e.a.all()); n != c.wantEndAudits {
				t.Errorf("audit lines = %d %+v, want %d", n, e.a.all(), c.wantEndAudits)
			}
			if v := e.g.VerifiedSince(); !v.Equal(before) {
				t.Errorf("VerifiedSince moved to %v on a stale result", v)
			}
		})
	}
}

func TestGuardRunAppliesChangeDuringProbe(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(w *fakeWatcher)
		wantState  string
		wantReason string
	}{
		{name: "binding removed", mutate: func(w *fakeWatcher) { w.b.Guard = nil },
			wantState: StateConfirmedBad, wantReason: "binding user-secrets-pod-guard: missing"},
		{name: "ConfigMap drifted", mutate: func(w *fakeWatcher) { w.cm.Data["jhub.hub"] = "x" },
			wantState: StateConfirmedBad, wantReason: "configmap user-secrets-creators"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, enforced)
			e.a.notify = make(chan guardLine, 8)
			entered, release := blockingProbe(e)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- e.g.Run(ctx) }()
			<-entered // the first evaluation is in flight
			e.watch(c.mutate)
			e.w.changed <- struct{}{}
			select {
			case l := <-e.a.notify:
				if l.state != c.wantState || !strings.Contains(l.reason, c.wantReason) {
					t.Errorf("line %+v, want %s %q", l, c.wantState, c.wantReason)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("change not applied while the probe was in flight")
			}
			cancel()
			close(release)
			if err := <-done; err != nil {
				t.Errorf("Run = %v", err)
			}
		})
	}
}

// TestGuardChangeBetweenProbeAndApply injects a watch event while the
// in-flight evaluation reads the snapshot it applies against: that read must
// happen under mu, so the event's onChange is ordered after the apply and is
// not overwritten by a stale verified.
func TestGuardChangeBetweenProbeAndApply(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(w *fakeWatcher)
		wantState  string
		wantReason string
	}{
		{name: "binding removed", mutate: func(w *fakeWatcher) { w.b.Guard = nil },
			wantState: StateConfirmedBad, wantReason: "binding user-secrets-pod-guard: missing"},
		{name: "binding generation +2", mutate: func(w *fakeWatcher) { w.b.Creators.Generation += 2 },
			wantState: StateUnknown, wantReason: "guard objects changed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, enforced)
			ctx := context.Background()
			if st := e.g.Evaluate(ctx); st.State != StateVerified {
				t.Fatalf("start: %+v", st)
			}
			probed := make(chan struct{})
			e.p.mu.Lock()
			e.p.hook = func() { close(probed) }
			e.p.mu.Unlock()
			onChangeDone := make(chan struct{})
			var fired sync.Once
			e.w.mu.Lock()
			e.w.onCreators = func() {
				select {
				case <-probed: // a snapshot read after the probe returned: the apply's
				default:
					return
				}
				fired.Do(func() {
					if e.g.mu.TryLock() {
						e.g.mu.Unlock()
						t.Error("apply read the snapshot without holding mu")
					}
					e.watch(c.mutate)
					go func() { e.g.onChange(ctx); close(onChangeDone) }()
				})
			}
			e.w.mu.Unlock()

			e.g.Evaluate(ctx)
			select {
			case <-onChangeDone:
			case <-time.After(5 * time.Second):
				t.Fatal("hook did not fire or onChange did not finish")
			}
			st := e.g.State()
			if st.State != c.wantState || !strings.Contains(st.Reason, c.wantReason) {
				t.Errorf("final %+v, want %s %q", st, c.wantState, c.wantReason)
			}
			if _, ok := e.g.Allows(); ok {
				t.Error("allowed after the change")
			}
			lines := e.a.all()
			if last := lines[len(lines)-1]; last.state != c.wantState {
				t.Errorf("last audit line %+v, want %s", last, c.wantState)
			}
		})
	}
}

// TestGuardMarksOutsideMu: a confirmed_bad produced by onChange or by the
// apply-time recheck is persisted, by Evaluate and never while mu is held.
func TestGuardMarksOutsideMu(t *testing.T) {
	cases := []struct {
		name string
		// run produces the confirmed_bad from a verified start.
		run           func(t *testing.T, e *env)
		wantMarks     int // total marker writes at the end
		wantMarkerSet bool
	}{
		{
			name: "onChange bad, then the follow-up evaluation writes",
			run: func(t *testing.T, e *env) {
				e.watch(func(w *fakeWatcher) { w.b.Guard = nil })
				e.g.onChange(context.Background())
				e.s.mu.Lock()
				n := e.s.marks
				e.s.mu.Unlock()
				if n != 0 {
					t.Errorf("onChange wrote the marker %d times", n)
				}
				e.g.Evaluate(context.Background()) // flush at start, then its own bad verdict
			},
			wantMarks: 2, wantMarkerSet: true,
		},
		{
			name: "recheck bad (binding removed during the probe) is written after the apply",
			run: func(t *testing.T, e *env) {
				e.p.mu.Lock()
				e.p.hook = func() { e.watch(func(w *fakeWatcher) { w.b.Guard = nil }) }
				e.p.mu.Unlock()
				if st := e.g.Evaluate(context.Background()); st.State != StateConfirmedBad {
					t.Errorf("recheck gave %+v, want confirmed_bad", st)
				}
			},
			wantMarks: 1, wantMarkerSet: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, enforced)
			if st := e.g.Evaluate(context.Background()); st.State != StateVerified {
				t.Fatalf("start: %+v", st)
			}
			e.s.onMark = func() {
				if !e.g.mu.TryLock() {
					t.Error("MarkBad called while mu is held")
					return
				}
				e.g.mu.Unlock()
			}
			c.run(t, e)
			e.s.mu.Lock()
			n := e.s.marks
			e.s.mu.Unlock()
			if n != c.wantMarks {
				t.Errorf("marker writes = %d, want %d", n, c.wantMarks)
			}
			if st, _ := e.s.Stored(); (st.BadMarker != "") != c.wantMarkerSet {
				t.Errorf("stored marker %q, want set %v", st.BadMarker, c.wantMarkerSet)
			}
			if got := e.g.State(); got.State != StateConfirmedBad {
				t.Errorf("state %+v, want confirmed_bad", got)
			}
		})
	}
}

func TestGuardConcurrentReads(t *testing.T) {
	e := newEnv(t, enforced)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				e.g.Evaluate(ctx)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = e.g.State()
				_, _ = e.g.Allows()
				_ = e.g.VerifiedSince()
			}
		}()
	}
	wg.Wait()
}

// The guard must satisfy httpapi.GuardStatus; checked here structurally.
var _ interface{ State() GuardState } = (*Guard)(nil)

// fakeTimer is a Run timer the test fires by hand.
type fakeTimer struct {
	kind timerKind
	d    time.Duration
	c    chan time.Time

	mu      sync.Mutex
	stopped bool
}

func (f *fakeTimer) C() <-chan time.Time { return f.c }

func (f *fakeTimer) Stop() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	was := !f.stopped
	f.stopped = true
	return was
}

func (f *fakeTimer) isStopped() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.stopped }

func (f *fakeTimer) fire() { f.c <- time.Time{} }

// fakeTimers records every timer Run makes, in order.
type fakeTimers struct{ made chan *fakeTimer }

// useFakeTimers replaces the guard's timers; call it before Run.
func useFakeTimers(e *env) *fakeTimers {
	ft := &fakeTimers{made: make(chan *fakeTimer, 64)}
	e.g.newTimer = func(k timerKind, d time.Duration) timer {
		tm := &fakeTimer{kind: k, d: d, c: make(chan time.Time, 1)}
		ft.made <- tm
		return tm
	}
	return ft
}

// next returns the next timer Run makes, which must be of kind.
func (ft *fakeTimers) next(t *testing.T, kind timerKind) *fakeTimer {
	t.Helper()
	select {
	case tm := <-ft.made:
		if tm.kind != kind {
			t.Fatalf("next timer is kind %d (%s), want kind %d", tm.kind, tm.d, kind)
		}
		return tm
	case <-time.After(5 * time.Second):
		t.Fatalf("no timer of kind %d made", kind)
	}
	return nil
}

func (e *env) probeCalls() int { e.p.mu.Lock(); defer e.p.mu.Unlock(); return e.p.calls }

// runGuard starts Run and returns a stop function that cancels it and checks
// that it returns nil. Calling stop again does nothing.
func runGuard(t *testing.T, e *env) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.g.Run(ctx) }()
	var once sync.Once
	return func() {
		t.Helper()
		once.Do(func() { stopRun(t, cancel, done) })
	}
}

func stopRun(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// nextLine returns the next audit line, failing after 5 s.
func nextLine(t *testing.T, e *env) guardLine {
	t.Helper()
	select {
	case l := <-e.a.notify:
		return l
	case <-time.After(5 * time.Second):
		t.Fatal("no audit line")
	}
	return guardLine{}
}

// TestGuardRunBacksOffWhileNotVerified: while evaluations end confirmed_bad or
// unknown, Run re-evaluates after 2, 4, 8, 16, 30, 30 s; a verified result
// stops the retries and resets the backoff to 2 s.
func TestGuardRunBacksOffWhileNotVerified(t *testing.T) {
	cases := []struct {
		name      string
		bad       ProbeResult
		wantState string
	}{
		{name: "confirmed bad: labelled probe admitted", bad: labelledAdmitted, wantState: StateConfirmedBad},
		{name: "unknown: probe inconclusive",
			bad:       ProbeResult{Labelled: pInc("other_denial"), Unlabelled: pAsDesigned, Canary: pAdmitted},
			wantState: StateUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, enforced)
			e.a.notify = make(chan guardLine, 16)
			e.probe(c.bad, nil)
			ft := useFakeTimers(e)
			stop := runGuard(t, e)
			defer stop()

			if l := nextLine(t, e); l.state != c.wantState {
				t.Fatalf("first line %+v, want %s", l, c.wantState)
			}
			want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second,
				30 * time.Second, 30 * time.Second}
			var last *fakeTimer
			for i, d := range want {
				tm := ft.next(t, timerRetry)
				if tm.d != d {
					t.Fatalf("retry %d after %s, want %s", i+1, tm.d, d)
				}
				if got := e.probeCalls(); got != i+1 {
					t.Fatalf("before retry %d: %d evaluations, want %d", i+1, got, i+1)
				}
				last = tm
				if i < len(want)-1 {
					tm.fire()
				}
			}

			// The flaw heals: the next retry verifies and no further retry is made.
			e.probe(probesPass, nil)
			last.fire()
			if l := nextLine(t, e); l.state != StateVerified {
				t.Fatalf("after healing %+v, want verified", l)
			}

			// A later bad result starts again at 2 s. A retry wrongly armed by
			// the verified result would show up here first, or with its 30 s.
			e.probe(c.bad, nil)
			e.w.changed <- struct{}{}
			ft.next(t, timerSettle).fire()
			if tm := ft.next(t, timerRetry); tm.d != RetryInitial {
				t.Errorf("after verified, first retry after %s, want %s", tm.d, RetryInitial)
			}
		})
	}
}

// TestGuardRunSettlesAfterWatchEvents: a burst of watch events gives one
// probing evaluation, SettleDelay after the latest event; each event restarts
// the delay.
func TestGuardRunSettlesAfterWatchEvents(t *testing.T) {
	cases := []struct {
		name   string
		events int
	}{
		{name: "one event", events: 1},
		{name: "a burst of three events", events: 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, enforced)
			e.a.notify = make(chan guardLine, 16)
			ft := useFakeTimers(e)
			probed := make(chan struct{}, 8)
			e.p.hook = func() { probed <- struct{}{} }
			stop := runGuard(t, e)
			defer stop()
			<-probed
			if l := nextLine(t, e); l.state != StateVerified {
				t.Fatalf("start %+v, want verified", l)
			}

			var timers []*fakeTimer
			for range c.events {
				e.w.changed <- struct{}{}
				tm := ft.next(t, timerSettle)
				if tm.d != SettleDelay {
					t.Fatalf("settle delay %s, want %s", tm.d, SettleDelay)
				}
				timers = append(timers, tm)
			}
			if got := e.probeCalls(); got != 1 {
				t.Fatalf("%d evaluations before the settle delay ended, want 1", got)
			}
			for i, tm := range timers[:len(timers)-1] {
				if !tm.isStopped() {
					t.Errorf("settle timer %d not stopped by the later event", i+1)
				}
			}
			timers[len(timers)-1].fire()
			select {
			case <-probed:
			case <-time.After(5 * time.Second):
				t.Fatal("no evaluation after the settle delay")
			}
			stop()
			if got := e.probeCalls(); got != 2 {
				t.Errorf("%d evaluations, want 2 (start and one after the burst)", got)
			}
		})
	}
}

// TestGuardRunFastPathDuringSettle: a change Compare can see is applied at
// once on the watch event, without waiting for the settle delay or probing.
func TestGuardRunFastPathDuringSettle(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(w *fakeWatcher)
		wantReason string
	}{
		{name: "binding B switched to Warn",
			mutate: func(w *fakeWatcher) {
				w.b.Creators.Spec.ValidationActions = []admissionregistrationv1.ValidationAction{admissionregistrationv1.Warn}
				w.b.Creators.Generation++
			},
			wantReason: "binding user-secrets-creators: validationActions lacks Deny"},
		{name: "creators ConfigMap deleted", mutate: func(w *fakeWatcher) { w.cm = nil },
			wantReason: "configmap user-secrets-creators: missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, enforced)
			e.a.notify = make(chan guardLine, 16)
			ft := useFakeTimers(e)
			stop := runGuard(t, e)
			defer stop()
			if l := nextLine(t, e); l.state != StateVerified {
				t.Fatalf("start %+v, want verified", l)
			}

			e.watch(c.mutate)
			e.w.changed <- struct{}{}
			l := nextLine(t, e)
			if l.state != StateConfirmedBad || l.reason != c.wantReason {
				t.Errorf("line %+v, want confirmed_bad %q", l, c.wantReason)
			}
			if _, ok := e.g.Allows(); ok {
				t.Error("allowed during the settle delay")
			}
			tm := ft.next(t, timerSettle)
			if tm.isStopped() {
				t.Error("settle timer stopped, want pending")
			}
			if got := e.probeCalls(); got != 1 {
				t.Errorf("%d evaluations, want 1: the fast path must not probe", got)
			}
		})
	}
}

// TestGuardRunWatchEventResetsBackoff: a watch event during a long bad period
// cancels the pending long retry and restarts the backoff, so the settled
// evaluation's bad result is retried after RetryInitial, not RetryMax.
func TestGuardRunWatchEventResetsBackoff(t *testing.T) {
	cases := []struct {
		name string
		bad  ProbeResult
	}{
		{name: "confirmed bad", bad: labelledAdmitted},
		{name: "unknown", bad: ProbeResult{Labelled: pInc("other_denial"), Unlabelled: pAsDesigned, Canary: pAdmitted}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, enforced)
			e.a.notify = make(chan guardLine, 16)
			e.probe(c.bad, nil)
			ft := useFakeTimers(e)
			stop := runGuard(t, e)
			defer stop()

			var long *fakeTimer
			for _, d := range []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, RetryMax} {
				tm := ft.next(t, timerRetry)
				if tm.d != d {
					t.Fatalf("retry after %s, want %s", tm.d, d)
				}
				if d == RetryMax {
					long = tm
					break
				}
				tm.fire()
			}

			e.w.changed <- struct{}{}
			ft.next(t, timerSettle).fire()
			if !long.isStopped() {
				t.Error("the pending RetryMax retry was not cancelled by the watch event")
			}
			if tm := ft.next(t, timerRetry); tm.d != RetryInitial {
				t.Errorf("retry after the watch event %s, want %s", tm.d, RetryInitial)
			}
		})
	}
}

// TestRunTimingInvariants pins the relations between Run's delays that its
// correctness depends on.
func TestRunTimingInvariants(t *testing.T) {
	// The API server's policy refresh interval (see SettleDelay).
	const apiServerPolicyRefresh = time.Second
	cases := []struct {
		name string
		ok   bool
	}{
		{name: "SettleDelay is longer than the API server's policy refresh", ok: SettleDelay > apiServerPolicyRefresh},
		{name: "RetryInitial >= SettleDelay: no retry probes inside the settle window", ok: RetryInitial >= SettleDelay},
		{name: "RetryMax >= RetryInitial", ok: RetryMax >= RetryInitial},
		{name: "RetryMax < EvaluateInterval: a bad state retries sooner than the verified tick",
			ok: RetryMax < EvaluateInterval},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !c.ok {
				t.Errorf("violated: SettleDelay %s, RetryInitial %s, RetryMax %s, EvaluateInterval %s",
					SettleDelay, RetryInitial, RetryMax, EvaluateInterval)
			}
		})
	}
}
