package guard

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/nebari-dev/nebari-user-secrets/internal/audit"
	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

const (
	// EvaluateInterval is how often Run evaluates without a watch event while
	// the state is verified (or overridden).
	EvaluateInterval = 5 * time.Minute
	// SettleDelay is how long after the latest watch event Run waits before
	// the probing evaluation. The API server applies a policy or binding change
	// to admission only on its next policy refresh, which runs every second
	// (k8s.io/apiserver v0.35.0 pkg/admission/plugin/policy/generic/policy_source.go:47
	// policyRefreshIntervalDefault = 1 * time.Second, run at :205 by wait.Until
	// and gated by policiesDirty at :241 and :267; the same 1 s, hard-coded, at
	// v0.30.0 :181). A probe sent sooner can meet the previous enforcement.
	SettleDelay = 2 * time.Second
	// RetryInitial and RetryMax bound the backoff on which Run re-evaluates
	// while the state is confirmed_bad or unknown: RetryInitial, doubling, at
	// most RetryMax, reset once the state is verified and on every watch
	// event.
	//
	// RetryInitial must be at least SettleDelay (TestRunTimingInvariants): a
	// watch event cancels any pending retry and resets the backoff, so the
	// earliest retry after an event is armed by a later evaluation result and
	// fires RetryInitial after it, never inside the settle window.
	RetryInitial = 2 * time.Second
	RetryMax     = 30 * time.Second
	// VerifiedSinceMargin is added to the API-server time when verifiedSince
	// moves, covering clock skew and the lag before a binding change takes
	// effect on every API server.
	VerifiedSinceMargin = 30 * time.Second
	// syncPollInterval is how often Run checks, until both caches have synced,
	// whether they have, so the first full evaluation does not wait for the
	// EvaluateInterval tick.
	syncPollInterval = 250 * time.Millisecond

	StateVerified     = "verified"
	StateConfirmedBad = "confirmed_bad"
	StateUnknown      = "unknown"
	StateOverridden   = "overridden"

	ModeEnforced   model.GuardMode = "enforced"
	ModeOverridden model.GuardMode = "overridden"

	reasonOverridden   = "guard.mode is unverified"
	reasonNotEvaluated = "not evaluated yet"
	reasonObjectsMoved = "guard objects changed"
)

// changeNotifier is implemented by InformerWatcher. Run evaluates on its
// events when the AdmissionWatcher provides it.
type changeNotifier interface {
	Changed() <-chan struct{}
}

// Guard combines the watched objects, the probes and the shared guard state
// into the replica's verdict.
type Guard struct {
	w        AdmissionWatcher
	p        Prober
	expected Expectation
	wantCM   map[string]string
	store    StateStore
	aud      audit.AuditSink
	mode     model.GuardMode
	grace    time.Duration
	now      func() time.Time
	// newTimer makes Run's settle and retry timers; tests replace it.
	newTimer func(kind timerKind, d time.Duration) timer

	// evalMu serialises full evaluations with each other only. State, Allows,
	// VerifiedSince and onChange never take it, so none of them waits for the
	// network calls an evaluation makes.
	evalMu sync.Mutex

	// mu guards the fields below. It is never held across a network call; the
	// audit sink (local logging) is called under it so lines keep the order of
	// the state changes.
	mu            sync.Mutex
	state         GuardState
	announced     bool      // the first GuardChanged has been emitted
	unknownSince  time.Time // local time the current unknown state began
	graceOK       bool      // the current unknown state may keep allowing for grace
	sawBad        bool      // confirmed_bad seen since verifiedSince last moved
	markPending   bool      // a confirmed_bad was applied and its marker is not yet written
	verifiedFP    string    // fingerprint of the snapshot the current verified state was based on
	verifiedSince time.Time // high-water mark of every value written or observed
}

// NewGuard builds a guard. mode is ModeEnforced or ModeOverridden (config
// guard.mode "unverified"); in override mode the watcher, prober and store are
// never used and may be nil. now is the local clock, used only for the grace
// period, never for verifiedSince.
func NewGuard(w AdmissionWatcher, p Prober, expected Expectation, wantCreators map[string]string, store StateStore,
	aud audit.AuditSink, mode model.GuardMode, grace time.Duration, now func() time.Time,
) *Guard {
	g := &Guard{
		w: w, p: p, expected: expected, wantCM: wantCreators, store: store, aud: aud,
		mode: mode, grace: grace, now: now, newTimer: newRealTimer,
		state: GuardState{State: StateUnknown, Mode: mode, Reason: reasonNotEvaluated},
	}
	if mode == ModeOverridden {
		g.state = GuardState{State: StateOverridden, Mode: mode, Reason: reasonOverridden}
	}
	return g
}

// outcome is one evaluation's verdict before it is applied.
type outcome struct {
	state, reason string
	fp            string       // fingerprint of the snapshot a verified verdict is based on
	movePending   bool         // verifiedSince must move and has not
	stored        *StoredState // the guard-state after this evaluation, when known
	err           error        // for the span only, never for the reason
}

// snapshot is the watched objects at one moment.
type snapshot struct {
	p  Policies
	b  Bindings
	cm *corev1.ConfigMap
}

func (g *Guard) snapshot() snapshot {
	pg, pc, _ := g.w.Policies()
	bg, bc, _ := g.w.Bindings()
	cm, _ := g.w.Creators()
	return snapshot{Policies{Guard: pg, Creators: pc}, Bindings{Guard: bg, Creators: bc}, cm}
}

func (g *Guard) synced() bool { return g.w.Synced() && g.store.Synced() }

// Evaluate checks the watched objects and runs the probes, then applies the
// verdict. It emits one GuardChanged when the state or reason changes. An
// evaluation cut short because ctx ended is discarded. A verified verdict is
// applied only if the objects still compare and fingerprint the same when it
// is ready, since they may have changed while the probes ran.
func (g *Guard) Evaluate(ctx context.Context) GuardState {
	ctx, span := otel.Tracer("nebari-user-secrets").Start(ctx, "guard.Evaluate")
	defer span.End()
	g.evalMu.Lock()
	defer g.evalMu.Unlock()

	if g.mode == ModeOverridden {
		return g.apply(ctx, outcome{state: StateOverridden, reason: reasonOverridden}, false)
	}
	// Persist a marker owed by an onChange confirmed_bad before probing.
	if err := g.flushMark(ctx); err != nil {
		span.RecordError(err)
	}
	g.mu.Lock()
	sawBad := g.sawBad
	g.mu.Unlock()

	o := g.check(ctx, sawBad)
	if o.err != nil {
		span.RecordError(o.err)
	}
	if ctx.Err() != nil {
		return g.State()
	}
	st := g.apply(ctx, o, true)
	// Every confirmed_bad applied (by this verdict or its recheck) writes a
	// fresh marker, outside mu, so a restart or another replica also moves
	// verifiedSince on recovery, and a move that observed an older marker
	// cannot clear this one. On failure the state stays confirmed_bad and the
	// write is retried by the next evaluation.
	if err := g.flushMark(ctx); err != nil {
		span.RecordError(err)
	}
	return st
}

// flushMark writes the bad-seen marker if a confirmed_bad was applied since the
// last write. It must not be called with mu held: MarkBad is a network call.
func (g *Guard) flushMark(ctx context.Context) error {
	g.mu.Lock()
	pending := g.markPending
	g.markPending = false
	g.mu.Unlock()
	if !pending {
		return nil
	}
	if err := g.store.MarkBad(ctx); err != nil {
		g.mu.Lock()
		g.markPending = true
		g.mu.Unlock()
		return err
	}
	return nil
}

// recheck re-reads the snapshot for an outcome that took time to compute: a
// Compare failure now wins over any verdict, and a verified verdict whose
// fingerprint no longer matches becomes unknown with a move pending. The
// caller holds mu, so a watch event's onChange is ordered before or after the
// whole recheck-and-apply, never in between. It reads only caches.
func (g *Guard) recheck(o outcome) outcome {
	if !g.synced() {
		return o
	}
	s := g.snapshot()
	if ok, reason := g.expected.Compare(s.p, s.b, s.cm, g.wantCM); !ok {
		return outcome{state: StateConfirmedBad, reason: reason}
	}
	if o.state == StateVerified && fingerprint(s.p, s.b, s.cm) != o.fp {
		return outcome{state: StateUnknown, reason: reasonObjectsMoved, movePending: true}
	}
	return o
}

// check computes the verdict without holding mu: it makes network calls.
func (g *Guard) check(ctx context.Context, sawBad bool) outcome {
	if !g.w.Synced() {
		return outcome{state: StateUnknown, reason: "watch not synced"}
	}
	if !g.store.Synced() {
		return outcome{state: StateUnknown, reason: "guard state not synced"}
	}
	s := g.snapshot()
	if ok, reason := g.expected.Compare(s.p, s.b, s.cm, g.wantCM); !ok {
		return outcome{state: StateConfirmedBad, reason: reason}
	}

	fp := fingerprint(s.p, s.b, s.cm)
	stored, has := g.store.Stored()
	move := sawBad || !has || stored.BadMarker != "" || stored.Fingerprint != fp || stored.VerifiedSince.IsZero()

	res, err := g.p.Probe(ctx)
	if err != nil {
		return outcome{state: StateUnknown, reason: "probe did not complete", movePending: move, err: err}
	}
	// A concluded wrong outcome is confirmed bad whatever the other probes did.
	switch {
	case res.Labelled.Outcome == OutcomeAdmitted:
		return outcome{state: StateConfirmedBad, reason: "labelled probe admitted"}
	case res.Unlabelled.Outcome == OutcomeAdmitted:
		return outcome{state: StateConfirmedBad, reason: "unlabelled probe admitted"}
	case res.Canary.Outcome == OutcomeDenied:
		return outcome{state: StateConfirmedBad, reason: "canary probe denied"}
	}
	if res.Labelled.Outcome != OutcomeDeniedAsExpected || res.Unlabelled.Outcome != OutcomeDeniedAsExpected ||
		res.Canary.Outcome != OutcomeAdmitted {
		return outcome{state: StateUnknown, reason: "probe inconclusive: " + res.Detail(), movePending: move}
	}

	// Re-read the stored state now that the probes passed: the marker observed
	// here, before the server time is read, is the only one this move may
	// clear.
	stored, has = g.store.Stored()
	move = sawBad || !has || stored.BadMarker != "" || stored.Fingerprint != fp || stored.VerifiedSince.IsZero()
	if !move {
		return outcome{state: StateVerified, fp: fp, stored: &stored}
	}
	observed := stored.BadMarker
	// The probes passed after a fingerprint change, a confirmed-bad state (here
	// or on another replica), or with nothing usable stored: move verifiedSince
	// to an API-server time taken now, plus the margin, never backwards
	// (Advance applies the max rule and clears the marker only if it is still
	// the observed one).
	serverNow, err := g.store.ServerNow(ctx)
	if err != nil {
		return outcome{state: StateUnknown, reason: "guard state: server time unavailable", movePending: true, err: err}
	}
	if serverNow.IsZero() {
		return outcome{state: StateUnknown, reason: "guard state: server time unavailable", movePending: true,
			err: errors.New("zero server time")}
	}
	st, err := g.store.Advance(ctx, fp, serverNow.Add(VerifiedSinceMargin), observed)
	if err != nil {
		return outcome{state: StateUnknown, reason: "guard state write failed", movePending: true, err: err}
	}
	if st.BadMarker != "" {
		// Some replica saw confirmed_bad after this move's observation: the
		// move was written (forward only) but cannot count; the next
		// evaluation moves again.
		return outcome{state: StateUnknown, reason: "guard state: new bad marker during the move", movePending: true}
	}
	return outcome{state: StateVerified, fp: fp, stored: &st}
}

// onChange reacts to a watch event at once, without waiting for an in-flight
// evaluation: a Compare failure is applied as confirmed_bad; a verified state
// whose fingerprint changed becomes unknown with a move pending; an unknown
// state whose fingerprint changed loses its grace. It runs under mu and reads
// only caches; the full evaluation that follows does the rest.
func (g *Guard) onChange(ctx context.Context) {
	if g.mode == ModeOverridden {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.synced() {
		return
	}
	s := g.snapshot()
	if ok, reason := g.expected.Compare(s.p, s.b, s.cm, g.wantCM); !ok {
		g.applyLocked(ctx, outcome{state: StateConfirmedBad, reason: reason})
		return
	}
	if fingerprint(s.p, s.b, s.cm) == g.verifiedFP {
		return
	}
	switch g.state.State {
	case StateVerified:
		g.applyLocked(ctx, outcome{state: StateUnknown, reason: reasonObjectsMoved, movePending: true})
	case StateUnknown:
		g.graceOK = false // a move is now pending: verifiedSince is stale
	}
}

// apply records the verdict and emits GuardChanged on a change. With recheck,
// the verdict is first checked against the current snapshot under mu.
func (g *Guard) apply(ctx context.Context, o outcome, recheck bool) GuardState {
	g.mu.Lock()
	defer g.mu.Unlock()
	if recheck {
		o = g.recheck(o)
	}
	return g.applyLocked(ctx, o)
}

func (g *Guard) applyLocked(ctx context.Context, o outcome) GuardState {
	prev := g.state
	next := GuardState{State: o.state, Mode: g.mode, Reason: o.reason}
	switch o.state {
	case StateUnknown:
		if prev.State != StateUnknown {
			g.unknownSince = g.now()
			g.graceOK = prev.State == StateVerified
		}
		// A pending move means verifiedSince is stale: allowing during grace
		// would trust pods admitted while the guard was not enforcing.
		if o.movePending {
			g.graceOK = false
		}
	case StateConfirmedBad:
		g.sawBad = true
		g.markPending = true // written by Evaluate's flushMark, outside mu
	case StateVerified:
		g.verifiedFP = o.fp
		if o.stored != nil {
			g.sawBad = false
			if o.stored.VerifiedSince.After(g.verifiedSince) {
				g.verifiedSince = o.stored.VerifiedSince
			}
		}
	}
	emit := next != prev || !g.announced
	g.state, g.announced = next, true
	if emit {
		g.aud.GuardChanged(ctx, next.State, string(next.Mode), next.Reason)
	}
	return next
}

// Allows reports whether delivery may proceed: always in override mode; while
// verified; and while unknown only within grace of a transition from verified.
func (g *Guard) Allows() (model.GuardMode, bool) {
	if g.mode == ModeOverridden {
		return g.mode, true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	switch g.state.State {
	case StateVerified:
		return g.mode, true
	case StateUnknown:
		return g.mode, g.graceOK && g.now().Sub(g.unknownSince) < g.grace
	default:
		return g.mode, false
	}
}

// State returns the current state for the status route.
func (g *Guard) State() GuardState {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state
}

// VerifiedSince returns the later of this replica's value and the stored value
// last observed through the guard-state watch. It never decreases. It is zero
// in override mode, where the check is skipped.
func (g *Guard) VerifiedSince() time.Time {
	if g.mode == ModeOverridden {
		return time.Time{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if st, ok := g.store.Stored(); ok && st.VerifiedSince.After(g.verifiedSince) {
		g.verifiedSince = st.VerifiedSince
	}
	return g.verifiedSince
}

// timerKind names what a Run timer is for, so tests can tell them apart.
type timerKind int

const (
	timerSettle timerKind = iota
	timerRetry
)

// timer is the part of time.Timer Run uses.
type timer interface {
	C() <-chan time.Time
	Stop() bool
}

type realTimer struct{ t *time.Timer }

func (r realTimer) C() <-chan time.Time { return r.t.C }
func (r realTimer) Stop() bool          { return r.t.Stop() }

func newRealTimer(_ timerKind, d time.Duration) timer { return realTimer{time.NewTimer(d)} }

// Run evaluates once, then as soon as the watcher and the guard-state store
// have synced, SettleDelay after the latest watch event (when the watcher
// provides Changed), on a backoff while the state is confirmed_bad or unknown
// (RetryInitial doubling to RetryMax, reset on verified and on a watch event), and every
// EvaluateInterval, until ctx ends. It returns nil then.
//
// A watch event is applied through onChange at once, so a change Compare can
// see denies immediately even while an evaluation is in flight or a settle
// delay runs; only the probing evaluation waits, and a burst of events
// restarts the delay and coalesces into one evaluation. Full evaluations run
// on a worker goroutine; requests made meanwhile coalesce into one further
// evaluation.
func (g *Guard) Run(ctx context.Context) error {
	ctx, span := otel.Tracer("nebari-user-secrets").Start(ctx, "guard.Run")
	defer span.End()

	requests := make(chan struct{}, 1)
	request := func() {
		select {
		case requests <- struct{}{}:
		default:
		}
	}
	results := make(chan GuardState)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		for {
			select {
			case <-ctx.Done():
				return
			case <-requests:
				st := g.Evaluate(ctx)
				select {
				case results <- st:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	defer func() { <-workerDone }()

	var changed <-chan struct{}
	if n, ok := g.w.(changeNotifier); ok {
		changed = n.Changed()
	}
	var syncTick <-chan time.Time
	if g.mode != ModeOverridden && !g.synced() {
		t := time.NewTicker(syncPollInterval)
		defer t.Stop()
		syncTick = t.C
	}
	ticker := time.NewTicker(EvaluateInterval)
	defer ticker.Stop()

	var settle, retry timer
	stop := func(t *timer) {
		if *t != nil {
			(*t).Stop()
			*t = nil
		}
	}
	defer stop(&settle)
	defer stop(&retry)
	timerC := func(t timer) <-chan time.Time {
		if t == nil {
			return nil
		}
		return t.C()
	}
	backoff := RetryInitial

	request()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
			g.onChange(ctx)
			// The settle evaluation supersedes a pending retry, and the backoff
			// starts over: the event may be the fix, so its result is retried
			// RetryInitial after settling, not after the long backoff reached
			// before it.
			stop(&retry)
			backoff = RetryInitial
			stop(&settle)
			settle = g.newTimer(timerSettle, SettleDelay)
		case <-timerC(settle):
			settle = nil
			request()
		case <-timerC(retry):
			retry = nil
			request()
		case st := <-results:
			stop(&retry)
			if st.State == StateConfirmedBad || st.State == StateUnknown {
				retry = g.newTimer(timerRetry, backoff)
				backoff = min(backoff*2, RetryMax)
			} else {
				backoff = RetryInitial
			}
		case <-syncTick:
			if g.synced() {
				syncTick = nil
				request()
			}
		case <-ticker.C:
			request()
		}
	}
}

// fingerprint identifies the guard objects' versions: uid and generation for
// the policies and bindings (generation tracks spec edits, so label changes do
// not count), uid and resourceVersion for the ConfigMap (no generation). It
// carries no ConfigMap data.
func fingerprint(p Policies, b Bindings, cm *corev1.ConfigMap) string {
	vap := func(name string, o *admissionregistrationv1.ValidatingAdmissionPolicy) string {
		if o == nil {
			return "vap/" + name + "=-"
		}
		return fmt.Sprintf("vap/%s=%s/%d", name, o.UID, o.Generation)
	}
	vapb := func(name string, o *admissionregistrationv1.ValidatingAdmissionPolicyBinding) string {
		if o == nil {
			return "vapb/" + name + "=-"
		}
		return fmt.Sprintf("vapb/%s=%s/%d", name, o.UID, o.Generation)
	}
	cmPart := "cm/" + creatorsName + "=-"
	if cm != nil {
		cmPart = fmt.Sprintf("cm/%s=%s/%s", creatorsName, cm.UID, cm.ResourceVersion)
	}
	return strings.Join([]string{
		vap(guardName, p.Guard), vap(creatorsName, p.Creators),
		vapb(guardName, b.Guard), vapb(creatorsName, b.Creators), cmPart,
	}, ";")
}
