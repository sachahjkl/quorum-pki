// Package simulation uses the production engine with deterministic virtual delay.
package simulation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	e "quorum-pki/internal/engine"
	p "quorum-pki/internal/protocol"
	"sort"
	"sync"
	"time"
)

type Options struct {
	Validators         int      `json:"validators"`
	Quorum             int      `json:"quorum"`
	Finality           int      `json:"finality"`
	Byzantine          int      `json:"byzantine"`
	Seed               int64    `json:"seed"`
	MinLatency         int      `json:"minLatencyMs"`
	MaxLatency         int      `json:"maxLatencyMs"`
	FailureProbability int      `json:"failurePercent"`
	Malicious          []string `json:"maliciousValidators"`
	Unavailable        []string `json:"unavailableValidators"`
	BadSignature       []string `json:"badSignatureValidators"`
	Refuse             []string `json:"refuseValidators"`
	Partitions         []string `json:"networkPartitions"`
	Realtime           bool     `json:"realtime"`
}

func Defaults() Options {
	return Options{Validators: 5, Quorum: 3, Finality: 4, Byzantine: 1, Seed: 42, MinLatency: 10, MaxLatency: 300, Malicious: []string{}, Unavailable: []string{}, BadSignature: []string{}, Refuse: []string{}, Partitions: []string{}}
}

type Actor struct {
	Authority   *e.Authority
	Delay       int
	Unavailable bool
	Realtime    bool
}

func (a *Actor) wait(ctx context.Context) error {
	if a.Unavailable {
		return errors.New("network partition/crash")
	}
	if a.Realtime {
		t := time.NewTimer(time.Duration(a.Delay) * time.Millisecond)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}
func (a *Actor) Approve(ctx context.Context, r e.Request, n int64) (p.Approval, error) {
	if err := a.wait(ctx); err != nil {
		return p.Approval{}, err
	}
	return a.Authority.Approve(r, n)
}
func (a *Actor) Notarize(ctx context.Context, x e.Candidate) (p.Signature, error) {
	if err := a.wait(ctx); err != nil {
		return p.Signature{}, err
	}
	return a.Authority.Notarize(x)
}
func Seed(label string, seed int64) []byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("DEMO-ONLY/%d/%s", seed, label)))
	return h[:]
}
func Key(label string, seed int64) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(Seed(label, seed))
}
func contains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}

type World struct {
	Coordinator *e.Coordinator
	Authorities []*e.Authority
	Owner       ed25519.PrivateKey
	Recovery    ed25519.PrivateKey
	Now         int64
	Seed        int64
	Counter     int
	Trace       []e.Event
	Mu          sync.Mutex
	Out         func(e.Event)
}

func New(o Options, out func(e.Event)) (*World, error) {
	if o.Validators < 1 || o.Validators > 100 || o.MaxLatency < o.MinLatency || o.MinLatency < 0 || o.MaxLatency > 10000 || o.FailureProbability < 0 || o.FailureProbability > 100 {
		return nil, errors.New("invalid simulator options")
	}
	c := p.Config{Version: 1, Epoch: 1, LogID: "qpk-demo", ApprovalQuorum: o.Quorum, FinalityQuorum: o.Finality, MaxByzantine: o.Byzantine, Members: []p.Member{}}
	ids := []e.Identity{}
	for i := 0; i < o.Validators; i++ {
		id := fmt.Sprintf("ca-%d", i+1)
		ident, err := e.IdentityFromSeed(id, Seed(id, o.Seed))
		if err != nil {
			return nil, err
		}
		ids = append(ids, ident)
		c.Members = append(c.Members, ident.Member(""))
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	w := &World{Owner: Key("owner", o.Seed), Recovery: Key("recovery", o.Seed), Now: 1800000000, Seed: o.Seed, Trace: []e.Event{}, Out: out}
	actors := map[string]e.Actor{}
	for _, id := range ids {
		mode := "honest"
		if contains(o.Malicious, id.ID) {
			mode = "malicious"
		}
		if contains(o.BadSignature, id.ID) {
			mode = "bad-signature"
		}
		if contains(o.Refuse, id.ID) {
			mode = "refuse"
		}
		a := &e.Authority{Identity: id, Config: c, OwnerKeys: map[string]string{"example.com": p.B64.EncodeToString(w.Owner.Public().(ed25519.PublicKey))}, RecoveryKeys: map[string]string{"example.com": p.B64.EncodeToString(w.Recovery.Public().(ed25519.PublicKey))}, Mode: mode}
		w.Authorities = append(w.Authorities, a)
		seed := Seed(id.ID+"/fault", o.Seed)
		delay := o.MinLatency + int(seed[0])*(o.MaxLatency-o.MinLatency)/255
		down := contains(o.Unavailable, id.ID) || contains(o.Partitions, id.ID) || int(seed[1])*100/256 < o.FailureProbability
		actors[id.ID] = &Actor{a, delay, down, o.Realtime}
	}
	w.Coordinator = &e.Coordinator{Config: c, Actors: actors, Emit: w.Emit, Stored: e.Stored{Entries: []p.Entry{}, Checkpoints: []p.Checkpoint{}}}
	return w, nil
}
func (w *World) Emit(ev e.Event) {
	w.Mu.Lock()
	w.Trace = append(w.Trace, ev)
	w.Mu.Unlock()
	if w.Out != nil {
		w.Out(ev)
	}
}
func (w *World) Request(event string, forged bool) e.Request {
	w.Counter++
	key := Key(fmt.Sprintf("key-%d", w.Counter), w.Seed)
	pr := p.Proposal{Version: 1, Epoch: 1, ConfigHash: w.Coordinator.Config.Hash(), Event: event, Subject: "example.com", Key: p.B64.EncodeToString(key.Public().(ed25519.PublicKey)), Generation: 1, Activate: w.Now, Retire: w.Now, Expires: w.Now + 86400, Nonce: fmt.Sprintf("demo-%020d", w.Counter)}
	ss, _ := e.States(w.Coordinator.Stored.Entries)
	if len(ss) > 0 {
		pr.Generation = ss[0].Generation + 1
		pr.Previous = ss[0].EntryHash
	}
	if event == "rotate" {
		pr.Activate = w.Now + 10
		pr.Retire = w.Now + 30
	}
	if event == "heartbeat" {
		pr.Generation--
		pr.Activate = 0
		pr.Retire = 0
		pr.Expires = 0
	}
	if event == "revoke" || event == "heartbeat" {
		pr.Key = ""
	}
	owner := w.Owner
	if forged {
		owner = Key("attacker", w.Seed)
	}
	recovery := event == "recover"
	if recovery {
		owner = w.Recovery
	}
	return e.Request{Proposal: pr, Owner: p.Sign(owner, "owner", "qpk-owner-v1", pr), Recovery: recovery}
}
func (w *World) Submit(ctx context.Context, event string, forged bool) (e.Bundle, error) {
	r := w.Request(event, forged)
	b, err := w.Coordinator.Submit(ctx, r, w.Now)
	if err != nil {
		w.Emit(e.Event{Kind: "error", Subject: "example.com", Message: err.Error(), Time: w.Now})
		return b, err
	}
	if err = e.VerifyBundle(b, w.Coordinator.Config, nil, "example.com", w.Now, 300); err == nil {
		w.Emit(e.Event{Kind: "verified", Subject: "example.com", Message: "light client verified quorum, X.509, log and current-state proofs", Time: w.Now})
	}
	return b, nil
}

// NormalizedTrace removes goroutine scheduling effects for deterministic export.
func (w *World) NormalizedTrace() []e.Event {
	w.Mu.Lock()
	defer w.Mu.Unlock()
	out := append([]e.Event{}, w.Trace...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Time != out[j].Time {
			return out[i].Time < out[j].Time
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Operator < out[j].Operator
	})
	for i := range out {
		out[i].Count = 0
	}
	return out
}

type Result struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

func Scenarios(out func(e.Event)) []Result {
	if out != nil {
		sink := out
		out = func(ev e.Event) { ev.Kind = "scenario/" + ev.Kind; sink(ev) }
	}

	rs := []Result{}
	add := func(n string, b bool, d string) { rs = append(rs, Result{n, b, d}) }
	ctx := context.Background()
	for _, n := range []int{0, 1, 2, 3} {
		o := Defaults()
		for i := 1; i <= n; i++ {
			o.Malicious = append(o.Malicious, fmt.Sprintf("ca-%d", i))
		}
		w, _ := New(o, out)
		_, err := w.Submit(ctx, "issue", n > 0)
		expected := n == 0 || n >= 3
		add(fmt.Sprintf("compromised-%d", n), (err == nil) == expected, fmt.Sprintf("3-of-5 approval: error=%v; >=3 malicious violates domain-validation assumption", err))
	}
	o := Defaults()
	o.Unavailable = []string{"ca-5"}
	w, _ := New(o, out)
	_, err := w.Submit(ctx, "issue", false)
	add("one-unavailable", err == nil, "four online satisfy both approval and finality")
	o.Unavailable = []string{"ca-4", "ca-5"}
	w, _ = New(o, out)
	_, err = w.Submit(ctx, "issue", false)
	add("two-unavailable", err != nil, "3 approvals are insufficient for 4 finality votes; fail closed")
	o = Defaults()
	o.BadSignature = []string{"ca-5"}
	w, _ = New(o, out)
	_, err = w.Submit(ctx, "issue", false)
	add("bad-signature", err == nil, "invalid vote discarded; remaining four suffice")
	w, _ = New(Defaults(), out)
	first, err := w.Submit(ctx, "issue", false)
	if err != nil {
		add("setup", false, err.Error())
		return rs
	}
	w.Now += 5
	rot, err := w.Submit(ctx, "rotate", false)
	if err != nil {
		add("rotation", false, err.Error())
		return rs
	}
	s := rot.State
	add("rotation", len(s.Keys(w.Now)) == 1 && len(s.Keys(w.Now+10)) == 2 && len(s.Keys(w.Now+30)) == 1, "scheduled -> overlap -> old key retired")
	err = e.VerifyBundle(first, w.Coordinator.Config, &rot.Checkpoint, "example.com", w.Now, 300)
	add("rollback", err != nil, fmt.Sprint(err))
	rot.Entry.Proposal.Key = p.B64.EncodeToString(Key("corrupt", 42).Public().(ed25519.PublicKey))
	err = e.VerifyBundle(rot, w.Coordinator.Config, nil, "example.com", w.Now, 300)
	add("corruption", err != nil, fmt.Sprint(err))
	w.Now += 40
	rev, err := w.Submit(ctx, "revoke", false)
	verify := e.VerifyBundle(rev, w.Coordinator.Config, nil, "example.com", w.Now, 300)
	add("revocation", err == nil && verify != nil, "revoked state proves absence of active keys")
	w.Now++
	rec, err := w.Submit(ctx, "recover", false)
	add("recovery", err == nil && len(rec.State.Keys(w.Now)) == 1, "separate preconfigured recovery key authorizes replacement") // Demonstrate authenticated fork evidence after finality assumption fails.
	cp := first.Checkpoint
	fork := cp
	fork.Head.Root = p.Hash("fork")
	fork.Votes = nil
	for _, a := range w.Authorities[:4] {
		fork.Votes = append(fork.Votes, p.Sign(a.Identity.Private(), a.Identity.ID, "qpk-checkpoint-v1", fork.Head))
	}
	err = e.Gossip(cp, fork, w.Coordinator.Config)
	add("split-view-evidence", err != nil, "four stolen keys produce a conflicting signed checkpoint; gossip exposes it")
	return rs
}
