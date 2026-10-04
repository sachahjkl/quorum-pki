package simulation

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	e "quorum-pki/internal/engine"
	p "quorum-pki/internal/protocol"
	"strings"
	"testing"
)

func TestScenarios(t *testing.T) {
	for _, r := range Scenarios(nil) {
		t.Run(r.Name, func(t *testing.T) {
			if !r.Passed {
				t.Fatal(r.Detail)
			}
		})
	}
}
func TestLocksSurviveRestart(t *testing.T) {
	w, _ := New(Defaults(), nil)
	ctx := context.Background()
	_, err := w.Submit(ctx, "issue", false)
	if err != nil {
		t.Fatal(err)
	}
	a := w.Authorities[0]
	a.Path = t.TempDir() + "/lock.json"
	if err = e.AtomicWrite(a.Path, a.Lock); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(a.Path)
	var lock e.Lock
	if err = p.Strict(raw, &lock); err != nil {
		t.Fatal(err)
	}
	a.Lock = lock
	fork := w.Coordinator.Stored.Entries[0]
	fork.Proposal.Nonce = "another-valid-nonce-0001"
	fork.Approvals = nil
	for _, actor := range w.Authorities {
		r := e.Request{Proposal: fork.Proposal, Owner: p.Sign(w.Owner, "owner", "qpk-owner-v1", fork.Proposal)}
		sig, err := actor.Approve(r, w.Now)
		if err != nil {
			t.Fatal(err)
		}
		fork.Approvals = append(fork.Approvals, sig)
	}
	candidate, err := e.NewCandidate(e.Stored{}, fork, w.Coordinator.Config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Notarize(candidate); err == nil {
		t.Fatal("durable conflicting vote accepted")
	}
}
func TestFreshnessAndState(t *testing.T) {
	w, _ := New(Defaults(), nil)
	b, err := w.Submit(context.Background(), "issue", false)
	if err != nil {
		t.Fatal(err)
	}
	c := w.Coordinator.Config
	if e.VerifyBundle(b, c, nil, "example.com", w.Now+301, 300) == nil {
		t.Fatal("stale checkpoint")
	}
	b.State.Key = p.B64.EncodeToString(Key("fake", 42).Public().(ed25519.PublicKey))
	if e.VerifyBundle(b, c, nil, "example.com", w.Now, 300) == nil {
		t.Fatal("tampered current key")
	}
}
func TestCurrentStateProof(t *testing.T) {
	w, _ := New(Defaults(), nil)
	first, err := w.Submit(context.Background(), "issue", false)
	if err != nil {
		t.Fatal(err)
	}
	w.Now += 5
	rot, err := w.Submit(context.Background(), "rotate", false)
	if err != nil {
		t.Fatal(err)
	}
	rot.State = first.State
	if e.VerifyBundle(rot, w.Coordinator.Config, nil, "example.com", w.Now, 300) == nil {
		t.Fatal("old state at new checkpoint")
	}
}
func TestNoThirdKeyDuringOverlap(t *testing.T) {
	w, _ := New(Defaults(), nil)
	_, _ = w.Submit(context.Background(), "issue", false)
	w.Now += 5
	_, err := w.Submit(context.Background(), "rotate", false)
	if err != nil {
		t.Fatal(err)
	}
	w.Now++
	_, err = w.Submit(context.Background(), "rotate", false)
	if err == nil {
		t.Fatal("pending rotation overwritten")
	}
}
func TestQuorumByzantineSafety(t *testing.T) {
	for n := 1; n <= 2; n++ {
		o := Defaults()
		for i := 1; i <= n; i++ {
			o.Malicious = append(o.Malicious, fmt.Sprintf("ca-%d", i))
		}
		w, _ := New(o, nil)
		if _, err := w.Submit(context.Background(), "issue", true); err == nil {
			t.Fatal("forgery below approval threshold")
		}
	}
}
func BenchmarkQuorum(b *testing.B) {
	for _, n := range []int{5, 10, 50, 100} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				o := Defaults()
				o.Validators = n
				o.Byzantine = (n - 1) / 3
				o.Quorum = n/2 + 1
				o.Finality = (n+o.Byzantine)/2 + 1
				w, err := New(o, nil)
				if err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				if _, err = w.Submit(context.Background(), "issue", false); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
func BenchmarkClient(b *testing.B) {
	w, _ := New(Defaults(), nil)
	proof, err := w.Submit(context.Background(), "issue", false)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportMetric(float64(len(p.Bytes(proof))), "bundle-bytes")
	for i := 0; i < b.N; i++ {
		if err := e.VerifyBundle(proof, w.Coordinator.Config, nil, "example.com", w.Now, 300); err != nil {
			b.Fatal(err)
		}
	}
}

func TestHeartbeatRefreshesWithoutExtendingKeys(t *testing.T) {
	w, _ := New(Defaults(), nil)
	first, err := w.Submit(context.Background(), "issue", false)
	if err != nil {
		t.Fatal(err)
	}
	w.Now += 301
	if e.VerifyBundle(first, w.Coordinator.Config, nil, "example.com", w.Now, 300) == nil {
		t.Fatal("old checkpoint remains fresh")
	}
	fresh, err := w.Submit(context.Background(), "heartbeat", false)
	if err != nil {
		t.Fatal(err)
	}
	if p.Hash(first.State) != p.Hash(fresh.State) || first.Checkpoint.Head.StateRoot != fresh.Checkpoint.Head.StateRoot {
		t.Fatal("heartbeat altered authorization")
	}
	if fresh.Checkpoint.Head.Size != 2 || fresh.Checkpoint.Head.Root == first.Checkpoint.Head.Root {
		t.Fatal("heartbeat not appended")
	}
	fresh, err = e.MakeBundle(w.Coordinator.Stored, "example.com", first.Checkpoint.Head.Size)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.VerifyBundle(fresh, w.Coordinator.Config, &first.Checkpoint, "example.com", w.Now, 300); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkSequentialWrites(b *testing.B) {
	w, _ := New(Defaults(), nil)
	if _, err := w.Submit(context.Background(), "issue", false); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Now++
		if _, err := w.Submit(context.Background(), "heartbeat", false); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "writes/s")
}

func TestSevenOperatorsTolerateTwoSilent(t *testing.T) {
	o := Defaults()
	o.Validators = 7
	o.Quorum = 5
	o.Finality = 5
	o.Byzantine = 2
	o.Unavailable = []string{"ca-1", "ca-2"}
	w, err := New(o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Submit(context.Background(), "issue", false); err != nil {
		t.Fatal(err)
	}
	o.Unavailable = nil
	o.Malicious = []string{"ca-1", "ca-2"}
	w, err = New(o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Submit(context.Background(), "issue", true); err == nil {
		t.Fatal("two Byzantine operators forged 5-of-7 binding")
	}
}

func TestScenarioEventsAreIsolated(t *testing.T) {
	count := 0
	results := Scenarios(func(ev e.Event) {
		count++
		if !strings.HasPrefix(ev.Kind, "scenario/") {
			t.Errorf("unscoped scenario event: %s", ev.Kind)
		}
	})
	if count == 0 || len(results) != 13 {
		t.Fatal("scenario emission missing")
	}
}
