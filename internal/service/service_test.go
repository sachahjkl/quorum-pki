package service

import (
	"context"
	"crypto/ed25519"
	"net/http/httptest"
	"path/filepath"
	e "quorum-pki/internal/engine"
	p "quorum-pki/internal/protocol"
	sim "quorum-pki/internal/simulation"
	"testing"
	"time"
)

func TestIndependentHTTPServices(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, []string{"a", "b", "c", "d", "e"}); err != nil {
		t.Fatal(err)
	}
	var cfg p.Config
	if err := Load(filepath.Join(dir, "config.json"), &cfg); err != nil {
		t.Fatal(err)
	}
	var owner e.Identity
	_ = Load(filepath.Join(dir, "owner.json"), &owner)
	var owners map[string]string
	_ = Load(filepath.Join(dir, "owner-keys.json"), &owners)
	actors := map[string]e.Actor{}
	for _, m := range cfg.Members {
		var id e.Identity
		_ = Load(filepath.Join(dir, m.ID+".json"), &id)
		a := &e.Authority{Identity: id, Config: cfg, OwnerKeys: owners, Mode: "honest", Path: filepath.Join(dir, m.ID+"-lock.json")}
		server := httptest.NewServer(ValidatorMux(a))
		defer server.Close()
		actors[m.ID] = Remote{server.URL}
	}
	rg := &Registry{Config: cfg, Stored: e.Stored{Entries: []p.Entry{}, Checkpoints: []p.Checkpoint{}}, Path: filepath.Join(dir, "journal.json")}
	registry := httptest.NewServer(rg.Mux())
	defer registry.Close()
	c := &e.Coordinator{Config: cfg, Actors: actors, Stored: rg.Stored, Commit: func(st e.Stored) error { return Call(context.Background(), registry.URL+"/v1/commit", st, nil) }}
	now := time.Now().Unix()
	pr := p.Proposal{Version: 1, Epoch: 1, ConfigHash: cfg.Hash(), Event: "issue", Subject: "example.com", Key: p.B64.EncodeToString(sim.Key("site", 99).Public().(ed25519.PublicKey)), Generation: 1, Activate: now, Retire: now, Expires: now + 3600, Nonce: "native-integration-001"}
	req := e.Request{Proposal: pr, Owner: p.Sign(owner.Private(), "owner", "qpk-owner-v1", pr)}
	if _, err := c.Submit(context.Background(), req, now); err != nil {
		t.Fatal(err)
	}
	var b e.Bundle
	if err := Call(context.Background(), registry.URL+"/v1/subjects/example.com?known=0", nil, &b); err != nil {
		t.Fatal(err)
	}
	if err := e.VerifyBundle(b, cfg, nil, "example.com", now, 300); err != nil {
		t.Fatal(err)
	}
	wit := &e.Witness{Config: cfg, Path: filepath.Join(dir, "witness.json")}
	wserver := httptest.NewServer(WitnessMux(wit))
	defer wserver.Close()
	ob := struct {
		Checkpoint  p.Checkpoint `json:"checkpoint"`
		Consistency []string     `json:"consistency"`
	}{b.Checkpoint, []string{}}
	if err := Call(context.Background(), wserver.URL+"/v1/observe", ob, nil); err != nil {
		t.Fatal(err)
	}
	var st e.Stored
	if err := Load(rg.Path, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Entries) != 1 {
		t.Fatal("journal not persisted")
	} // Registry cannot commit an unsigned or overwritten state.
	st.Entries[0].Proposal.Key = "forged"
	if err := Call(context.Background(), registry.URL+"/v1/commit", st, nil); err == nil {
		t.Fatal("forged rewrite accepted")
	}
}

func TestHubResetDropsOldReplayAndQueuedEvents(t *testing.T) {
	hub := NewHub()
	ch := make(chan e.Event, 3)
	hub.Subs[ch] = true
	hub.Emit(e.Event{Kind: "committed"})
	hub.Reset()
	if len(hub.History) != 0 || len(ch) != 0 {
		t.Fatal("old simulation events survived reset")
	}
	hub.Emit(e.Event{Kind: "reset"})
	if (<-ch).Kind != "reset" {
		t.Fatal("subscriber did not survive reset")
	}
}
