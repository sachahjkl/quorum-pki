package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	e "quorum-pki/internal/engine"
	p "quorum-pki/internal/protocol"
	s "quorum-pki/internal/service"
	"time"
)

func main() {
	url := flag.String("url", "http://localhost:8083", "coordinator URL")
	dir := flag.String("data", "data", "fixture keys/config")
	subject := flag.String("subject", "example.com", "subject")
	event := flag.String("event", "issue", "issue/rotate/revoke/recover/heartbeat")
	flag.Parse()
	var config p.Config
	var owner e.Identity
	if err := s.Load(filepath.Join(*dir, "config.json"), &config); err != nil {
		log.Fatal(err)
	}
	ownerName := "owner"
	if *event == "recover" {
		ownerName = "recovery"
	}
	if err := s.Load(filepath.Join(*dir, ownerName+".json"), &owner); err != nil {
		log.Fatal(err)
	}
	now := time.Now().Unix()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	nonce := make([]byte, 24)
	_, _ = rand.Read(nonce)
	pr := p.Proposal{Version: 1, Epoch: config.Epoch, ConfigHash: config.Hash(), Event: *event, Subject: *subject, Key: p.B64.EncodeToString(pub), Generation: 1, Activate: now, Retire: now, Expires: now + 86400, Nonce: p.B64.EncodeToString(nonce)}
	if *event != "issue" {
		var prior e.Bundle
		if err = s.Call(context.Background(), *url+"/v1/subjects/"+*subject+"?known=0", nil, &prior); err != nil {
			log.Fatal(err)
		}
		if err = e.VerifyCheckpoint(prior.Checkpoint, config); err != nil {
			log.Fatal(err)
		}
		pr.Generation = prior.State.Generation + 1
		pr.Previous = prior.State.EntryHash
	}
	if *event == "rotate" {
		pr.Activate = now + 10
		pr.Retire = now + 30
	}
	if *event == "heartbeat" {
		pr.Generation--
		pr.Activate = 0
		pr.Retire = 0
		pr.Expires = 0
	}
	if *event == "revoke" || *event == "heartbeat" {
		pr.Key = ""
	}
	req := e.Request{Proposal: pr, Owner: p.Sign(owner.Private(), "owner", "qpk-owner-v1", pr), Recovery: *event == "recover"}
	if *event != "revoke" && *event != "heartbeat" {
		if err = e.AtomicWrite(filepath.Join(*dir, "subject-key-"+pr.Nonce+".json"), map[string]string{"key": p.B64.EncodeToString(key.Seed())}); err != nil {
			log.Fatal(err)
		}
	}
	if err = e.AtomicWrite(filepath.Join(*dir, "request-"+pr.Nonce+".json"), req); err != nil {
		log.Fatal(err)
	}
	var b e.Bundle
	if err = s.Call(context.Background(), *url+"/v1/subjects", req, &b); err != nil {
		log.Fatal(err)
	}
	if err = e.AtomicWrite(filepath.Join(*dir, "bundle.json"), b); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("FINALIZED %s generation=%d size=%d root=%s\n", *subject, b.State.Generation, b.Checkpoint.Head.Size, b.Checkpoint.Head.Root)
}
