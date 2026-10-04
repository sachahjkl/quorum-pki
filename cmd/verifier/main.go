package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	e "quorum-pki/internal/engine"
	p "quorum-pki/internal/protocol"
	s "quorum-pki/internal/service"
	"time"
)

func main() {
	url := flag.String("url", "http://localhost:8081", "registry")
	config := flag.String("config", "data/config.json", "PINNED trusted config")
	subject := flag.String("subject", "example.com", "DNS subject")
	path := flag.String("checkpoint", "client-checkpoint.json", "persistent local checkpoint")
	age := flag.Int64("max-age", 300, "maximum checkpoint age seconds")
	flag.Parse()
	var c p.Config
	if err := s.Load(*config, &c); err != nil {
		log.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		log.Fatal(err)
	}
	var known *p.Checkpoint
	var cp p.Checkpoint
	if err := s.Load(*path, &cp); err == nil {
		if err = e.VerifyCheckpoint(cp, c); err != nil {
			log.Fatal(err)
		}
		known = &cp
	} else if !os.IsNotExist(err) {
		log.Fatal(err)
	}
	size := 0
	if known != nil {
		size = known.Head.Size
	}
	var b e.Bundle
	if err := s.Call(context.Background(), fmt.Sprintf("%s/v1/subjects/%s?known=%d", *url, *subject, size), nil, &b); err != nil {
		log.Fatal(err)
	}
	if err := e.VerifyBundle(b, c, known, *subject, time.Now().Unix(), *age); err != nil {
		log.Fatal(err)
	}
	if err := e.AtomicWrite(*path, b.Checkpoint); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("VERIFIED %s generation=%d phase=%s keys=%v size=%d root=%s\n", *subject, b.State.Generation, b.State.Phase(time.Now().Unix()), b.State.Keys(time.Now().Unix()), b.Checkpoint.Head.Size, b.Checkpoint.Head.Root)
}
