package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	e "quorum-pki/internal/engine"
	p "quorum-pki/internal/protocol"
	s "quorum-pki/internal/service"
	"strings"
	"time"
)

func main() {
	role := flag.String("role", "validator", "init/validator/coordinator/registry/witness")
	id := flag.String("id", "ca-1", "operator")
	dir := flag.String("data", "data", "state directory")
	addr := flag.String("listen", ":8080", "listen address")
	registry := flag.String("registry", "http://localhost:8081", "registry URL")
	mode := flag.String("mode", "honest", "honest/malicious/refuse/bad-signature")
	urls := flag.String("urls", "http://localhost:8101,http://localhost:8102,http://localhost:8103,http://localhost:8104,http://localhost:8105", "validator URLs")
	flag.Parse()
	if *role == "init" {
		if err := s.Init(*dir, strings.Split(*urls, ",")); err != nil {
			log.Fatal(err)
		}
		return
	}
	var config p.Config
	if err := s.Load(filepath.Join(*dir, "config.json"), &config); err != nil {
		log.Fatal(err)
	}
	if err := config.Validate(); err != nil {
		log.Fatal(err)
	}
	var mux *http.ServeMux
	switch *role {
	case "validator":
		var ident e.Identity
		if err := s.Load(filepath.Join(*dir, *id+".json"), &ident); err != nil {
			log.Fatal(err)
		}
		a := &e.Authority{Identity: ident, Config: config, Path: filepath.Join(*dir, *id+"-lock.json"), Mode: *mode}
		if err := s.Load(filepath.Join(*dir, "owner-keys.json"), &a.OwnerKeys); err != nil {
			log.Fatal(err)
		}
		if err := s.Load(filepath.Join(*dir, "recovery-keys.json"), &a.RecoveryKeys); err != nil {
			log.Fatal(err)
		}
		if err := s.Load(a.Path, &a.Lock); err != nil && !os.IsNotExist(err) {
			log.Fatal(err)
		}
		mux = s.ValidatorMux(a)
	case "registry":
		rg := &s.Registry{Config: config, Path: filepath.Join(*dir, "registry.json"), Stored: e.Stored{Entries: []p.Entry{}, Checkpoints: []p.Checkpoint{}}}
		if err := s.Load(rg.Path, &rg.Stored); err != nil && !os.IsNotExist(err) {
			log.Fatal(err)
		}
		for i, cp := range rg.Stored.Checkpoints {
			parent := e.Genesis(config)
			if i > 0 {
				parent = rg.Stored.Checkpoints[i-1]
			}
			if err := e.VerifyCheckpoint(cp, config); err != nil {
				log.Fatal(err)
			}
			if err := e.VerifyCandidate(e.Candidate{Entries: rg.Stored.Entries[:i+1], Parent: parent, Head: cp.Head}, config); err != nil {
				log.Fatal(err)
			}
		}
		mux = rg.Mux()
	case "witness":
		wi := &e.Witness{Config: config, Path: filepath.Join(*dir, *id+"-witness.json")}
		if err := s.Load(wi.Path, &wi.Checkpoint); err != nil && !os.IsNotExist(err) {
			log.Fatal(err)
		}
		mux = s.WitnessMux(wi)
	case "coordinator":
		hub := s.NewHub()
		c := &e.Coordinator{Config: config, Actors: map[string]e.Actor{}, Emit: hub.Emit}
		for _, m := range config.Members {
			c.Actors[m.ID] = s.Remote{URL: m.URL}
		}
		if err := s.Call(context.Background(), *registry+"/v1/snapshot", nil, &c.Stored); err != nil {
			log.Fatal(err)
		}
		c.Commit = func(st e.Stored) error { return s.Call(context.Background(), *registry+"/v1/commit", st, nil) }
		mux = http.NewServeMux()
		mux.HandleFunc("POST /v1/subjects", func(w http.ResponseWriter, r *http.Request) {
			var req e.Request
			if err := s.Decode(w, r, &req); err != nil {
				s.Error(w, err)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
			defer cancel()
			b, err := c.Submit(ctx, req, time.Now().Unix())
			if err != nil {
				s.Error(w, err)
				return
			}
			s.JSON(w, b)
		})
		mux.HandleFunc("GET /v1/config", func(w http.ResponseWriter, r *http.Request) { s.JSON(w, config) })
		mux.HandleFunc("GET /v1/events", hub.SSE)
		mux.HandleFunc("GET /v1/subjects/{subject}", func(w http.ResponseWriter, r *http.Request) {
			var out e.Bundle
			url := *registry + "/v1/subjects/" + r.PathValue("subject") + "?known=" + r.URL.Query().Get("known")
			if err := s.Call(r.Context(), url, nil, &out); err != nil {
				s.Error(w, err)
				return
			}
			s.JSON(w, out)
		})
		mux.Handle("/", http.FileServer(http.Dir("web")))
	default:
		log.Fatalf("unknown role %s", *role)
	}
	fmt.Printf("%s %s listening on %s\n", *role, *id, *addr)
	server := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}
