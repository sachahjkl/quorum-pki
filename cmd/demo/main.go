package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	e "quorum-pki/internal/engine"
	s "quorum-pki/internal/service"
	sim "quorum-pki/internal/simulation"
	"sync"
	"time"
)

func main() {
	check := flag.Bool("check", false, "run automatic adversarial scenarios")
	export := flag.String("export", "", "export deterministic fixture directory")
	addr := flag.String("listen", ":8080", "listen address")
	flag.Parse()
	if *export != "" {
		w, err := sim.New(sim.Defaults(), nil)
		if err != nil {
			log.Fatal(err)
		}
		b, err := w.Submit(context.Background(), "issue", false)
		if err != nil {
			log.Fatal(err)
		}
		for name, v := range map[string]any{"bundle.json": b, "config.json": w.Coordinator.Config, "trace.json": w.NormalizedTrace()} {
			if err := e.AtomicWrite(*export+"/"+name, v); err != nil {
				log.Fatal(err)
			}
		}
		return
	}
	if *check {
		rs := sim.Scenarios(nil)
		failed := false
		for _, r := range rs {
			fmt.Printf("%t %-25s %s\n", r.Passed, r.Name, r.Detail)
			if !r.Passed {
				failed = true
			}
		}
		if failed {
			log.Fatal("scenario failure")
		}
		return
	}
	hub := s.NewHub()
	var mu sync.Mutex
	o := sim.Defaults()
	o.Realtime = true
	world, err := sim.New(o, hub.Emit)
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/events", hub.SSE)
	mux.HandleFunc("GET /v1/config", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		s.JSON(w, world.Coordinator.Config)
	})
	mux.HandleFunc("POST /v1/simulation", func(w http.ResponseWriter, r *http.Request) {
		var opts sim.Options
		if err := s.Decode(w, r, &opts); err != nil {
			s.Error(w, err)
			return
		}
		newWorld, err := sim.New(opts, hub.Emit)
		if err != nil {
			s.Error(w, err)
			return
		}
		mu.Lock()
		world = newWorld
		hub.Reset()
		mu.Unlock()
		hub.Emit(e.Event{Kind: "reset", Message: "new independent simulator; checkpoints from old configuration are not transferable"})
		s.JSON(w, newWorld.Coordinator.Config)
	})
	mux.HandleFunc("POST /v1/subjects", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Event  string `json:"event"`
			Forged bool   `json:"forged"`
		}
		if err := s.Decode(w, r, &in); err != nil {
			s.Error(w, err)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		b, err := world.Submit(ctx, in.Event, in.Forged)
		if err != nil {
			s.Error(w, err)
			return
		}
		s.JSON(w, b)
	})
	mux.HandleFunc("POST /v1/tick", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Seconds int64 `json:"seconds"`
		}
		if err := s.Decode(w, r, &in); err != nil || in.Seconds < 0 || in.Seconds > 86400 {
			s.Error(w, fmt.Errorf("invalid clock delta"))
			return
		}
		mu.Lock()
		defer mu.Unlock()
		world.Now += in.Seconds
		states, _ := e.States(world.Coordinator.Stored.Entries)
		for _, st := range states {
			hub.Emit(e.Event{Kind: "phase", Subject: st.Subject, Message: st.Phase(world.Now), Count: len(st.Keys(world.Now)), Time: world.Now})
		}
		s.JSON(w, map[string]int64{"now": world.Now})
	})
	mux.HandleFunc("GET /v1/subjects/{subject}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		b, err := e.MakeBundle(world.Coordinator.Stored, r.PathValue("subject"), 0)
		if err != nil {
			s.Error(w, err)
			return
		}
		s.JSON(w, b)
	})
	mux.HandleFunc("GET /v1/snapshot", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		s.JSON(w, world.Coordinator.Stored)
	})
	mux.HandleFunc("GET /v1/trace", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		s.JSON(w, world.NormalizedTrace())
	})
	mux.HandleFunc("POST /v1/scenarios", func(w http.ResponseWriter, r *http.Request) { s.JSON(w, sim.Scenarios(hub.Emit)) })
	mux.Handle("/", http.FileServer(http.Dir("web")))
	fmt.Printf("Quorum PKI demo listening on %s (open http://localhost:8080 for default port)\n", *addr)
	log.Fatal((&http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
}
