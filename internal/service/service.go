package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	e "quorum-pki/internal/engine"
	m "quorum-pki/internal/merkle"
	p "quorum-pki/internal/protocol"
	"strconv"
	"sync"
	"time"
)

var Client = &http.Client{Timeout: 5 * time.Second}

func Call(ctx context.Context, url string, in, out any) error {
	var body io.Reader
	if in != nil {
		body = &reader{b: p.Bytes(in)}
	}
	method := "GET"
	if in != nil {
		method = "POST"
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", url, b)
	}
	if out == nil {
		return nil
	}
	return p.Strict(b, out)
}

type reader struct{ b []byte }

func (r *reader) Read(b []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(b, r.b)
	r.b = r.b[n:]
	return n, nil
}
func Decode(w http.ResponseWriter, r *http.Request, v any) error {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
	if err != nil {
		return err
	}
	return p.Strict(b, v)
}
func JSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func Error(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(409)
	JSON(w, map[string]string{"error": err.Error()})
}
func Load(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return p.Strict(b, v)
}

type Remote struct{ URL string }

func (r Remote) Approve(ctx context.Context, in e.Request, n int64) (p.Approval, error) {
	var out p.Approval
	err := Call(ctx, r.URL+"/v1/approve", in, &out)
	return out, err
}
func (r Remote) Notarize(ctx context.Context, in e.Candidate) (p.Signature, error) {
	var out p.Signature
	err := Call(ctx, r.URL+"/v1/notarize", in, &out)
	return out, err
}

type Hub struct {
	Mu      sync.Mutex
	Subs    map[chan e.Event]bool
	History []e.Event
}

func NewHub() *Hub { return &Hub{Subs: map[chan e.Event]bool{}, History: []e.Event{}} }
func (h *Hub) Emit(ev e.Event) {
	h.Mu.Lock()
	defer h.Mu.Unlock()
	h.History = append(h.History, ev)
	if len(h.History) > 2000 {
		h.History = h.History[len(h.History)-2000:]
	}
	for ch := range h.Subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// Reset stops old simulation history from being replayed to reconnecting clients.
func (h *Hub) Reset() {
	h.Mu.Lock()
	defer h.Mu.Unlock()
	h.History = []e.Event{}
	for ch := range h.Subs {
	draining:
		for {
			select {
			case <-ch:
			default:
				break draining
			}
		}
	}
}
func (h *Hub) SSE(w http.ResponseWriter, r *http.Request) {
	f, ok := w.(http.Flusher)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch := make(chan e.Event, 256)
	h.Mu.Lock()
	history := append([]e.Event{}, h.History...)
	h.Subs[ch] = true
	h.Mu.Unlock()
	defer func() { h.Mu.Lock(); delete(h.Subs, ch); h.Mu.Unlock() }()
	send := func(ev e.Event) { b, _ := json.Marshal(ev); fmt.Fprintf(w, "data: %s\n\n", b); f.Flush() }
	for _, ev := range history {
		send(ev)
	}
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			send(ev)
		case <-tick.C:
			fmt.Fprint(w, ": keepalive\n\n")
			f.Flush()
		}
	}
}
func ValidatorMux(a *e.Authority) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/approve", func(w http.ResponseWriter, r *http.Request) {
		var in e.Request
		if err := Decode(w, r, &in); err != nil {
			Error(w, err)
			return
		}
		out, err := a.Approve(in, time.Now().Unix())
		if err != nil {
			Error(w, err)
			return
		}
		JSON(w, out)
	})
	mux.HandleFunc("POST /v1/notarize", func(w http.ResponseWriter, r *http.Request) {
		var in e.Candidate
		if err := Decode(w, r, &in); err != nil {
			Error(w, err)
			return
		}
		out, err := a.Notarize(in)
		if err != nil {
			Error(w, err)
			return
		}
		JSON(w, out)
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, map[string]string{"operator": a.Identity.ID, "mode": a.Mode})
	})
	return mux
}

type Registry struct {
	Mu     sync.Mutex
	Config p.Config
	Stored e.Stored
	Path   string
}

func (rg *Registry) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/commit", func(w http.ResponseWriter, r *http.Request) {
		var st e.Stored
		if err := Decode(w, r, &st); err != nil {
			Error(w, err)
			return
		}
		rg.Mu.Lock()
		defer rg.Mu.Unlock()
		n := len(st.Entries)
		if n != len(rg.Stored.Entries)+1 || len(st.Checkpoints) != n {
			Error(w, errors.New("append CAS failed"))
			return
		}
		for i := range rg.Stored.Entries {
			if p.Hash(st.Entries[i]) != p.Hash(rg.Stored.Entries[i]) || p.Hash(st.Checkpoints[i]) != p.Hash(rg.Stored.Checkpoints[i]) {
				Error(w, errors.New("prefix modified"))
				return
			}
		}
		parent := e.Genesis(rg.Config)
		if n > 1 {
			parent = st.Checkpoints[n-2]
		}
		cp := st.Checkpoints[n-1]
		if err := e.VerifyCheckpoint(cp, rg.Config); err != nil {
			Error(w, err)
			return
		}
		if err := e.VerifyCandidate(e.Candidate{Entries: st.Entries, Parent: parent, Head: cp.Head}, rg.Config); err != nil {
			Error(w, err)
			return
		}
		if err := e.AtomicWrite(rg.Path, st); err != nil {
			Error(w, err)
			return
		}
		rg.Stored = st
		JSON(w, map[string]string{"status": "committed"})
	})
	mux.HandleFunc("GET /v1/snapshot", func(w http.ResponseWriter, r *http.Request) { rg.Mu.Lock(); defer rg.Mu.Unlock(); JSON(w, rg.Stored) })
	mux.HandleFunc("GET /v1/checkpoint", func(w http.ResponseWriter, r *http.Request) {
		rg.Mu.Lock()
		defer rg.Mu.Unlock()
		if len(rg.Stored.Checkpoints) == 0 {
			JSON(w, e.Genesis(rg.Config))
			return
		}
		JSON(w, rg.Stored.Checkpoints[len(rg.Stored.Checkpoints)-1])
	})
	mux.HandleFunc("GET /v1/subjects/{subject}", func(w http.ResponseWriter, r *http.Request) {
		known, _ := strconv.Atoi(r.URL.Query().Get("known"))
		rg.Mu.Lock()
		defer rg.Mu.Unlock()
		out, err := e.MakeBundle(rg.Stored, r.PathValue("subject"), known)
		if err != nil {
			Error(w, err)
			return
		}
		JSON(w, out)
	})
	mux.HandleFunc("GET /v1/entries/{sequence}", func(w http.ResponseWriter, r *http.Request) {
		i, err := strconv.Atoi(r.PathValue("sequence"))
		rg.Mu.Lock()
		defer rg.Mu.Unlock()
		if err != nil || i < 1 || i > len(rg.Stored.Entries) {
			Error(w, errors.New("sequence out of range"))
			return
		}
		JSON(w, rg.Stored.Entries[i-1])
	})
	mux.HandleFunc("GET /v1/proofs/consistency", func(w http.ResponseWriter, r *http.Request) {
		from, err := strconv.Atoi(r.URL.Query().Get("from"))
		rg.Mu.Lock()
		defer rg.Mu.Unlock()
		to := len(rg.Stored.Entries)
		if err != nil || from < 0 || from > to {
			Error(w, errors.New("size out of range"))
			return
		}
		JSON(w, m.Strings(m.Consistency(e.Leaves(rg.Stored.Entries), from)))
	})
	mux.HandleFunc("GET /v1/proofs/inclusion/{sequence}", func(w http.ResponseWriter, r *http.Request) {
		i, err := strconv.Atoi(r.PathValue("sequence"))
		rg.Mu.Lock()
		defer rg.Mu.Unlock()
		if err != nil || i < 1 || i > len(rg.Stored.Entries) {
			Error(w, errors.New("sequence out of range"))
			return
		}
		JSON(w, m.Strings(m.Inclusion(e.Leaves(rg.Stored.Entries), i-1)))
	})
	return mux
}
func WitnessMux(wi *e.Witness) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/observe", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Checkpoint  p.Checkpoint `json:"checkpoint"`
			Consistency []string     `json:"consistency"`
		}
		if err := Decode(w, r, &in); err != nil {
			Error(w, err)
			return
		}
		if err := wi.Observe(in.Checkpoint, in.Consistency); err != nil {
			Error(w, err)
			return
		}
		JSON(w, map[string]string{"status": "consistent"})
	})
	mux.HandleFunc("POST /v1/gossip", func(w http.ResponseWriter, r *http.Request) {
		var other p.Checkpoint
		if err := Decode(w, r, &other); err != nil {
			Error(w, err)
			return
		}
		wi.Mu.Lock()
		own := wi.Checkpoint
		wi.Mu.Unlock()
		if err := e.Gossip(own, other, wi.Config); err != nil {
			Error(w, err)
			return
		}
		JSON(w, map[string]string{"status": "no same-size fork observed"})
	})
	mux.HandleFunc("GET /v1/checkpoint", func(w http.ResponseWriter, r *http.Request) {
		wi.Mu.Lock()
		defer wi.Mu.Unlock()
		JSON(w, wi.Checkpoint)
	})
	return mux
}
func Init(dir string, urls []string) error {
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err == nil {
		var existing p.Config
		if err := Load(filepath.Join(dir, "config.json"), &existing); err != nil {
			return err
		}
		if err := existing.Validate(); err != nil {
			return err
		}
		if len(existing.Members) != len(urls) {
			return errors.New("bootstrap existing member count differs")
		}
		for i, member := range existing.Members {
			var identity e.Identity
			if err := Load(filepath.Join(dir, member.ID+".json"), &identity); err != nil {
				return err
			}
			if p.Hash(identity.Member(urls[i])) != p.Hash(member) {
				return errors.New("bootstrap existing keys/URLs differ; refusing overwrite")
			}
		}
		for _, name := range []string{"owner", "recovery"} {
			var id e.Identity
			var keys map[string]string
			if err := Load(filepath.Join(dir, name+".json"), &id); err != nil {
				return err
			}
			if err := Load(filepath.Join(dir, name+"-keys.json"), &keys); err != nil {
				return err
			}
			if keys["example.com"] != id.Member("").Key {
				return errors.New("bootstrap owner fixture mismatch")
			}
		}
		return nil
	}
	config := p.Config{Version: 1, Epoch: 1, LogID: "qpk-native", ApprovalQuorum: 3, FinalityQuorum: 4, MaxByzantine: 1, Members: []p.Member{}}
	for i, url := range urls {
		id, err := e.NewIdentity(fmt.Sprintf("ca-%d", i+1))
		if err != nil {
			return err
		}
		config.Members = append(config.Members, id.Member(url))
		if err = e.AtomicWrite(filepath.Join(dir, id.ID+".json"), id); err != nil {
			return err
		}
	}
	if err := config.Validate(); err != nil {
		return err
	}
	for _, name := range []string{"owner", "recovery"} {
		id, err := e.NewIdentity(name)
		if err != nil {
			return err
		}
		if err = e.AtomicWrite(filepath.Join(dir, name+".json"), id); err != nil {
			return err
		}
		keys := map[string]string{"example.com": id.Member("").Key}
		if err = e.AtomicWrite(filepath.Join(dir, name+"-keys.json"), keys); err != nil {
			return err
		}
	}
	return e.AtomicWrite(filepath.Join(dir, "config.json"), config)
}
