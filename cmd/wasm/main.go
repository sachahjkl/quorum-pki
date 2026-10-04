//go:build js && wasm

package main

import (
	"context"
	"encoding/json"
	e "quorum-pki/internal/engine"
	p "quorum-pki/internal/protocol"
	sim "quorum-pki/internal/simulation"
	"sync"
	"syscall/js"
)

var world *sim.World
var mu sync.Mutex

func emit(ev e.Event) {
	js.Global().Call("postMessage", map[string]any{"type": "event", "data": string(p.Bytes(ev))})
}
func main() {
	o := sim.Defaults()
	world, _ = sim.New(o, emit)
	cb := js.FuncOf(func(this js.Value, args []js.Value) any {
		raw := args[0].Get("data").String()
		go func() {
			mu.Lock()
			defer mu.Unlock()
			var req struct {
				Action  string      `json:"action"`
				Event   string      `json:"event"`
				Forged  bool        `json:"forged"`
				Seconds int64       `json:"seconds"`
				Options sim.Options `json:"options"`
			}
			if err := p.Strict([]byte(raw), &req); err != nil {
				reply(nil, err.Error())
				return
			}
			switch req.Action {
			case "reset":
				w, err := sim.New(req.Options, emit)
				if err != nil {
					reply(nil, err.Error())
					return
				}
				world = w
				reply(world.Coordinator.Config, "")
			case "submit":
				b, err := world.Submit(context.Background(), req.Event, req.Forged)
				if err != nil {
					reply(nil, err.Error())
					return
				}
				reply(b, "")
			case "tick":
				if req.Seconds < 0 || req.Seconds > 86400 {
					reply(nil, "invalid clock delta")
					return
				}
				world.Now += req.Seconds
				ss, _ := e.States(world.Coordinator.Stored.Entries)
				for _, s := range ss {
					emit(e.Event{Kind: "phase", Subject: s.Subject, Message: s.Phase(world.Now), Count: len(s.Keys(world.Now)), Time: world.Now})
				}
				reply(ss, "")
			case "scenarios":
				reply(sim.Scenarios(emit), "")
			case "trace":
				reply(world.NormalizedTrace(), "")
			default:
				reply(nil, "unknown action")
			}
		}()
		return nil
	})
	js.Global().Set("onmessage", cb)
	js.Global().Call("postMessage", map[string]any{"type": "ready"})
	select {}
}
func reply(v any, err string) {
	b, _ := json.Marshal(v)
	js.Global().Call("postMessage", map[string]any{"type": "result", "data": string(b), "error": err})
}
