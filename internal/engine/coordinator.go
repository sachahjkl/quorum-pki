package engine

import (
	"context"
	"errors"
	"fmt"
	p "quorum-pki/internal/protocol"
	"sort"
	"sync"
)

type Actor interface {
	Approve(context.Context, Request, int64) (p.Approval, error)
	Notarize(context.Context, Candidate) (p.Signature, error)
}
type Event struct {
	Kind     string  `json:"kind"`
	Operator string  `json:"operator"`
	Subject  string  `json:"subject"`
	Message  string  `json:"message"`
	Count    int     `json:"count"`
	Required int     `json:"required"`
	Head     *p.Head `json:"head"`
	Time     int64   `json:"time"`
}
type Coordinator struct {
	Mu     sync.Mutex
	Config p.Config
	Actors map[string]Actor
	Stored Stored
	Path   string
	Emit   func(Event)
	Commit func(Stored) error
}

func (c *Coordinator) emit(e Event) {
	if c.Emit != nil {
		c.Emit(e)
	}
}
func (c *Coordinator) Submit(ctx context.Context, r Request, now int64) (Bundle, error) {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	pr := r.Proposal
	if err := p.CheckProposal(pr, c.Config, now); err != nil {
		return Bundle{}, err
	}
	c.emit(Event{Kind: "proposed", Subject: pr.Subject, Message: pr.Event, Time: now, Required: c.Config.ApprovalQuorum})
	type ar struct {
		id string
		a  p.Approval
		e  error
	}
	ch := make(chan ar, len(c.Config.Members))
	for _, member := range c.Config.Members {
		go func(id string) {
			actor := c.Actors[id]
			if actor == nil {
				ch <- ar{id: id, e: errors.New("unavailable")}
				return
			}
			a, e := actor.Approve(ctx, r, now)
			ch <- ar{id, a, e}
		}(member.ID)
	}
	as := []p.Approval{}
	remaining := len(c.Config.Members)
	for remaining > 0 {
		select {
		case <-ctx.Done():
			return Bundle{}, ctx.Err()
		case result := <-ch:
			remaining--
			e := result.e
			if e == nil {
				if result.a.Operator != result.id {
					e = errors.New("operator mismatch")
				} else {
					e = VerifyApproval(p.Entry{Timestamp: now, Proposal: pr, Approvals: []p.Approval{result.a}}, c.Config)
				}
			}
			kind := "signed"
			if e != nil {
				kind = "rejected"
			} else {
				as = append(as, result.a)
			}
			message := "verified approval"
			if e != nil {
				message = e.Error()
			}
			c.emit(Event{Kind: kind, Operator: result.id, Subject: pr.Subject, Message: message, Count: len(as), Required: c.Config.ApprovalQuorum, Time: now})

		}
	}
	if len(as) < c.Config.ApprovalQuorum {
		return Bundle{}, errors.New("approval quorum impossible")
	}
	sort.Slice(as, func(i, j int) bool { return as[i].Operator < as[j].Operator })
	prev := ""
	if len(c.Stored.Entries) > 0 {
		prev = p.Hash(c.Stored.Entries[len(c.Stored.Entries)-1])
	}
	entry := p.Entry{Version: 1, Sequence: len(c.Stored.Entries) + 1, Timestamp: now, Previous: prev, Proposal: pr, Approvals: as}
	if err := VerifyApprovals(entry, c.Config); err != nil {
		return Bundle{}, err
	}
	candidate, err := NewCandidate(c.Stored, entry, c.Config)
	if err != nil {
		return Bundle{}, err
	}
	c.emit(Event{Kind: "approved", Subject: pr.Subject, Count: len(as), Required: c.Config.ApprovalQuorum, Time: now})
	type vr struct {
		id string
		s  p.Signature
		e  error
	}
	vc := make(chan vr, len(c.Config.Members))
	for _, member := range c.Config.Members {
		go func(id string) {
			actor := c.Actors[id]
			if actor == nil {
				vc <- vr{id: id, e: errors.New("unavailable")}
				return
			}
			s, e := actor.Notarize(ctx, candidate)
			vc <- vr{id, s, e}
		}(member.ID)
	}
	votes := []p.Signature{}
	remaining = len(c.Config.Members)
	for remaining > 0 {
		select {
		case <-ctx.Done():
			return Bundle{}, ctx.Err()
		case result := <-vc:
			remaining--
			e := result.e
			if e == nil {
				id, err := p.Verify(result.s, c.Config, "qpk-checkpoint-v1", candidate.Head)
				if err != nil || id != result.id {
					e = errors.New("invalid finality vote")
				}
			}
			message := "checkpoint signed"
			kind := "finality-vote"
			if e != nil {
				message = e.Error()
				kind = "error"
			} else {
				votes = append(votes, result.s)
			}
			c.emit(Event{Kind: kind, Operator: result.id, Subject: pr.Subject, Message: message, Count: len(votes), Required: c.Config.FinalityQuorum, Time: now})

		}
	}
	cp := p.Checkpoint{Head: candidate.Head, Votes: votes}
	if err := VerifyCheckpoint(cp, c.Config); err != nil {
		return Bundle{}, err
	}
	st := Stored{Entries: candidate.Entries, Checkpoints: append(append([]p.Checkpoint{}, c.Stored.Checkpoints...), cp)}
	if c.Commit != nil {
		if err := c.Commit(st); err != nil {
			return Bundle{}, err
		}
	}
	if err := AtomicWrite(c.Path, st); err != nil {
		return Bundle{}, err
	}
	c.Stored = st
	c.emit(Event{Kind: "committed", Subject: pr.Subject, Message: fmt.Sprintf("entry #%d", entry.Sequence), Count: len(votes), Required: c.Config.FinalityQuorum, Head: &cp.Head, Time: now})
	return MakeBundle(st, pr.Subject, 0)
}
