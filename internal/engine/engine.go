package engine

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	m "quorum-pki/internal/merkle"
	p "quorum-pki/internal/protocol"
	"sort"
	"sync"
	"time"
)

type Request struct {
	Proposal p.Proposal  `json:"proposal"`
	Owner    p.Signature `json:"owner"`
	Recovery bool        `json:"recovery"`
}
type Candidate struct {
	Entries []p.Entry    `json:"entries"`
	Parent  p.Checkpoint `json:"parent"`
	Head    p.Head       `json:"head"`
}
type Bundle struct {
	Entry       p.Entry      `json:"entry"`
	Checkpoint  p.Checkpoint `json:"checkpoint"`
	Inclusion   []string     `json:"inclusion"`
	State       p.State      `json:"state"`
	StateIndex  int          `json:"stateIndex"`
	StateCount  int          `json:"stateCount"`
	StateProof  []string     `json:"stateProof"`
	Consistency []string     `json:"consistency"`
}
type Stored struct {
	Entries     []p.Entry      `json:"entries"`
	Checkpoints []p.Checkpoint `json:"checkpoints"`
}

func Genesis(c p.Config) p.Checkpoint {
	return p.Checkpoint{Head: p.Head{Version: 1, Epoch: c.Epoch, ConfigHash: c.Hash(), LogID: c.LogID, Root: m.Root(nil).String(), StateRoot: m.Root(nil).String()}, Votes: []p.Signature{}}
}
func Leaves(es []p.Entry) []m.Hash {
	a := make([]m.Hash, 0, len(es))
	for _, e := range es {
		a = append(a, m.Leaf(p.Bytes(e)))
	}
	return a
}
func States(es []p.Entry) ([]p.State, error) {
	states := map[string]p.State{}
	for i, e := range es {
		if e.Version != 1 || e.Sequence != i+1 || e.Timestamp < 0 {
			return nil, errors.New("nonsequential entry")
		}
		if i == 0 && e.Previous != "" || i > 0 && e.Previous != p.Hash(es[i-1]) {
			return nil, errors.New("broken journal chain")
		}
		s, ok := states[e.Proposal.Subject]
		pr := e.Proposal
		if pr.Event == "heartbeat" {
			if !ok || pr.Generation != s.Generation || pr.Previous != s.EntryHash {
				return nil, errors.New("heartbeat requires current subject reference")
			}
			continue
		}
		if ok {
			if pr.Generation != s.Generation+1 || pr.Previous != s.EntryHash {
				return nil, errors.New("stale generation")
			}
			if pr.Event == "issue" {
				return nil, errors.New("subject already exists")
			}
			if pr.Event == "rotate" && (s.Revoked || e.Timestamp >= s.Expires || e.Timestamp < s.Retire || pr.Activate < s.Retire || pr.Retire > s.Expires || pr.Key == s.Key) {
				return nil, errors.New("unsafe rotation")
			}
		} else if pr.Event != "issue" || pr.Generation != 1 || pr.Previous != "" {
			return nil, errors.New("subject absent")
		}
		if pr.Event == "revoke" {
			s.Generation = pr.Generation
			s.EntryHash = p.Hash(e)
			s.Revoked = true
		} else {
			s = p.State{Subject: pr.Subject, Generation: pr.Generation, EntryHash: p.Hash(e), Key: pr.Key, Activate: pr.Activate, Retire: pr.Retire, Expires: pr.Expires}
			if ok && pr.Event == "rotate" {
				s.OldKey = states[pr.Subject].Key
			}
		}
		states[pr.Subject] = s
	}
	out := make([]p.State, 0, len(states))
	for _, s := range states {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out, nil
}
func StateLeaves(ss []p.State) []m.Hash {
	out := make([]m.Hash, 0, len(ss))
	for _, s := range ss {
		out = append(out, m.Leaf(p.Bytes(s)))
	}
	return out
}
func VerifyApprovals(e p.Entry, c p.Config) error { return verifyApprovals(e, c, c.ApprovalQuorum) }
func VerifyApproval(e p.Entry, c p.Config) error  { return verifyApprovals(e, c, 1) }
func verifyApprovals(e p.Entry, c p.Config, required int) error {
	if err := p.CheckProposal(e.Proposal, c, e.Timestamp); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, a := range e.Approvals {
		id, err := p.Verify(a.Vote, c, "qpk-approval-v1", e.Proposal)
		if err != nil {
			return err
		}
		if id != a.Operator || seen[id] {
			return errors.New("duplicate/mismatched approval")
		}
		seen[id] = true
		if e.Proposal.Event != "revoke" && e.Proposal.Event != "heartbeat" {
			member, _ := c.Member(id)
			rootDER, err := p.B64.DecodeString(member.Root)
			if err != nil {
				return err
			}
			root, err := x509.ParseCertificate(rootDER)
			if err != nil {
				return err
			}
			certDER, err := p.B64.DecodeString(a.Certificate)
			if err != nil {
				return err
			}
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			pool.AddCert(root)
			_, err = cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: e.Proposal.Subject, CurrentTime: time.Unix(e.Timestamp, 0), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			if err != nil {
				return err
			}
			spki, err := p.SPKI(e.Proposal.Key)
			if err != nil || string(spki) != string(cert.RawSubjectPublicKeyInfo) {
				return errors.New("certificate SPKI mismatch")
			}
			if cert.NotBefore.Unix() > e.Proposal.Activate || cert.NotAfter.Unix() < e.Proposal.Expires {
				return errors.New("certificate validity does not cover schedule")
			}
		} else if a.Certificate != "" {
			return errors.New("revocation must not carry certificate")
		}
	}
	if len(seen) < required {
		return errors.New("approval quorum missing")
	}
	return nil
}
func VerifyCheckpoint(cp p.Checkpoint, c p.Config) error {
	if cp.Head.Version != 1 || cp.Head.Epoch != c.Epoch || cp.Head.ConfigHash != c.Hash() || cp.Head.LogID != c.LogID || cp.Head.Size < 1 {
		return errors.New("invalid checkpoint domain")
	}
	return p.VerifyVotes(cp.Votes, c, "qpk-checkpoint-v1", cp.Head, c.FinalityQuorum)
}
func VerifyCandidate(x Candidate, c p.Config) error {
	if len(x.Entries) != x.Head.Size || x.Head.Size < 1 {
		return errors.New("candidate size mismatch")
	}
	for _, e := range x.Entries {
		if err := VerifyApprovals(e, c); err != nil {
			return err
		}
	}
	ss, err := States(x.Entries)
	if err != nil {
		return err
	}
	g := Genesis(c)
	if x.Parent.Head.Size == 0 {
		if p.Hash(x.Parent.Head) != p.Hash(g.Head) || len(x.Parent.Votes) != 0 {
			return errors.New("wrong genesis")
		}
	} else if err = VerifyCheckpoint(x.Parent, c); err != nil {
		return err
	}
	if x.Parent.Head.Size != x.Head.Size-1 || x.Head.Previous != p.Hash(x.Parent.Head) || x.Head.Timestamp < x.Parent.Head.Timestamp {
		return errors.New("parent mismatch")
	}
	prefix := x.Entries[:len(x.Entries)-1]
	ps, err := States(prefix)
	if err != nil {
		return err
	}
	if m.Root(Leaves(prefix)).String() != x.Parent.Head.Root || m.Root(StateLeaves(ps)).String() != x.Parent.Head.StateRoot {
		return errors.New("parent roots mismatch")
	}
	if x.Head.Root != m.Root(Leaves(x.Entries)).String() || x.Head.StateRoot != m.Root(StateLeaves(ss)).String() || x.Head.Timestamp != x.Entries[len(x.Entries)-1].Timestamp {
		return errors.New("candidate roots/time mismatch")
	}
	if x.Head.Version != 1 || x.Head.Epoch != c.Epoch || x.Head.ConfigHash != c.Hash() || x.Head.LogID != c.LogID {
		return errors.New("wrong candidate context")
	}
	return nil
}
func NewCandidate(st Stored, e p.Entry, c p.Config) (Candidate, error) {
	entries := append(append([]p.Entry{}, st.Entries...), e)
	ss, err := States(entries)
	if err != nil {
		return Candidate{}, err
	}
	parent := Genesis(c)
	if len(st.Checkpoints) > 0 {
		parent = st.Checkpoints[len(st.Checkpoints)-1]
	}
	h := p.Head{Version: 1, Epoch: c.Epoch, ConfigHash: c.Hash(), LogID: c.LogID, Size: len(entries), Root: m.Root(Leaves(entries)).String(), StateRoot: m.Root(StateLeaves(ss)).String(), Timestamp: e.Timestamp, Previous: p.Hash(parent.Head)}
	return Candidate{entries, parent, h}, nil
}
func MakeBundle(st Stored, subject string, known int) (Bundle, error) {
	ss, err := States(st.Entries)
	if err != nil {
		return Bundle{}, err
	}
	i := -1
	for j, s := range ss {
		if s.Subject == subject {
			i = j
		}
	}
	if i < 0 || len(st.Checkpoints) == 0 {
		return Bundle{}, errors.New("subject not found")
	}
	ei := -1
	for j, e := range st.Entries {
		if p.Hash(e) == ss[i].EntryHash {
			ei = j
		}
	}
	if ei < 0 || known < 0 || known > len(st.Entries) {
		return Bundle{}, errors.New("invalid proof request")
	}
	ls := Leaves(st.Entries)
	return Bundle{st.Entries[ei], st.Checkpoints[len(st.Checkpoints)-1], m.Strings(m.Inclusion(ls, ei)), ss[i], i, len(ss), m.Strings(m.Inclusion(StateLeaves(ss), i)), m.Strings(m.Consistency(ls, known))}, nil
}
func VerifyBundle(b Bundle, c p.Config, known *p.Checkpoint, subject string, now, maxAge int64) error {
	if err := VerifyCheckpoint(b.Checkpoint, c); err != nil {
		return err
	}
	h := b.Checkpoint.Head
	if h.Timestamp > now+5 || now-h.Timestamp > maxAge {
		return errors.New("stale/future checkpoint")
	}
	if err := VerifyApprovals(b.Entry, c); err != nil {
		return err
	}
	root, ok := m.Parse(h.Root)
	path, pok := m.Hashes(b.Inclusion)
	if !ok || !pok || !m.VerifyInclusion(m.Leaf(p.Bytes(b.Entry)), b.Entry.Sequence-1, h.Size, path, root) {
		return errors.New("invalid inclusion")
	}
	sr, ok := m.Parse(h.StateRoot)
	sp, pok := m.Hashes(b.StateProof)
	if !ok || !pok || !m.VerifyInclusion(m.Leaf(p.Bytes(b.State)), b.StateIndex, b.StateCount, sp, sr) {
		return errors.New("invalid current-state proof")
	}
	if b.State.Subject != subject || b.Entry.Proposal.Subject != subject || b.State.EntryHash != p.Hash(b.Entry) || b.State.Generation != b.Entry.Proposal.Generation {
		return errors.New("state/entry mismatch")
	}
	if known != nil {
		k := known.Head
		if h.Size < k.Size || h.Timestamp < k.Timestamp {
			return errors.New("rollback")
		}
		if h.Size == k.Size && p.Hash(h) != p.Hash(k) {
			return errors.New("equivocation")
		}
		old, ok := m.Parse(k.Root)
		path, pok := m.Hashes(b.Consistency)
		if !ok || !pok || !m.VerifyConsistency(k.Size, h.Size, old, root, path) {
			return errors.New("inconsistent history")
		}
	}
	if len(b.State.Keys(now)) == 0 {
		return errors.New("no active key (revoked, scheduled or expired)")
	}
	return nil
}

// AtomicWrite persists locks before releasing signatures. Directory fsync is best effort
// only on platforms without directory syncing; errors on file writes always fail closed.
func AtomicWrite(path string, v any) error {
	if path == "" {
		return nil
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

type Identity struct {
	ID   string `json:"id"`
	Seed string `json:"seed"`
	Root string `json:"root"`
}

func NewIdentity(id string) (Identity, error) {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	return IdentityFromSeed(id, k.Seed())
}
func IdentityFromSeed(id string, seed []byte) (Identity, error) {
	k := ed25519.NewKeyFromSeed(seed)
	t := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: id}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(4102444800, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, t, t, k.Public(), k)
	return Identity{id, p.B64.EncodeToString(seed), p.B64.EncodeToString(der)}, err
}
func (i Identity) Private() ed25519.PrivateKey {
	b, _ := p.B64.DecodeString(i.Seed)
	return ed25519.NewKeyFromSeed(b)
}
func (i Identity) Member(url string) p.Member {
	return p.Member{ID: i.ID, Key: p.B64.EncodeToString(i.Private().Public().(ed25519.PublicKey)), Root: i.Root, URL: url}
}

type Lock struct {
	Head p.Head `json:"head"`
}
type Authority struct {
	Mu           sync.Mutex
	Identity     Identity
	Config       p.Config
	OwnerKeys    map[string]string
	RecoveryKeys map[string]string
	Lock         Lock
	Path         string
	Mode         string
}

func (a *Authority) Approve(r Request, now int64) (p.Approval, error) {
	a.Mu.Lock()
	defer a.Mu.Unlock()
	if a.Mode == "refuse" {
		return p.Approval{}, errors.New("local refusal")
	}
	if err := p.CheckProposal(r.Proposal, a.Config, now); err != nil {
		return p.Approval{}, err
	}
	if a.Mode != "malicious" && a.Mode != "bad-signature" {
		keys := a.OwnerKeys
		if r.Proposal.Event == "recover" {
			keys = a.RecoveryKeys
			if !r.Recovery {
				return p.Approval{}, errors.New("recovery authorization missing")
			}
		}
		key, ok := keys[r.Proposal.Subject]
		if !ok {
			return p.Approval{}, errors.New("domain not in validation fixture")
		}
		c := p.Config{Members: []p.Member{{ID: "owner", Key: key}}}
		if _, err := p.Verify(r.Owner, c, "qpk-owner-v1", r.Proposal); err != nil {
			return p.Approval{}, errors.New("owner proof rejected")
		}
	}
	cert := ""
	if r.Proposal.Event != "revoke" && r.Proposal.Event != "heartbeat" {
		rootDER, _ := p.B64.DecodeString(a.Identity.Root)
		root, err := x509.ParseCertificate(rootDER)
		if err != nil {
			return p.Approval{}, err
		}
		key, _ := p.B64.DecodeString(r.Proposal.Key)
		serialHash := p.Hash(r.Proposal)
		serial := new(big.Int)
		serial.SetString(serialHash[:30], 16)
		t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: r.Proposal.Subject}, DNSNames: []string{r.Proposal.Subject}, NotBefore: time.Unix(r.Proposal.Activate-60, 0), NotAfter: time.Unix(r.Proposal.Expires, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
		der, err := x509.CreateCertificate(rand.Reader, t, root, ed25519.PublicKey(key), a.Identity.Private())
		if err != nil {
			return p.Approval{}, err
		}
		cert = p.B64.EncodeToString(der)
	}
	s := p.Sign(a.Identity.Private(), a.Identity.ID, "qpk-approval-v1", r.Proposal)
	if a.Mode == "bad-signature" {
		s.Signature = p.B64.EncodeToString(make([]byte, 64))
	}
	return p.Approval{Operator: a.Identity.ID, Certificate: cert, Vote: s}, nil
}
func (a *Authority) Notarize(x Candidate) (p.Signature, error) {
	a.Mu.Lock()
	defer a.Mu.Unlock()
	if a.Mode == "refuse" {
		return p.Signature{}, errors.New("local refusal")
	}
	if err := VerifyCandidate(x, a.Config); err != nil {
		return p.Signature{}, err
	}
	if a.Mode != "malicious" {
		old := a.Lock.Head
		if x.Head.Size < old.Size {
			return p.Signature{}, errors.New("rollback vote")
		}
		if x.Head.Size == old.Size && p.Hash(x.Head) != p.Hash(old) {
			return p.Signature{}, errors.New("conflicting vote locked")
		}
		if old.Size > 0 && x.Head.Size > old.Size {
			if m.Root(Leaves(x.Entries[:old.Size])).String() != old.Root {
				return p.Signature{}, errors.New("conflicting prefix")
			}
			if x.Parent.Head.Size == old.Size && p.Hash(x.Parent.Head) != p.Hash(old) {
				return p.Signature{}, errors.New("conflicting parent")
			}
		}
		lock := Lock{x.Head}
		if err := AtomicWrite(a.Path, lock); err != nil {
			return p.Signature{}, err
		}
		a.Lock = lock
	}
	s := p.Sign(a.Identity.Private(), a.Identity.ID, "qpk-checkpoint-v1", x.Head)
	if a.Mode == "bad-signature" {
		s.Signature = p.B64.EncodeToString(make([]byte, 64))
	}
	return s, nil
}

type Witness struct {
	Mu         sync.Mutex
	Config     p.Config
	Checkpoint p.Checkpoint
	Path       string
}

func (w *Witness) Observe(cp p.Checkpoint, proof []string) error {
	w.Mu.Lock()
	defer w.Mu.Unlock()
	if err := VerifyCheckpoint(cp, w.Config); err != nil {
		return err
	}
	if w.Checkpoint.Head.Size > 0 {
		old := w.Checkpoint.Head
		if cp.Head.Size < old.Size {
			return errors.New("witness rollback")
		}
		if cp.Head.Size == old.Size && p.Hash(cp.Head) != p.Hash(old) {
			return errors.New("witness equivocation evidence")
		}
		a, ok := m.Parse(old.Root)
		b, bok := m.Parse(cp.Head.Root)
		pr, pok := m.Hashes(proof)
		if !ok || !bok || !pok || !m.VerifyConsistency(old.Size, cp.Head.Size, a, b, pr) {
			return errors.New("witness inconsistent extension")
		}
	}
	if err := AtomicWrite(w.Path, cp); err != nil {
		return err
	}
	w.Checkpoint = cp
	return nil
}
func Gossip(a, b p.Checkpoint, c p.Config) error {
	if err := VerifyCheckpoint(a, c); err != nil {
		return err
	}
	if err := VerifyCheckpoint(b, c); err != nil {
		return err
	}
	if a.Head.Size == b.Head.Size && p.Hash(a.Head) != p.Hash(b.Head) {
		return fmt.Errorf("signed fork at size %d: %s / %s", a.Head.Size, a.Head.Root, b.Head.Root)
	}
	return nil
}
