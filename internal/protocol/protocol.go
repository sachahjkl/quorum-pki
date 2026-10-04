// Package protocol implements a deliberately restricted, ASCII/integer JCS profile.
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const Version = 1

var B64 = base64.RawURLEncoding
var domain = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

type Member struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Root string `json:"root"`
	URL  string `json:"url"`
}
type Config struct {
	Version        int      `json:"version"`
	Epoch          int      `json:"epoch"`
	LogID          string   `json:"logId"`
	ApprovalQuorum int      `json:"approvalQuorum"`
	FinalityQuorum int      `json:"finalityQuorum"`
	MaxByzantine   int      `json:"maxByzantine"`
	Members        []Member `json:"members"`
}

func (c Config) Validate() error {
	m := len(c.Members)
	if c.Version != 1 || c.Epoch < 1 || c.LogID == "" || c.ApprovalQuorum < 1 || c.ApprovalQuorum > m || c.MaxByzantine < 0 || c.ApprovalQuorum <= c.MaxByzantine || c.FinalityQuorum > m || 2*c.FinalityQuorum <= m+c.MaxByzantine {
		return errors.New("unsafe configuration")
	}
	seen := map[string]bool{}
	keys := map[string]bool{}
	for _, v := range c.Members {
		k, e := B64.DecodeString(v.Key)
		if e != nil || len(k) != 32 || seen[v.ID] || keys[v.Key] || v.ID == "" {
			return errors.New("duplicate or invalid member")
		}
		seen[v.ID] = true
		keys[v.Key] = true
	}
	return nil
}
func (c Config) Member(id string) (Member, bool) {
	for _, m := range c.Members {
		if m.ID == id {
			return m, true
		}
	}
	return Member{}, false
}
func (c Config) Hash() string { return Hash(c) }

type Proposal struct {
	Version    int    `json:"version"`
	Epoch      int    `json:"epoch"`
	ConfigHash string `json:"configHash"`
	Event      string `json:"event"`
	Subject    string `json:"subject"`
	Key        string `json:"key"`
	Generation int    `json:"generation"`
	Previous   string `json:"previous"`
	Activate   int64  `json:"activate"`
	Retire     int64  `json:"retire"`
	Expires    int64  `json:"expires"`
	Nonce      string `json:"nonce"`
}
type Signature struct {
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}
type Approval struct {
	Operator    string    `json:"operator"`
	Certificate string    `json:"certificate"`
	Vote        Signature `json:"vote"`
}
type Entry struct {
	Version   int        `json:"version"`
	Sequence  int        `json:"sequence"`
	Timestamp int64      `json:"timestamp"`
	Previous  string     `json:"previous"`
	Proposal  Proposal   `json:"proposal"`
	Approvals []Approval `json:"approvals"`
}
type State struct {
	Subject    string `json:"subject"`
	Generation int    `json:"generation"`
	EntryHash  string `json:"entryHash"`
	Key        string `json:"key"`
	OldKey     string `json:"oldKey"`
	Activate   int64  `json:"activate"`
	Retire     int64  `json:"retire"`
	Expires    int64  `json:"expires"`
	Revoked    bool   `json:"revoked"`
}
type Head struct {
	Version    int    `json:"version"`
	Epoch      int    `json:"epoch"`
	ConfigHash string `json:"configHash"`
	LogID      string `json:"logId"`
	Size       int    `json:"size"`
	Root       string `json:"root"`
	StateRoot  string `json:"stateRoot"`
	Timestamp  int64  `json:"timestamp"`
	Previous   string `json:"previous"`
}
type Checkpoint struct {
	Head  Head        `json:"head"`
	Votes []Signature `json:"votes"`
}

func (s State) Keys(now int64) []string {
	if s.Revoked || now >= s.Expires {
		return nil
	}
	if now < s.Activate {
		if s.OldKey != "" {
			return []string{s.OldKey}
		}
		return nil
	}
	if s.OldKey != "" && now < s.Retire {
		return []string{s.Key, s.OldKey}
	}
	return []string{s.Key}
}
func (s State) Phase(now int64) string {
	if s.Revoked {
		return "REVOKED"
	}
	if now >= s.Expires {
		return "RETIRED"
	}
	if now < s.Activate {
		return "SCHEDULED"
	}
	if s.OldKey != "" && now < s.Retire {
		return "GRACE"
	}
	return "ACTIVE"
}

// Canonical only accepts ASCII strings and JSON integers in the I-JSON safe range.
// This subset has exactly RFC 8785 bytes, without implementing float conversion.
func Canonical(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var x any
	if e = d.Decode(&x); e != nil {
		return nil, e
	}
	var out bytes.Buffer
	e = canon(&out, x)
	return out.Bytes(), e
}
func canon(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case json.Number:
		n, e := strconv.ParseInt(string(x), 10, 64)
		if e != nil || n > 9007199254740991 || n < -9007199254740991 {
			return errors.New("non-profile number")
		}
		b.WriteString(strconv.FormatInt(n, 10))
	case string:
		for _, r := range x {
			if r > 127 {
				return errors.New("non-ASCII string")
			}
		}
		var t bytes.Buffer
		enc := json.NewEncoder(&t)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(x)
		s := strings.TrimSuffix(t.String(), "\n")
		b.WriteString(s)
	case []any:
		b.WriteByte('[')
		for i, a := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if e := canon(b, a); e != nil {
				return e
			}
		}
		b.WriteByte(']')
	case map[string]any:
		ks := make([]string, 0, len(x))
		for k := range x {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		b.WriteByte('{')
		for i, k := range ks {
			if i > 0 {
				b.WriteByte(',')
			}
			if e := canon(b, k); e != nil {
				return e
			}
			b.WriteByte(':')
			if e := canon(b, x[k]); e != nil {
				return e
			}
		}
		b.WriteByte('}')
	default:
		return errors.New("unsupported JSON")
	}
	return nil
}
func Hash(v any) string {
	b, e := Canonical(v)
	if e != nil {
		panic(e)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func Bytes(v any) []byte {
	b, e := Canonical(v)
	if e != nil {
		panic(e)
	}
	return b
}

// Strict rejects duplicate object members, unknown members, floats, non-ASCII, and trailing data.
func Strict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e := walk(d); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	_, e := Canonical(v)
	return e
}
func walk(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return e
	}
	switch x := t.(type) {
	case json.Delim:
		if x == '{' {
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return errors.New("duplicate member")
				}
				seen[s] = true
				var b bytes.Buffer
				if e := canon(&b, s); e != nil {
					return e
				}
				if e := walk(d); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		}
		if x == '[' {
			for d.More() {
				if e := walk(d); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		}
		return errors.New("delimiter")
	default:
		var b bytes.Buffer
		return canon(&b, x)
	}
}
func Sign(key ed25519.PrivateKey, id, typ string, payload any) Signature {
	h := map[string]string{"alg": "EdDSA", "kid": id, "typ": typ}
	p := B64.EncodeToString(Bytes(h))
	input := p + "." + B64.EncodeToString(Bytes(payload))
	return Signature{p, B64.EncodeToString(ed25519.Sign(key, []byte(input)))}
}
func Verify(sig Signature, c Config, typ string, payload any) (string, error) {
	b, e := B64.DecodeString(sig.Protected)
	if e != nil {
		return "", e
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if e = Strict(b, &h); e != nil {
		return "", e
	}
	if h.Alg != "EdDSA" || h.Typ != typ {
		return "", errors.New("wrong signature context")
	}
	m, ok := c.Member(h.Kid)
	if !ok {
		return "", errors.New("unknown operator")
	}
	key, _ := B64.DecodeString(m.Key)
	s, e := B64.DecodeString(sig.Signature)
	if e != nil || len(key) != 32 {
		return "", errors.New("signature encoding")
	}
	input := sig.Protected + "." + B64.EncodeToString(Bytes(payload))
	if !ed25519.Verify(key, []byte(input), s) {
		return "", errors.New("invalid signature")
	}
	return h.Kid, nil
}
func VerifyVotes(v []Signature, c Config, typ string, p any, required int) error {
	seen := map[string]bool{}
	for _, s := range v {
		id, e := Verify(s, c, typ, p)
		if e != nil {
			return e
		}
		if seen[id] {
			return errors.New("duplicate vote")
		}
		seen[id] = true
	}
	if len(seen) < required {
		return errors.New("quorum not reached")
	}
	return nil
}
func CheckProposal(p Proposal, c Config, now int64) error {
	if p.Version != Version || p.Epoch != c.Epoch || p.ConfigHash != c.Hash() {
		return errors.New("wrong epoch/version")
	}
	if !domain.MatchString(p.Subject) || len(p.Subject) > 253 || strings.Contains(p.Subject, "..") || p.Generation < 1 || len(p.Nonce) < 16 || len(p.Nonce) > 128 {
		return errors.New("invalid subject/generation/nonce")
	}
	for _, label := range strings.Split(p.Subject, ".") {
		if len(label) > 63 || label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid DNS label")
		}
	}
	switch p.Event {
	case "issue", "rotate", "recover":
		k, e := B64.DecodeString(p.Key)
		if e != nil || len(k) != 32 {
			return errors.New("key must be Ed25519")
		}
		if p.Activate < now-60 || p.Expires <= p.Activate || p.Retire < p.Activate || p.Retire > p.Expires {
			return errors.New("invalid schedule")
		}
		if p.Event == "rotate" && p.Retire <= p.Activate {
			return errors.New("rotation requires overlap")
		}
	case "revoke", "heartbeat":
		if p.Key != "" {
			return errors.New("revocation key must be empty")
		}
	default:
		return fmt.Errorf("unknown event %q", p.Event)
	}
	return nil
}
func SPKI(key string) ([]byte, error) {
	b, e := B64.DecodeString(key)
	if e != nil || len(b) != 32 {
		return nil, errors.New("invalid key")
	}
	return x509.MarshalPKIXPublicKey(ed25519.PublicKey(b))
}
