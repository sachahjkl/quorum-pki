package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestCanonical(t *testing.T) {
	b, e := Canonical(map[string]any{"z": 1, "a": "<>&\n", "list": []int{1, 2}})
	if e != nil || string(b) != `{"a":"<>&\n","list":[1,2],"z":1}` {
		t.Fatalf("%s %v", b, e)
	}
	for _, in := range []string{`{"x":1,"x":2}`, `{"x":1} {}`, `{"x":1.5}`, `{"x":1e2}`, `{"x":"\ud800"}`, `{"x":"é"}`, `{"x":9007199254740992}`, `{"y":1}`} {
		var v struct {
			X any `json:"x"`
		}
		if Strict([]byte(in), &v) == nil {
			t.Fatalf("accepted %s", in)
		}
	}
}
func TestSignatures(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	c := Config{Members: []Member{{ID: "a", Key: B64.EncodeToString(pub)}}}
	sig := Sign(key, "a", "test", map[string]int{"x": 1})
	if _, e := Verify(sig, c, "test", map[string]int{"x": 1}); e != nil {
		t.Fatal(e)
	}
	if _, e := Verify(sig, c, "other", map[string]int{"x": 1}); e == nil {
		t.Fatal("cross-context replay")
	}
	if _, e := Verify(sig, c, "test", map[string]int{"x": 2}); e == nil {
		t.Fatal("tamper")
	}
	if VerifyVotes([]Signature{sig, sig}, c, "test", map[string]int{"x": 1}, 2) == nil {
		t.Fatal("duplicate counted")
	}
}
func TestIntersection(t *testing.T) {
	for _, tc := range []struct {
		n, q, f int
		safe    bool
	}{{5, 3, 1, false}, {5, 4, 1, true}, {5, 4, 2, true}, {7, 5, 2, true}, {7, 4, 2, false}} {
		c := Config{Version: 1, Epoch: 1, LogID: "x", ApprovalQuorum: 3, FinalityQuorum: tc.q, MaxByzantine: tc.f}
		for i := 0; i < tc.n; i++ {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			c.Members = append(c.Members, Member{ID: string(rune('a' + i)), Key: B64.EncodeToString(pub)})
		}
		if (c.Validate() == nil) != tc.safe {
			t.Fatalf("%+v", tc)
		}
	}
}
func BenchmarkSignature(b *testing.B) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	c := Config{Members: []Member{{ID: "a", Key: B64.EncodeToString(pub)}}}
	payload := map[string]int{"version": 1}
	sig := Sign(key, "a", "test", payload)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, e := Verify(sig, c, "test", payload); e != nil {
			b.Fatal(e)
		}
	}
}
