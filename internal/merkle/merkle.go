// Package merkle implements RFC 9162 section 2.1 tree hashes and proofs.
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
)

type Hash [32]byte

func (h Hash) String() string { return hex.EncodeToString(h[:]) }
func Parse(s string) (Hash, bool) {
	var h Hash
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 {
		return h, false
	}
	copy(h[:], b)
	return h, true
}
func Leaf(b []byte) Hash { return sha256.Sum256(append([]byte{0}, b...)) }
func Node(l, r Hash) Hash {
	b := make([]byte, 65)
	b[0] = 1
	copy(b[1:], l[:])
	copy(b[33:], r[:])
	return sha256.Sum256(b)
}
func split(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}
func Root(leaves []Hash) Hash {
	n := len(leaves)
	if n == 0 {
		return sha256.Sum256(nil)
	}
	if n == 1 {
		return leaves[0]
	}
	k := split(n)
	return Node(Root(leaves[:k]), Root(leaves[k:]))
}
func Inclusion(a []Hash, i int) []Hash {
	if i < 0 || i >= len(a) {
		return nil
	}
	if len(a) == 1 {
		return []Hash{}
	}
	k := split(len(a))
	if i < k {
		return append(Inclusion(a[:k], i), Root(a[k:]))
	}
	return append(Inclusion(a[k:], i-k), Root(a[:k]))
}
func VerifyInclusion(leaf Hash, i, n int, proof []Hash, root Hash) bool {
	if n < 1 || i < 0 || i >= n {
		return false
	}
	pos := 0
	var rec func(int, int) (Hash, bool)
	rec = func(i, n int) (Hash, bool) {
		if n == 1 {
			return leaf, true
		}
		k := split(n)
		var child Hash
		var ok bool
		if i < k {
			child, ok = rec(i, k)
		} else {
			child, ok = rec(i-k, n-k)
		}
		if !ok || pos >= len(proof) {
			return Hash{}, false
		}
		s := proof[pos]
		pos++
		if i < k {
			return Node(child, s), true
		}
		return Node(s, child), true
	}
	h, ok := rec(i, n)
	return ok && pos == len(proof) && h == root
}
func Consistency(a []Hash, m int) []Hash {
	n := len(a)
	if m < 0 || m > n {
		return nil
	}
	if m == 0 || m == n {
		return []Hash{}
	}
	return sub(a, m, true)
}
func sub(a []Hash, m int, b bool) []Hash {
	if m == len(a) {
		if b {
			return []Hash{}
		}
		return []Hash{Root(a)}
	}
	k := split(len(a))
	if m <= k {
		return append(sub(a[:k], m, b), Root(a[k:]))
	}
	return append(sub(a[k:], m-k, false), Root(a[:k]))
}
func VerifyConsistency(m, n int, old, new Hash, p []Hash) bool {
	if m < 0 || n < m {
		return false
	}
	if m == 0 {
		return len(p) == 0 && old == Root(nil)
	}
	if m == n {
		return len(p) == 0 && old == new
	}
	if len(p) == 0 {
		return false
	}
	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	var fr, sr Hash
	start := 0
	if fn == 0 {
		fr = old
		sr = old
	} else {
		fr = p[0]
		sr = p[0]
		start = 1
	}
	for _, h := range p[start:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = Node(h, fr)
			sr = Node(h, sr)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = Node(sr, h)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && fr == old && sr == new
}
func Strings(p []Hash) []string {
	a := make([]string, 0, len(p))
	for _, h := range p {
		a = append(a, h.String())
	}
	return a
}
func Hashes(p []string) ([]Hash, bool) {
	a := make([]Hash, 0, len(p))
	for _, s := range p {
		h, ok := Parse(s)
		if !ok {
			return nil, false
		}
		a = append(a, h)
	}
	return a, true
}
