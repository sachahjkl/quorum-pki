package merkle

import (
	"fmt"
	"testing"
)

func TestAllProofs(t *testing.T) {
	for n := 1; n <= 128; n++ {
		a := make([]Hash, n)
		for i := range a {
			a[i] = Leaf([]byte(fmt.Sprint(i)))
		}
		root := Root(a)
		for i := range a {
			p := Inclusion(a, i)
			if !VerifyInclusion(a[i], i, n, p, root) {
				t.Fatalf("inclusion %d/%d", i, n)
			}
			if len(p) > 0 {
				p[0][0] ^= 1
				if VerifyInclusion(a[i], i, n, p, root) {
					t.Fatal("tampered inclusion")
				}
			}
		}
		for k := 0; k <= n; k++ {
			p := Consistency(a, k)
			old := Root(a[:k])
			if !VerifyConsistency(k, n, old, root, p) {
				t.Fatalf("consistency %d/%d proof=%v", k, n, p)
			}
			if len(p) > 0 {
				p[0][0] ^= 1
				if VerifyConsistency(k, n, old, root, p) {
					t.Fatal("tampered consistency")
				}
			}
			if VerifyConsistency(k, n, old, root, append(p, Leaf([]byte("extra")))) {
				t.Fatal("extra proof nodes accepted")
			}
		}
	}
}
func TestDomainSeparation(t *testing.T) {
	a, b := Leaf([]byte("a")), Leaf([]byte("b"))
	if Node(a, b) == Leaf(append(a[:], b[:]...)) {
		t.Fatal("leaf/internal collision")
	}
}
func BenchmarkInclusion(b *testing.B) {
	a := make([]Hash, 1024)
	for i := range a {
		a[i] = Leaf([]byte(fmt.Sprint(i)))
	}
	root := Root(a)
	p := Inclusion(a, 500)
	b.ResetTimer()
	b.ReportMetric(float64(len(p)*32), "proof-bytes")
	for i := 0; i < b.N; i++ {
		if !VerifyInclusion(a[500], 500, len(a), p, root) {
			b.Fatal("proof")
		}
	}
}
