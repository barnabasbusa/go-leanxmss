package leanxmss

import "testing"

// nextBottomTree is the next bottom tree of sharedKey no benchmark has used, so
// each iteration of the benchmarks below builds a tree.
var nextBottomTree = uint32(1 << 10)

// signedLeaves is how many leaf indices BenchmarkSignCachedTree signs at.
const signedLeaves = 40

// freshLeafIndex returns the first leaf index of a bottom tree never built before.
func freshLeafIndex() uint32 {
	nextBottomTree++
	return nextBottomTree << layerHeight
}

func BenchmarkNewKeyFromSeed(b *testing.B) {
	for i := range b.N {
		NewKeyFromSeed([seedSize]byte{byte(i)})
	}
}

// BenchmarkSignCachedTree signs in a bottom tree already built. The randomizer
// search, most of the cost, takes a number of trials that depends on the leaf
// index, so it cycles through the same signedLeaves leaf indices: run it with
// -benchtime 40x, or any multiple of signedLeaves, for figures that compare.
func BenchmarkSignCachedTree(b *testing.B) {
	sk := sharedKey()
	sk.Prepare(0)
	message := testMessage()
	b.ResetTimer()

	for i := range b.N {
		sk.Sign(uint32(i%signedLeaves), message)
	}
}

// BenchmarkPrepare builds a bottom tree not cached yet.
func BenchmarkPrepare(b *testing.B) {
	sk := sharedKey()

	for b.Loop() {
		sk.Prepare(freshLeafIndex())
	}
}

// BenchmarkSignNewTree signs in a bottom tree not cached yet, so each signature
// builds its tree.
func BenchmarkSignNewTree(b *testing.B) {
	sk := sharedKey()
	message := testMessage()

	for b.Loop() {
		sk.Sign(freshLeafIndex(), message)
	}
}

func BenchmarkVerify(b *testing.B) {
	sk := sharedKey()
	message := testMessage()
	sig := sk.Sign(0, message)
	pk := sk.PublicKey()
	b.ReportAllocs()

	for b.Loop() {
		if !Verify(pk, 0, message, sig) {
			b.Fatal("does not verify")
		}
	}
}
