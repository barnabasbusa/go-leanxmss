//go:build arm64 && !purego

package leanxmss

import "golang.org/x/sys/cpu"

// useSHA3 says whether keccakF1600x2 uses the Armv8.2 SHA3 instructions.
var useSHA3 = cpu.ARM64.HasSHA3

//go:generate go run _asm/keccakf_arm64_scalar.go

//go:noescape
func keccakF1600Scalar(s *[25]uint64)

//go:noescape
func keccakF1600x2NEON(s *[50]uint64)

//go:noescape
func searchNEON(base *[25]uint64, at int, r *[2]uint64, from, to uint64, out *[4]uint64) uint64

// keccakF1600 is the Keccak-f[1600] permutation, in assembly, on the
// general-purpose registers.
func keccakF1600(s *[25]uint64) {
	keccakF1600Scalar(s)
}

// keccakF1600Digest returns lanes 0 and 1 of the Keccak-f[1600] permutation of s,
// the first 16 bytes of a one-block hash, and leaves s in an unspecified state.
func keccakF1600Digest(s *[25]uint64) (uint64, uint64) {
	keccakF1600Scalar(s)
	return s[0], s[1]
}

// keccakF1600x2 is Keccak-f[1600] of two states at once, interleaved: s[2i] and
// s[2i+1] are lane i of the first and of the second state.
func keccakF1600x2(s *[50]uint64) {
	if useSHA3 {
		keccakF1600x2NEON(s)
		return
	}

	keccakF1600x2Generic(s)
}

// firstTrialSHA3 is firstTrial with the SHA3 instructions, two trials at once.
// The assembly skips the pairs no codeword is in by the top bits of their
// digests, and the other checks are made here.
func (s *trialSearch) firstTrialSHA3(from, to uint64) uint64 {
	r := [2]uint64{s.base.lo, s.base.hi}
	var out [4]uint64 // lane 0 of both states, then lane 1.
	for from < to {
		c := searchNEON(&s.state, s.at, &r, from, to, &out)
		if c == notFound {
			return notFound
		}

		if isCodeword(out[0], out[2]) {
			return c
		}

		if isCodeword(out[1], out[3]) {
			return c + 1
		}

		from = c + 2
	}

	return notFound
}
