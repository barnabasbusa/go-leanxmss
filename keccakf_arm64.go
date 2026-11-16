//go:build arm64 && !purego

package leanxmss

import "golang.org/x/sys/cpu"

// useSHA3 says whether keccakF1600x2 uses the Armv8.2 SHA3 instructions.
var useSHA3 = cpu.ARM64.HasSHA3

//go:noescape
func keccakF1600x2NEON(s *[50]uint64)

// keccakF1600x2 is Keccak-f[1600] of two states at once, interleaved: s[2i] and
// s[2i+1] are lane i of the first and of the second state.
func keccakF1600x2(s *[50]uint64) {
	if useSHA3 {
		keccakF1600x2NEON(s)
		return
	}

	keccakF1600x2Generic(s)
}
