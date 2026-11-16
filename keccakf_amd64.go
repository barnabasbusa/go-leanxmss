//go:build amd64 && !purego

package leanxmss

//go:noescape
func keccakF1600AMD64(s *[25]uint64)

// keccakF1600 is the Keccak-f[1600] permutation, in assembly.
func keccakF1600(s *[25]uint64) {
	keccakF1600AMD64(s)
}

// keccakF1600Digest returns lanes 0 and 1 of the Keccak-f[1600] permutation of s,
// the first 16 bytes of a one-block hash, and leaves s in an unspecified state.
func keccakF1600Digest(s *[25]uint64) (uint64, uint64) {
	keccakF1600AMD64(s)
	return s[0], s[1]
}
