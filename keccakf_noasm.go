package leanxmss

// keccakF1600 is the Keccak-f[1600] permutation.
func keccakF1600(s *[25]uint64) {
	keccakF1600Generic(s)
}

// keccakF1600Digest returns lanes 0 and 1 of the Keccak-f[1600] permutation of s,
// the first 16 bytes of a one-block hash, and leaves s in an unspecified state.
// Its last round computes those two lanes only.
func keccakF1600Digest(s *[25]uint64) (uint64, uint64) {
	return keccakF1600DigestGeneric(s)
}
