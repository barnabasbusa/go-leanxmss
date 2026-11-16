//go:build !arm64 || purego

package leanxmss

// useSHA3 is false: there is no assembly for this architecture, or purego is set.
var useSHA3 = false

// keccakF1600x2 is Keccak-f[1600] of two states at once, interleaved: s[2i] and
// s[2i+1] are lane i of the first and of the second state.
func keccakF1600x2(s *[50]uint64) {
	keccakF1600x2Generic(s)
}

// firstTrialSHA3 is never called: useSHA3 is false.
func (s *trialSearch) firstTrialSHA3(from, to uint64) uint64 {
	panic("leanxmss: no SHA3 instructions")
}
