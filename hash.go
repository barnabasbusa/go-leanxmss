package leanxmss

import (
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/sha3"
)

const maxHashInput = publicParamLen + addressLen + v*n // Longest hash input: P, A and the v chain ends of a leaf.

// The tweakable hash Th(P, A, M) = first n bytes of Keccak-256(P | A | M), its
// address A, and the derivation of the scheme's seed and public parameter.
//
// The two layers share one public parameter, so the address separates them: the
// top layer sets topFlag in hi. A bottom address's lo is the leaf index, or a
// node's index leafIndex >> level, which also separates the bottom trees; a top
// address's lo is the top tree's own.

// digest is a hash value or a Merkle node.
type digest [n]byte

// publicParam is the public parameter P of a key.
type publicParam [publicParamLen]byte

// schemeSeed is the seed every secret of a key derives from: the hash of seedTag
// then the key's seed.
type schemeSeed [32]byte

// seedTag is hashed before a key's seed, so no other scheme derives from the same
// bytes.
var seedTag = []byte("leanXMSS")

// tweak is the address of a hash call: its type, a chain step, and two fields,
// hi < 2^24 and lo.
type tweak struct {
	t    uint8
	step uint8
	hi   uint32
	lo   uint32
}

func newTweak(t uint8, hi, lo uint32) tweak {
	return tweak{t: t, hi: hi, lo: lo}
}

// withStep returns the same address at chain step step < 8.
func (tw tweak) withStep(step int) tweak {
	tw.step = uint8(step)
	return tw
}

// layerHi returns hi for field on layer layer (0 the bottom, 1 the top).
func layerHi(layer int, field uint32) uint32 {
	return field | uint32(layer)*topFlag
}

// putAddress writes the 16 bytes that follow P in a hash input:
// [lo:4 | hi:3 | t + 32*step:1 | zero:8], the fields little endian.
func putAddress(out *[addressLen]byte, tw tweak) {
	binary.LittleEndian.PutUint32(out[0:4], tw.lo)
	out[4] = byte(tw.hi)
	out[5] = byte(tw.hi >> 8)
	out[6] = byte(tw.hi >> 16)
	out[7] = tw.t | tw.step<<5
	clear(out[8:])
}

// hasher computes Keccak-256 over inputs it assembles in its own buffer. It is not
// safe for concurrent use: each goroutine uses its own.
type hasher struct {
	h   hash.Hash
	buf [maxHashInput]byte
	len int
	out [32]byte
}

func newHasher() *hasher {
	return &hasher{h: sha3.NewLegacyKeccak256()}
}

// reset empties the input.
func (k *hasher) reset() {
	k.len = 0
}

// begin starts an input with P | A.
func (k *hasher) begin(pp *publicParam, tw tweak) {
	copy(k.buf[:publicParamLen], pp[:])
	putAddress((*[addressLen]byte)(k.buf[publicParamLen:publicParamLen+addressLen]), tw)
	k.len = publicParamLen + addressLen
}

// write appends p to the input.
func (k *hasher) write(p []byte) {
	if k.len+len(p) > len(k.buf) {
		panic("leanxmss: hash input too long")
	}

	k.len += copy(k.buf[k.len:], p)
}

// sum returns Keccak-256 of the input. The result is overwritten by the next sum.
func (k *hasher) sum() *[32]byte {
	k.h.Reset()
	k.h.Write(k.buf[:k.len])
	k.h.Sum(k.out[:0])
	return &k.out
}

// truncated returns the first n bytes of Keccak-256 of the input.
func (k *hasher) truncated() digest {
	return digest(k.sum()[:n])
}

// th returns Th(P, A, payload).
func (k *hasher) th(pp *publicParam, tw tweak, payload []byte) digest {
	k.begin(pp, tw)
	k.write(payload)

	return k.truncated()
}

// thPair returns two secrets for one hash: the two halves of the untruncated
// Keccak-256 of P | A | S.
func (k *hasher) thPair(pp *publicParam, tw tweak, seed *schemeSeed) (digest, digest) {
	k.begin(pp, tw)
	k.write(seed[:])
	out := k.sum()

	return digest(out[:n]), digest(out[n:])
}

// deriveSchemeSeed returns Keccak-256(seedTag | seed).
func (k *hasher) deriveSchemeSeed(seed *[seedSize]byte) schemeSeed {
	k.reset()
	k.write(seedTag)
	k.write(seed[:])

	return schemeSeed(*k.sum())
}

// derivePublicParam returns the public parameter, Th over the scheme's seed under
// P = 0 and the parameter address.
func (k *hasher) derivePublicParam(seed *schemeSeed) publicParam {
	var zero publicParam
	return publicParam(k.th(&zero, newTweak(tweakParameter, 0, 0), seed[:]))
}
