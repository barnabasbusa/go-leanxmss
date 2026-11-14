package leanxmss

import (
	"encoding/binary"
	"math"
	"math/bits"
	"runtime"
	"sync"
)

// The one-time signature, WOTS+C: v hash chains of 2^w - 1 steps, and a target-sum
// code in place of the Winternitz checksum.
//
// A layer's message digest is Th(P, A, M | R), read as digits of w bits, little
// endian. It is a codeword when its last zeroDigits digits are zero, so those have
// no chain, and the other v sum to targetSum. The signer grinds the randomizer R
// until it is.

const (
	lowBits    = 0x5555555555555555 // Low bit of every 2-bit digit set.
	notFound   = math.MaxUint64     // Marks a search range without a codeword. Trials are below 2^32.
	trialChunk = 1 << 12            // Number of consecutive trials one goroutine scans at a time.
)

// randomizer is the value a layer's message digest is computed under.
type randomizer [randomizerLen]byte

// layerIndex returns the index of leafIndex's one-time key on layer: the leaf index
// itself at the bottom, the bottom tree's index at the top.
func layerIndex(leafIndex uint32, layer int) uint32 {
	return uint32(uint64(leafIndex) >> (layer * layerHeight))
}

// wotsSecrets returns the starts of the v chains of key e on layer. One hash of the
// seed gives two of them: chains 2t and 2t + 1 are its two halves.
func (k *hasher) wotsSecrets(pp *publicParam, seed *schemeSeed, layer int, e uint32) [v]digest {
	var secrets [v]digest
	for t := range v / 2 {
		secrets[2*t], secrets[2*t+1] = k.thPair(pp, newTweak(tweakPRF, layerHi(layer, uint32(t)), e), seed)
	}

	return secrets
}

// chain walks steps steps of chain i of key e on layer from position start. A
// step's address carries the position it leaves, and the chain index follows the
// value, as a 16-byte little-endian integer.
func (k *hasher) chain(pp *publicParam, layer int, e uint32, i, start, steps int, value digest) digest {
	if start+steps >= chainLen {
		panic("leanxmss: chain walk past its end")
	}

	var index [16]byte
	binary.LittleEndian.PutUint64(index[:8], uint64(i))
	base := newTweak(tweakChain, layerHi(layer, 0), e)

	for from := start; from < start+steps; from++ {
		k.begin(pp, base.withStep(from))
		k.write(value[:])
		k.write(index[:])
		value = k.truncated()
	}

	return value
}

// wotsLeafHash returns the Merkle leaf of a one-time key: Th over its v chain ends.
func (k *hasher) wotsLeafHash(pp *publicParam, layer int, e uint32, ends *[v]digest) digest {
	k.begin(pp, newTweak(tweakLeaf, layerHi(layer, 0), e))
	for i := range ends {
		k.write(ends[i][:])
	}

	return k.truncated()
}

// messageDigest returns the digest key e on layer signs: Th(P, A, M | R), M the
// message at the bottom and the bottom root at the top.
func (k *hasher) messageDigest(pp *publicParam, layer int, e uint32, r *randomizer, message []byte) digest {
	k.begin(pp, newTweak(tweakMsg, layerHi(layer, 0), e))
	k.write(message)
	k.write(r[:])

	return k.truncated()
}

// isCodeword reports whether the 128-bit little-endian digest lo | hi << 64 is a
// codeword: its digits past the v-th are zero, and, a 2-bit digit being its low bit
// plus twice its high bit, the others sum to targetSum.
func isCodeword(lo, hi uint64) bool {
	if hi>>(w*v-64) != 0 {
		return false
	}

	sum := bits.OnesCount64(lo&lowBits) + bits.OnesCount64(hi&lowBits) +
		2*(bits.OnesCount64(lo&^lowBits)+bits.OnesCount64(hi&^lowBits))

	return sum == targetSum
}

// codeword returns the digest's first v digits, if it is a codeword.
func codeword(d *digest) ([v]uint8, bool) {
	var x [v]uint8
	lo := binary.LittleEndian.Uint64(d[0:8])
	hi := binary.LittleEndian.Uint64(d[8:16])
	if !isCodeword(lo, hi) {
		return x, false
	}

	for i := range v {
		bit := w * i // w divides 8, so no digit spans two bytes.
		x[i] = d[bit/8] >> (bit % 8) & (chainLen - 1)
	}

	return x, true
}

// u128 is a 128-bit unsigned integer.
type u128 struct {
	lo, hi uint64
}

// addTrial returns base + c, modulo 2^128, as 16 little-endian bytes.
func addTrial(base u128, c uint64) randomizer {
	lo, carry := bits.Add64(base.lo, c, 0)
	hi, _ := bits.Add64(base.hi, 0, carry)

	var r randomizer
	binary.LittleEndian.PutUint64(r[0:8], lo)
	binary.LittleEndian.PutUint64(r[8:16], hi)

	return r
}

// leastTrial returns the least c below maxRandomizerTrials whose randomizer
// base + c makes key e's digest of message on layer a codeword: the least, which
// keeps one key to one codeword. The search is spread over all CPUs, in rounds of
// consecutive chunks; the first chunk of a round holding a codeword holds the least.
func leastTrial(pp *publicParam, layer int, e uint32, message []byte, base u128) (uint64, bool) {
	workers := runtime.GOMAXPROCS(0)
	hashers := make([]*hasher, workers)
	for i := range hashers {
		hashers[i] = newHasher()
	}

	found := make([]uint64, workers)
	round := uint64(workers) * trialChunk
	for start := uint64(0); start < maxRandomizerTrials; start += round {
		var wg sync.WaitGroup
		for i := range workers {
			found[i] = notFound
			from := start + uint64(i)*trialChunk
			if from >= maxRandomizerTrials {
				continue
			}

			to := min(from+trialChunk, maxRandomizerTrials)
			wg.Go(func() {
				found[i] = hashers[i].firstTrial(pp, layer, e, message, base, from, to)
			})
		}

		wg.Wait()

		for _, c := range found {
			if c != notFound {
				return c, true
			}
		}
	}

	return 0, false
}

// firstTrial returns the least c in [from, to) whose randomizer base + c makes the
// digest a codeword, or notFound.
func (k *hasher) firstTrial(pp *publicParam, layer int, e uint32, message []byte, base u128, from, to uint64) uint64 {
	var zero randomizer
	k.begin(pp, newTweak(tweakMsg, layerHi(layer, 0), e))
	k.write(message)
	k.write(zero[:])

	slot := k.buf[k.len-randomizerLen : k.len]
	for c := from; c < to; c++ {
		r := addTrial(base, c)
		copy(slot, r[:])
		out := k.sum()
		if isCodeword(binary.LittleEndian.Uint64(out[0:8]), binary.LittleEndian.Uint64(out[8:16])) {
			return c
		}
	}

	return notFound
}

// wotsSign signs message with key e on layer: the randomizer of the least
// admissible trial R0 + c, R0 a hash of the seed and the message, and the chain
// value each digit opens. It is deterministic in its inputs. It reports false
// if none of the trials gives a codeword.
func wotsSign(pp *publicParam, seed *schemeSeed, layer int, e uint32, message []byte) (randomizer, [v]digest, bool) {
	k := newHasher()
	k.begin(pp, newTweak(tweakRandomizer, layerHi(layer, 0), e))
	k.write(seed[:])
	k.write(message)
	out := k.sum()
	base := u128{lo: binary.LittleEndian.Uint64(out[0:8]), hi: binary.LittleEndian.Uint64(out[8:16])}

	c, ok := leastTrial(pp, layer, e, message, base)
	if !ok {
		return randomizer{}, [v]digest{}, false
	}

	r := addTrial(base, c)
	d := k.messageDigest(pp, layer, e, &r, message)
	x, ok := codeword(&d)

	if !ok {
		return randomizer{}, [v]digest{}, false
	}

	secrets := k.wotsSecrets(pp, seed, layer, e)
	var values [v]digest
	for i := range v {
		values[i] = k.chain(pp, layer, e, i, 0, int(x[i]), secrets[i])
	}

	return r, values, true
}

// wotsLeaf returns the leaf a claimed signature recovers, or false if its digest
// is not a codeword.
func (k *hasher) wotsLeaf(pp *publicParam, layer int, e uint32, message []byte, r *randomizer, values *[v]digest) (digest, bool) {
	d := k.messageDigest(pp, layer, e, r, message)
	x, ok := codeword(&d)
	if !ok {
		return digest{}, false
	}

	var ends [v]digest
	for i := range v {
		start := int(x[i])
		ends[i] = k.chain(pp, layer, e, i, start, chainLen-1-start, values[i])
	}

	return k.wotsLeafHash(pp, layer, e, &ends), true
}

// wotsPublicLeaf returns the leaf of key e on layer, from the seed.
func (k *hasher) wotsPublicLeaf(pp *publicParam, seed *schemeSeed, layer int, e uint32) digest {
	secrets := k.wotsSecrets(pp, seed, layer, e)
	var ends [v]digest
	for i := range v {
		ends[i] = k.chain(pp, layer, e, i, 0, chainLen-1, secrets[i])
	}

	return k.wotsLeafHash(pp, layer, e, &ends)
}
