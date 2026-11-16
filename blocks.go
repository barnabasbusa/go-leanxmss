package leanxmss

import "encoding/binary"

// Building a tree hashes 64-byte inputs, P | A | 32 bytes, nearly only: the
// chain steps, the seed hashes and the Merkle nodes. Each is one Keccak-256
// block, so a blockPair writes two of them, padded, straight into the lanes of two
// interleaved Keccak states, and hashes both with one keccakF1600x2.

const (
	shortInputLanes = (publicParamLen + addressLen + 2*n) / 8      // Number of lanes of a 64-byte input.
	leafInputLanes  = (publicParamLen + addressLen + v*n) / 8      // Number of lanes of a leaf hash's input.
	rateLanes       = keccakRate / 8                               // Number of lanes a Keccak-256 block fills.
	leafBlocks      = (leafInputLanes*8 + keccakRate) / keccakRate // Number of blocks of a leaf hash's padded input.
	padFirst        = 0x01                                         // Keccak's padding: this byte right after the input,
	padLast         = 0x80 << 56                                   // and this bit at the top of the block's last lane.
	headerLanes     = (publicParamLen + addressLen) / 8            // Number of lanes of P | A, which start every input.
)

// The inputs are whole lanes, a short one is 64 bytes, and a leaf hash takes 8
// blocks.
var (
	_ = [1]int{}[(publicParamLen+addressLen+2*n)-64]
	_ = [1]int{}[(publicParamLen+addressLen)%8]
	_ = [1]int{}[n-16]
	_ = [1]int{}[leafBlocks-8]
)

// addressLane returns the lane the 16-byte address of tw starts with, as
// putAddress writes it. Its second lane is zero.
func addressLane(tw tweak) uint64 {
	return uint64(tw.lo) | uint64(tw.hi&0xffffff)<<32 | uint64(tw.t|tw.step<<5)<<56
}

// digestLanes returns d as two little-endian lanes.
func digestLanes(d *digest) (uint64, uint64) {
	return binary.LittleEndian.Uint64(d[0:8]), binary.LittleEndian.Uint64(d[8:16])
}

// laneDigest returns the digest of two little-endian lanes.
func laneDigest(lo, hi uint64) digest {
	var d digest
	binary.LittleEndian.PutUint64(d[0:8], lo)
	binary.LittleEndian.PutUint64(d[8:16], hi)

	return d
}

// blockPair is two interleaved Keccak states: s[2i] and s[2i+1] are lane i of
// state 0 and of state 1.
type blockPair struct {
	s  [50]uint64
	pp [2]uint64 // P, as two lanes.
}

func newBlockPair(pp *publicParam) *blockPair {
	lo, hi := binary.LittleEndian.Uint64(pp[0:8]), binary.LittleEndian.Uint64(pp[8:16])
	return &blockPair{pp: [2]uint64{lo, hi}}
}

// hashShort sets state j to the padded block of P | A | x0 | x1 | x2 | x3, and
// both states must be set before permute.
func (b *blockPair) hashShort(j int, tw tweak, x0, x1, x2, x3 uint64) {
	s := b.s[j:]
	s[0], s[2], s[4], s[6] = b.pp[0], b.pp[1], addressLane(tw), 0
	s[8], s[10], s[12], s[14] = x0, x1, x2, x3
	s[16] = padFirst
	for i := shortInputLanes + 1; i < 25; i++ {
		s[2*i] = 0
	}

	s[2*(rateLanes-1)] = padLast
}

// permute permutes both states.
func (b *blockPair) permute() {
	keccakF1600x2(&b.s)
}

// lane returns lane i of state j.
func (b *blockPair) lane(j, i int) uint64 {
	return b.s[2*i+j]
}

// leafPair computes the leaves of the one-time keys e and e + 1 on layer, with
// the same hashes as wotsPublicLeaf, both keys' in one permutation each.
type leafPair struct {
	blocks   *blockPair
	seed     [4]uint64 // The scheme's seed, as four lanes.
	layer    int
	chains   [2][v][2]uint64           // Each key's chain values, two lanes each.
	leafLane [2][leafInputLanes]uint64 // Each key's leaf hash input.
}

func newLeafPair(pp *publicParam, seed *schemeSeed, layer int) *leafPair {
	l := &leafPair{blocks: newBlockPair(pp), layer: layer}
	for i := range l.seed {
		l.seed[i] = binary.LittleEndian.Uint64(seed[8*i:])
	}

	return l
}

// leaves returns the leaves of keys e and e + 1.
func (l *leafPair) leaves(e uint32) (digest, digest) {
	b := l.blocks
	s := &l.seed

	// The chain starts, two per hash of the seed.
	for t := range v / 2 {
		for j := range 2 {
			b.hashShort(j, newTweak(tweakPRF, layerHi(l.layer, uint32(t)), e+uint32(j)), s[0], s[1], s[2], s[3])
		}

		b.permute()
		for j := range 2 {
			l.chains[j][2*t] = [2]uint64{b.lane(j, 0), b.lane(j, 1)}
			l.chains[j][2*t+1] = [2]uint64{b.lane(j, 2), b.lane(j, 3)}
		}
	}

	// The chains, walked to their ends.
	for i := range v {
		for step := range chainLen - 1 {
			for j := range 2 {
				tw := newTweak(tweakChain, layerHi(l.layer, 0), e+uint32(j)).withStep(step)
				c := &l.chains[j][i]
				b.hashShort(j, tw, c[0], c[1], uint64(i), 0)
			}

			b.permute()
			for j := range 2 {
				l.chains[j][i] = [2]uint64{b.lane(j, 0), b.lane(j, 1)}
			}
		}
	}

	// The leaf hash over the chain ends, several blocks.
	for j := range 2 {
		in := &l.leafLane[j]
		in[0], in[1] = b.pp[0], b.pp[1]
		in[2], in[3] = addressLane(newTweak(tweakLeaf, layerHi(l.layer, 0), e+uint32(j))), 0
		for i := range v {
			in[headerLanes+2*i], in[headerLanes+2*i+1] = l.chains[j][i][0], l.chains[j][i][1]
		}
	}

	clear(b.s[:])
	for block := range leafBlocks {
		for j := range 2 {
			for i := range rateLanes {
				at := block*rateLanes + i
				switch {
				case at < leafInputLanes:
					b.s[2*i+j] ^= l.leafLane[j][at]
				case at == leafInputLanes:
					b.s[2*i+j] ^= padFirst
				}
			}

			if block == leafBlocks-1 {
				b.s[2*(rateLanes-1)+j] ^= padLast
			}
		}

		b.permute()
	}

	return laneDigest(b.lane(0, 0), b.lane(0, 1)), laneDigest(b.lane(1, 0), b.lane(1, 1))
}

// nodes computes up[j], the Merkle parent of below[2j] and below[2j + 1], for j
// in [from, to), at level of layer, up[0] at index base. They are hashed in pairs,
// the last alone if their number is odd.
func (b *blockPair) nodes(layer, level int, base uint32, below, up []digest, from, to int) {
	for j := from; j < to; j += 2 {
		pair := min(2, to-j)
		for k := range 2 {
			at := j + k%pair // an odd last node is hashed twice.
			l0, l1 := digestLanes(&below[2*at])
			r0, r1 := digestLanes(&below[2*at+1])
			b.hashShort(k, newTweak(tweakNode, layerHi(layer, uint32(level)), base+uint32(at)), l0, l1, r0, r1)
		}

		b.permute()
		for k := range pair {
			up[j+k] = laneDigest(b.lane(k, 0), b.lane(k, 1))
		}
	}
}
