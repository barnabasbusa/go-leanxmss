package leanxmss

import (
	"encoding/binary"
	"testing"
)

// TestAddressLane checks addressLane against putAddress.
func TestAddressLane(t *testing.T) {
	tw := newTweak(tweakNode, layerHi(1, 0x12), 0x89abcdef).withStep(5)
	var addr [addressLen]byte
	putAddress(&addr, tw)
	if got, want := addressLane(tw), binary.LittleEndian.Uint64(addr[:8]); got != want {
		t.Errorf("address lane %x, want %x", got, want)
	}

	if rest := binary.LittleEndian.Uint64(addr[8:]); rest != 0 {
		t.Errorf("second address lane %x, want 0", rest)
	}
}

// TestLeafPair checks the leaves of two keys hashed together against
// wotsPublicLeaf, on both layers.
func TestLeafPair(t *testing.T) {
	var pp publicParam
	var seed schemeSeed
	for i := range pp {
		pp[i] = byte(3*i + 1)
	}

	for i := range seed {
		seed[i] = byte(5*i + 2)
	}

	k := newHasher()
	for _, layer := range []int{0, 1} {
		leaves := newLeafPair(&pp, &seed, layer)
		for _, e := range []uint32{0, 6, 1<<16 + 2, 1<<32 - 2} {
			got0, got1 := leaves.leaves(e)
			want0, want1 := k.wotsPublicLeaf(&pp, &seed, layer, e), k.wotsPublicLeaf(&pp, &seed, layer, e+1)
			if got0 != want0 || got1 != want1 {
				t.Errorf("layer %d, keys %d and %d: %x %x, want %x %x", layer, e, e+1, got0, got1, want0, want1)
			}
		}
	}
}

// TestNodes checks Merkle nodes hashed in pairs, an odd number of them included,
// against hasher.node.
func TestNodes(t *testing.T) {
	var pp publicParam
	for i := range pp {
		pp[i] = byte(7 * i)
	}

	below := make([]digest, 10)
	for i := range below {
		for j := range below[i] {
			below[i][j] = byte(i*n + j)
		}
	}

	k := newHasher()
	b := newBlockPair(&pp)
	const layer, level, base = 1, 3, 1000
	for _, to := range []int{1, 2, 5} {
		up := make([]digest, len(below)/2)
		b.nodes(layer, level, base, below, up, 0, to)
		for j := range to {
			if want := k.node(&pp, layer, level, base+uint32(j), &below[2*j], &below[2*j+1]); up[j] != want {
				t.Errorf("%d nodes, node %d: %x, want %x", to, j, up[j], want)
			}
		}
	}
}
