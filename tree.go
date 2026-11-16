package leanxmss

import (
	"fmt"
	"runtime"
	"sync"
)

const layerWidth = 1 << layerHeight // Number of leaves of a layer's tree.

// One layer's Merkle tree over 2^16 leaves. Nodes are indexed on the layer, as
// their addresses are: a bottom tree's leaves by their leaf indices.

// node returns the Merkle parent at level and index j of layer.
func (k *hasher) node(pp *publicParam, layer, level int, j uint32, left, right *digest) digest {
	k.begin(pp, newTweak(tweakNode, layerHi(layer, uint32(level)), j))
	k.write(left[:])
	k.write(right[:])

	return k.truncated()
}

type layerTree struct {
	first  uint32                    // the index of the first leaf.
	levels [layerHeight + 1][]digest // levels[l] holds the nodes of level l, from index first >> l on.
}

// buildLayerTree builds tree index of layer. The leaves are computed on all CPUs.
func buildLayerTree(pp *publicParam, seed *schemeSeed, layer int, index uint32) *layerTree {
	t := &layerTree{first: index << layerHeight}

	leaves := make([]digest, layerWidth)
	workers := min(runtime.GOMAXPROCS(0), layerWidth)

	var wg sync.WaitGroup
	for i := range workers {
		from, to := i*layerWidth/workers, (i+1)*layerWidth/workers
		wg.Go(func() {
			k := newHasher()
			for j := from; j < to; j++ {
				leaves[j] = k.wotsPublicLeaf(pp, seed, layer, t.first+uint32(j))
			}
		})
	}

	wg.Wait()
	t.levels[0] = leaves

	k := newHasher()
	for level := 1; level <= layerHeight; level++ {
		below := t.levels[level-1]
		up := make([]digest, len(below)/2)
		base := t.first >> level
		for j := range up {
			up[j] = k.node(pp, layer, level, base+uint32(j), &below[2*j], &below[2*j+1])
		}

		t.levels[level] = up
	}

	return t
}

func (t *layerTree) root() digest {
	return t.levels[layerHeight][0]
}

// path returns the authentication path of leaf, or an error if leaf is not in the
// tree.
func (t *layerTree) path(leaf uint32) ([layerHeight]digest, error) {
	var path [layerHeight]digest
	k := leaf - t.first
	if k>>layerHeight != 0 {
		return path, fmt.Errorf("%w: leaf %d, tree from %d", errLeafOutside, leaf, t.first)
	}

	for level := range layerHeight {
		path[level] = t.levels[level][(k>>level)^1]
	}

	return path, nil
}

// pathRoot returns the root that leaf, at index e on layer, and its authentication
// path reach. Bit z of e says whether the node at level z is the right child.
func (k *hasher) pathRoot(pp *publicParam, layer int, e uint32, leaf digest, path *[layerHeight]digest) digest {
	current := leaf
	for z := range layerHeight {
		sibling := path[z]
		if (e>>z)&1 == 0 {
			current = k.node(pp, layer, z+1, e>>(z+1), &current, &sibling)
			continue
		}

		current = k.node(pp, layer, z+1, e>>(z+1), &sibling, &current)
	}

	return current
}
