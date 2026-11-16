package leanxmss

import (
	"runtime"
	"sync"
	"sync/atomic"
)

const (
	layerWidth    = 1 << layerHeight                   // Number of leaves of a layer's tree.
	subtreeHeight = 8                                  // Height of the subtrees a tree's build is split into.
	subtrees      = 1 << (layerHeight - subtreeHeight) // Number of subtrees of a layer's tree.
)

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

// buildLayerTree builds tree index of layer, on all CPUs. Each goroutine takes
// the next subtree of 2^subtreeHeight leaves from a shared counter as soon as it
// has built one, so faster cores build more, and the levels above the subtrees
// are built last.
func buildLayerTree(pp *publicParam, seed *schemeSeed, layer int, index uint32) *layerTree {
	t := &layerTree{first: index << layerHeight}
	for level := range t.levels {
		t.levels[level] = make([]digest, layerWidth>>level)
	}

	var next atomic.Uint32
	var wg sync.WaitGroup
	for range min(runtime.GOMAXPROCS(0), subtrees) {
		wg.Go(func() {
			leaves := newLeafPair(pp, seed, layer)
			for {
				s := next.Add(1) - 1
				if s >= subtrees {
					return
				}

				t.buildSubtree(leaves, layer, s)
			}
		})
	}

	wg.Wait()

	b := newBlockPair(pp)
	for level := subtreeHeight + 1; level <= layerHeight; level++ {
		t.hashLevel(b, layer, level, 0, layerWidth>>level)
	}

	return t
}

// buildSubtree computes the leaves and nodes of subtree s, up to its root.
func (t *layerTree) buildSubtree(leaves *leafPair, layer int, s uint32) {
	from := s << subtreeHeight
	for j := from; j < from+1<<subtreeHeight; j += 2 {
		t.levels[0][j], t.levels[0][j+1] = leaves.leaves(t.first + j)
	}

	for level := 1; level <= subtreeHeight; level++ {
		width := 1 << (subtreeHeight - level)
		t.hashLevel(leaves.blocks, layer, level, int(s)*width, int(s+1)*width)
	}
}

// hashLevel computes the nodes of level with indices in [from, to), relative to
// the tree's first node on that level.
func (t *layerTree) hashLevel(b *blockPair, layer, level, from, to int) {
	b.nodes(layer, level, t.first>>level, t.levels[level-1], t.levels[level], from, to)
}

func (t *layerTree) root() digest {
	return t.levels[layerHeight][0]
}

// path returns the authentication path of leaf, which must be in the tree.
func (t *layerTree) path(leaf uint32) [layerHeight]digest {
	k := leaf - t.first
	if k>>layerHeight != 0 {
		panic("leanxmss: leaf outside the tree")
	}

	var path [layerHeight]digest
	for level := range layerHeight {
		path[level] = t.levels[level][(k>>level)^1]
	}

	return path
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
