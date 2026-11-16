package leanxmss

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestKeccakF1600 checks the permutation through Keccak-256 of one-block inputs,
// against golang.org/x/crypto/sha3.
func TestKeccakF1600(t *testing.T) {
	for _, size := range []int{0, 1, 64, 80, keccakRate - 1} {
		input := bytes.Repeat([]byte{0xa5}, size)
		var block [keccakRate]byte
		copy(block[:], input)
		block[size] ^= 0x01
		block[keccakRate-1] ^= 0x80

		var state [25]uint64
		for i := range keccakRate / 8 {
			state[i] = binary.LittleEndian.Uint64(block[8*i:])
		}

		keccakF1600(&state)
		var got [32]byte
		for i := range 4 {
			binary.LittleEndian.PutUint64(got[8*i:], state[i])
		}

		if want := keccak256(input); !bytes.Equal(got[:], want) {
			t.Errorf("Keccak-256 of %d bytes: %x, want %x", size, got, want)
		}
	}
}

// TestLeastTrial checks that the randomizer search finds a codeword, and that it
// is the least: no trial below it hashes, the slow way, to a codeword.
func TestLeastTrial(t *testing.T) {
	var pp publicParam
	for i := range pp {
		pp[i] = byte(i)
	}

	message := testMessage()
	base := u128{lo: ^uint64(0) - 1000, hi: 5} // the low half carries during the search
	c, ok := leastTrial(&pp, 0, 9, message[:], base)
	if !ok {
		t.Fatal("no trial found")
	}

	k := newHasher()
	r := addTrial(base, c)
	d := k.messageDigest(&pp, 0, 9, &r, message[:])
	if _, ok := codeword(&d); !ok {
		t.Fatalf("trial %d is not a codeword", c)
	}

	if testing.Short() {
		return
	}

	for below := range c {
		r := addTrial(base, below)
		d := k.messageDigest(&pp, 0, 9, &r, message[:])
		if _, ok := codeword(&d); ok {
			t.Fatalf("trial %d below %d is a codeword", below, c)
		}
	}
}
