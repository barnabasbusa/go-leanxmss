package leanxmss_test

import (
	"crypto/rand"
	"fmt"

	leanxmss "github.com/nalepae/go-leanxmss"
)

func Example() {
	// The seed is the whole private key: generate it once, keep it secret.
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		panic(err)
	}
	sk := leanxmss.NewKeyFromSeed(seed)
	pk := sk.PublicKey()

	// Never sign two different messages at the same leaf index.
	var message [32]byte
	copy(message[:], "a 32-byte message, or its hash..")
	const leafIndex = 42
	sig, err := sk.Sign(leafIndex, message)
	if err != nil {
		panic(err)
	}

	// Keys and signatures travel as bytes.
	decoded, err := leanxmss.SignatureFromBytes(sig.Bytes())
	if err != nil {
		panic(err)
	}
	fmt.Println(len(pk.Bytes()), len(sig.Bytes()))
	fmt.Println(decoded.LeafIndex())
	fmt.Println(leanxmss.Verify(pk, leafIndex, message, decoded))
	fmt.Println(leanxmss.Verify(pk, leafIndex+1, message, decoded))
	// Output:
	// 32 2404
	// 42
	// true
	// false
}
