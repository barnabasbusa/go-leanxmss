# go-leanxmss

A Go implementation of **leanXMSS**, the post-quantum hash-based signature scheme
of Ethereum's PQ consensus specification, over Keccak-256.

Specification: [leanXMSS](https://github.com/leanEthereum/leanVM/blob/f7ba4999ae523b94c8d0969b32762c3effea4cbd/doc/lean_xmss/main.tex)
(leanVM's `doc/lean_xmss`).

> [!CAUTION]
> **This library is a proof of concept only. Do NOT use it in production.**
> It has not been audited, it is not formally verified, and the leanXMSS
> specification and parameters it follows may still change. Never use it to
> protect real funds or real validator keys.

```sh
go get github.com/nalepae/go-leanxmss
```

```go
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"

	leanxmss "github.com/nalepae/go-leanxmss"
)

func main() {
	// The seed is the whole private key: generate it once, and keep it secret.
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		log.Fatal(err)
	}

	sk := leanxmss.NewKeyFromSeed(seed)
	pk := sk.PublicKey()

	// Messages are 32 bytes: sign a hash of longer data.
	message := sha256.Sum256([]byte("Dear quantum computer: nice try."))

	// Never sign two different messages at the same leaf index.
	const leafIndex = 42
	sig := sk.Sign(leafIndex, message)

	// Keys and signatures travel as bytes.
	pkBytes, sigBytes := pk.Bytes(), sig.Bytes()
	fmt.Printf("public key: %d bytes, signature: %d bytes\n", len(pkBytes), len(sigBytes))

	decodedPK, err := leanxmss.PublicKeyFromBytes(pkBytes)
	if err != nil {
		log.Fatal(err)
	}

	decodedSig, err := leanxmss.SignatureFromBytes(sigBytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("leaf index:", decodedSig.LeafIndex())
	fmt.Println("valid:", leanxmss.Verify(decodedPK, leafIndex, message, decodedSig))
	fmt.Println("valid at another leaf index:", leanxmss.Verify(decodedPK, leafIndex+1, message, decodedSig))
}
```

It prints:

```text
public key: 32 bytes, signature: 2404 bytes
leaf index: 42
valid: true
valid at another leaf index: false
```

## How it works

leanXMSS is two layers of Merkle trees of height 16 over one-time signature keys.
Each of the top tree's 65,536 leaves signs the root of one bottom tree, and each
bottom tree's 65,536 leaves sign messages, so a key has 2^32 leaf indices.

`NewKeyFromSeed` builds the top tree. Signing at a leaf index needs the bottom
tree that index is in: a `PrivateKey` caches the 8 bottom trees it used last, so
signing at consecutive leaf indices builds a tree only once every 65,536
signatures, and `Prepare` builds the next one ahead of time. Key generation, tree
building and signing use all CPUs.

### Signing is a randomizer search

A one-time signature only accepts a message digest that is a codeword: a digest
whose last 6 base-4 digits are zero and whose other 58 sum to 106. So the signer
hashes the message with one randomizer after another until the digest is one:
about a million trials on average, a number that depends on the message and the
leaf index. This search is nearly all the time of signing once the bottom tree is
built. Signing in a new bottom tree also builds that tree, and runs a second
search, to sign its root with the top tree's leaf.

## API

### `PrivateKey`

Safe for concurrent use.

| Function                                                            | Description                                                                                |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `NewKeyFromSeed(seed [32]byte) *PrivateKey`                         | Returns the private key of a seed. Builds the top tree.                                    |
| `(*PrivateKey).PublicKey() PublicKey`                               | Returns the public key.                                                                    |
| `(*PrivateKey).Sign(leafIndex uint32, message [32]byte) *Signature` | Signs a message at a leaf index. Never sign two different messages at the same leaf index. |
| `(*PrivateKey).Prepare(leafIndex uint32)`                           | Builds the bottom tree of a leaf index ahead of time.                                      |

### `PublicKey`

Comparable with `==`.

| Function                                          | Description                                                         |
| ------------------------------------------------- | ------------------------------------------------------------------- |
| `PublicKeyFromBytes(b []byte) (PublicKey, error)` | Decodes a public key. Returns an error unless `b` is 32 bytes long. |
| `(PublicKey).Bytes() []byte`                      | Encodes a public key on 32 bytes.                                   |

### `Signature`

| Function                                           | Description                                                           |
| -------------------------------------------------- | --------------------------------------------------------------------- |
| `SignatureFromBytes(b []byte) (*Signature, error)` | Decodes a signature. Returns an error unless `b` is 2,404 bytes long. |
| `(*Signature).Bytes() []byte`                      | Encodes a signature on 2,404 bytes.                                   |
| `(*Signature).LeafIndex() uint32`                  | Returns the leaf index the signature was made at.                     |

### Verification

| Function                                                                        | Description                                                        |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `Verify(pk PublicKey, leafIndex uint32, message [32]byte, sig *Signature) bool` | Reports whether a signature of a message is valid at a leaf index. |

Leaf indices are `uint32`: a key has 2^32 of them, and a signature stores its
index on 4 bytes.

## Leaf indices are the caller's duty

leanXMSS is stateful: **never sign two different messages at the same leaf
index** with the same key, or forgeries become possible. This package does not
record used leaf indices. Signing is deterministic, so signing the same message at
the same leaf index again is safe and gives the same signature.

## Performance

On an Apple M2 Max (12 cores), mean of 5 runs of `go test -run '^$' -bench . -count 5
-cpu 1,12`:

| Operation                              | 12 CPUs | 1 CPU   |
| -------------------------------------- | ------- | ------- |
| `NewKeyFromSeed` (builds the top tree) | 590 ms  | 5.26 s  |
| `Prepare` (builds a bottom tree)       | 698 ms  | 5.45 s  |
| `Verify`                               | 69.7 µs | 71.1 µs |

Signing:

| Operation                                      | 12 CPUs | 1 CPU   |
| ---------------------------------------------- | ------- | ------- |
| `Sign`, bottom tree cached                     | 54.0 ms | 331 ms  |
| `Sign`, bottom tree not cached yet (builds it) | 747 ms  | 5.68 s  |

Signing in a cached tree comes from `-bench SignCachedTree -benchtime 40x`, which
signs at the same 40 leaf indices in every run, as the number of randomizer
trials depends on the leaf index. With `-cpu 1`, the first run of `Prepare` and
of `Sign` in a new tree runs at the speed of all CPUs, a quirk of the benchmark
harness: those two cells are the mean of the other 4 runs.

## Tests and benchmarks

Run the tests (about 18 s on the machine above):

```sh
go test
```

`-short` skips the two slowest tests, which tamper with every byte of a signature
and fill the bottom-tree cache:

```sh
go test -short
```

Run the tests, then the benchmarks:

```sh
go test -bench .
```

The figures above come from `go test -run '^$' -bench . -count 5 -cpu 1,12` (about
6 minutes). Replace `.` after `-bench` with a name, such as `Verify`, to run only
the matching benchmarks.

## Correctness

The tests check, byte for byte, every [EthLib](https://github.com/ethereum/EthLib)
test vector (key generation, signing, verification and leaf-index reading: 41
cases, vendored in `testdata/ethlib` with their checksums). EthLib is the Lean
specification of the scheme.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option, as leanVM is. See [NOTICE](NOTICE).
