package leanxmss

// leanXMSS against the test vectors of EthLib, the Lean specification of the scheme.
//
// testdata/ethlib is EthLib's tests/cryptography/xmss/, as vendored by the reference
// implementation (leanVM's crates/lean_xmss/tests/lean_xmss/ethlib). testdata/ethlib/COMMIT
// names the EthLib commit it comes from.
//
// Every case runs, and each must give EthLib's output byte for byte:
//
//   - key_gen: the public key of a seed.
//   - sign: the signature of a message at a leaf index.
//   - verify: whether a signature verifies.
//   - signature_index: the leaf index a signature names.
//
// An output of null marks an input EthLib rejects: here, an input of the wrong length.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const ethlibDir = "testdata/ethlib"

// value is one value of a case, as EthLib writes it: a byte string, an integer, a
// boolean, or null.
type value struct {
	kind  string // "bytes", "int", "bool" or "null"
	bytes []byte
	int   uint64
	bool  bool
}

func (v value) String() string {
	switch v.kind {
	case "bytes":
		return "0x" + hex.EncodeToString(v.bytes)
	case "int":
		return strconv.FormatUint(v.int, 10)
	case "bool":
		return strconv.FormatBool(v.bool)
	default:
		return v.kind
	}
}

var null = value{kind: "null"}

func bytesValue(b []byte) value { return value{kind: "bytes", bytes: b} }
func intValue(i uint64) value   { return value{kind: "int", int: i} }
func boolValue(b bool) value    { return value{kind: "bool", bool: b} }

// testCase is one case: its name, its named inputs and its output.
type testCase struct {
	name   string
	input  map[string]value
	output value
}

func (c *testCase) bytes(t *testing.T, key string) []byte {
	t.Helper()
	v, ok := c.input[key]
	if !ok || v.kind != "bytes" {
		t.Fatalf("%s: input %s is %v, not bytes", c.name, key, v)
	}

	return v.bytes
}

func (c *testCase) integer(t *testing.T, key string) uint64 {
	t.Helper()
	v, ok := c.input[key]
	if !ok || v.kind != "int" {
		t.Fatalf("%s: input %s is %v, not an integer", c.name, key, v)
	}

	return v.int
}

// parseValue parses one scalar, in the subset of YAML EthLib's cases use.
func parseValue(s string) (value, error) {
	switch s {
	case "null":
		return null, nil
	case "true":
		return boolValue(true), nil
	case "false":
		return boolValue(false), nil
	}

	if quoted, ok := strings.CutPrefix(s, "'"); ok {
		quoted, ok = strings.CutSuffix(quoted, "'")
		if !ok {
			return value{}, fmt.Errorf("unterminated string %s", s)
		}

		digits, ok := strings.CutPrefix(quoted, "0x")
		if !ok {
			return value{}, fmt.Errorf("hex without 0x: %s", s)
		}

		b, err := hex.DecodeString(digits)
		if err != nil {
			return value{}, fmt.Errorf("decode hex %s: %w", s, err)
		}

		return bytesValue(b), nil
	}

	i, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return value{}, fmt.Errorf("unknown value %s: %w", s, err)
	}

	return intValue(i), nil
}

// parseCase reads one data.yaml, rejecting any line outside its fixed shape:
//
//	input:
//	  <key>: <value>
//	  ...
//	output: <value>
func parseCase(name, text string) (*testCase, error) {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 2 || lines[0] != "input:" {
		return nil, fmt.Errorf("%s: no input", name)
	}

	c := &testCase{name: name, input: map[string]value{}}
	for i, line := range lines[1:] {
		field, indented := strings.CutPrefix(line, "  ")
		if !indented {
			raw, ok := strings.CutPrefix(line, "output: ")
			if !ok {
				return nil, fmt.Errorf("%s: bad line %q", name, line)
			}

			if i != len(lines)-2 {
				return nil, fmt.Errorf("%s: text after the output", name)
			}

			out, err := parseValue(raw)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}

			c.output = out
			return c, nil
		}

		key, raw, ok := strings.Cut(field, ": ")
		if !ok {
			return nil, fmt.Errorf("%s: bad input %q", name, field)
		}

		in, err := parseValue(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}

		c.input[key] = in
	}

	return nil, fmt.Errorf("%s: no output", name)
}

// cases returns every case of one handler, in name order.
func cases(t *testing.T, handler string) []*testCase {
	t.Helper()
	dir := filepath.Join(ethlibDir, handler)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}

	sort.Strings(names)
	if len(names) == 0 {
		t.Fatalf("no %s cases", handler)
	}

	var out []*testCase
	for _, name := range names {
		text, err := os.ReadFile(filepath.Join(dir, name, "data.yaml"))
		if err != nil {
			t.Fatal(err)
		}

		c, err := parseCase(name, string(text))
		if err != nil {
			t.Fatal(err)
		}

		out = append(out, c)
	}

	return out
}

// exact32 copies b into a 32-byte array, or reports false for any other length.
// Seeds and messages are both 32 bytes.
func exact32(b []byte) ([32]byte, bool) {
	var a [32]byte
	if len(b) != len(a) {
		return a, false
	}

	copy(a[:], b)
	return a, true
}

var _ = [1]int{}[seedSize-32]
var _ = [1]int{}[messageSize-32]

func checkOutput(t *testing.T, c *testCase, got value) {
	t.Helper()
	if !reflect.DeepEqual(got, c.output) {
		t.Errorf("%s: got %v, want %v", c.name, got, c.output)
	}
}

// TestEthlibChecksums checks the vendored vectors against EthLib's SHA256SUMS, and
// that every data.yaml is listed.
func TestEthlibChecksums(t *testing.T) {
	sums, err := os.ReadFile(filepath.Join(ethlibDir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}

	listed := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}

		want, path, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("bad SHA256SUMS line %q", line)
		}

		data, err := os.ReadFile(filepath.Join(ethlibDir, path))
		if err != nil {
			t.Fatal(err)
		}

		got := sha256.Sum256(data)
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("%s: checksum mismatch", path)
		}

		listed[path] = true
	}

	err = filepath.WalkDir(ethlibDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}

		if d.Name() != "data.yaml" {
			return nil
		}

		rel, err := filepath.Rel(ethlibDir, path)
		if err != nil {
			return fmt.Errorf("relative path of %s: %w", path, err)
		}

		if !listed[filepath.ToSlash(rel)] {
			t.Errorf("%s is not in SHA256SUMS", rel)
		}

		return nil
	})

	if err != nil {
		t.Fatal(err)
	}
}

func TestKeyGenMatchesEthlib(t *testing.T) {
	for _, c := range cases(t, "key_gen") {
		got := null
		if seed, ok := exact32(c.bytes(t, "seed")); ok {
			got = bytesValue(NewKeyFromSeed(seed).PublicKey().Bytes())
		}

		checkOutput(t, c, got)
	}
}

func TestSignMatchesEthlib(t *testing.T) {
	// A key is generated once per seed: generation builds the whole top tree.
	keys := map[[seedSize]byte]*PrivateKey{}
	for _, c := range cases(t, "sign") {
		leafIndex := c.integer(t, "leaf_index")
		if leafIndex > 0xFFFFFFFF {
			t.Fatalf("%s: leaf index %d is not 32-bit", c.name, leafIndex)
		}

		got := null
		seed, seedOK := exact32(c.bytes(t, "seed"))
		message, messageOK := exact32(c.bytes(t, "message"))
		if seedOK && messageOK {
			sk, ok := keys[seed]
			if !ok {
				sk = NewKeyFromSeed(seed)
				keys[seed] = sk
			}

			got = bytesValue(sk.Sign(uint32(leafIndex), message).Bytes())
		}

		checkOutput(t, c, got)
	}
}

func TestSignatureIndexMatchesEthlib(t *testing.T) {
	for _, c := range cases(t, "signature_index") {
		got := null
		if sig, err := SignatureFromBytes(c.bytes(t, "signature")); err == nil {
			got = intValue(uint64(sig.LeafIndex()))
		}

		checkOutput(t, c, got)
	}
}

func TestVerifyMatchesEthlib(t *testing.T) {
	for _, c := range cases(t, "verify") {
		got := null
		pk, pkErr := PublicKeyFromBytes(c.bytes(t, "public_key"))
		message, messageOK := exact32(c.bytes(t, "message"))
		sig, sigErr := SignatureFromBytes(c.bytes(t, "signature"))
		if pkErr == nil && messageOK && sigErr == nil {
			// The vectors check a signature at the leaf index it carries.
			got = boolValue(Verify(pk, sig.LeafIndex(), message, sig))
		}

		checkOutput(t, c, got)
	}
}

// TestEthlibCoversEveryHandler guards against a handler silently losing its cases.
func TestEthlibCoversEveryHandler(t *testing.T) {
	want := map[string]int{"key_gen": 4, "sign": 6, "signature_index": 8, "verify": 23}
	for handler, count := range want {
		if got := len(cases(t, handler)); got != count {
			t.Errorf("%s: %d cases, want %d", handler, got, count)
		}
	}

	commit, err := os.ReadFile(filepath.Join(ethlibDir, "COMMIT"))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bytes.TrimSpace(commit), []byte("a2a9e655f965dbadf33b3acfbc645696078fc75d")) {
		t.Errorf("unexpected EthLib commit %q", commit)
	}
}
