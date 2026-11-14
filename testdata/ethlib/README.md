# EthLib leanXMSS test vectors

EthLib's `tests/cryptography/xmss/` at the commit in `COMMIT`, copied from
leanVM's `crates/lean_xmss/tests/lean_xmss/ethlib/` at commit
`f7ba4999ae523b94c8d0969b32762c3effea4cbd`, without its `sync.sh`.

`TestEthlibChecksums` checks every `data.yaml` against `SHA256SUMS`. To refresh,
replace this directory's contents with EthLib's `tests/cryptography/xmss/` at a
new commit, write that commit to `COMMIT`, and update the expected commit and
case counts in `TestEthlibCoversEveryHandler`.
