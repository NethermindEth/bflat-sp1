# Vendored test vectors

Unmodified official vectors, pinned:

| Path | Source | License | Pinned at |
|---|---|---|---|
| `geth/bn256Pairing.json`, `geth/pointEvaluation.json` | go-ethereum `core/vm/testdata/precompiles`, as vendored by SP1's `zkevm/libzkevm/tests/data/geth` at `v6.9.0` | LGPL-3.0 (test data) | `geth/GETH_COMMIT.txt` |
| `kzg/verify_kzg_proof.json` | c-kzg-4844 `tests/verify_kzg_proof/kzg-mainnet` (the consensus-spec `verify_kzg_proof` suite), the `data.yaml` files collected into one JSON | CC0-1.0 (consensus-spec test vectors) | the commit in the file's `source` |
