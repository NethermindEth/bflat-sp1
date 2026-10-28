# bflat-sp1

[![Nethermind.Sp1.Runtime](https://img.shields.io/nuget/v/Nethermind.Sp1.Runtime)](https://www.nuget.org/packages/Nethermind.Sp1.Runtime)

SP1 bindings for [bflat-riscv64](https://github.com/NethermindEth/bflat-riscv64)
guests built with `--libc sp1`, providing the native half of
[Nethermind.Zkvm.Abstractions](https://www.nuget.org/packages/Nethermind.Zkvm.Abstractions).

## What this is

`libsp1.a` — five layers in one archive:

1. **SP1's own zkEVM SDK.** SP1 ships a complete implementation of the
   [eth-act zkVM accelerator standard](https://github.com/eth-act/zkvm-standards)
   (sources under `sp1/zkevm/`, published as the `zkevm-sdk-<version>.tar.gz`
   release asset). 13 of the 19 accelerator entry points plus `read_input` /
   `write_output` come straight from there.
2. **`zkvm_secp256k1_ecrecover`** (`src/secp256k1`) — replaces the SDK's,
   which spends ~512 point doublings and ~256 additions per recovery. This one
   uses GLV and wNAF for ~128 and ~78, with identical results; every
   transaction sender goes through it. Tested on the host against a Python
   reference (`tests/secp256k1`) and on SP1 itself in CI.
3. **`zkvm_modexp`, `zkvm_bn254_g1_add` and `zkvm_bn254_g1_mul`**
   (`src/modexp`, `src/bn254`) — replace the SDK's, which run modexp in
   32-bit-limb software and BN254 G1 on the field precompiles alone. Moduli up
   to 256 bits go through UINT256_MUL with a 4-bit window (326 calls for a
   BN254 field inversion); wider ones still reach the SDK. G1 runs on the
   BN254_ADD/BN254_DOUBLE point precompiles, the multiplication with GLV and
   wNAF (~125 doublings, ~49 additions). On mainnet blocks that verify zk
   proofs this is -72..-78% of all cycles. Tested on the host against a Python
   reference (`tests/modexp`, `tests/bn254`) and on SP1 itself in CI.
4. **`zkvm_bn254_pairing` and `zkvm_kzg_point_eval`** (`src/pairing`) — replace
   the SDK's, whose curve crates reach the field precompiles one element at a
   time and copy every operand in and out. One Fp2/Fp6/Fp12 tower
   (`tower.h`) runs both curves on the BN254_FP2 and BLS12_381_FP2
   precompiles: sparse line products, a shared Miller loop over signed
   digits, cyclotomic squaring in the final exponentiation, and the fast
   subgroup checks (pi(Q) = [6x^2]Q on BN254 G2, phi(P) = -[x^2]P on
   BLS12-381 G1). KZG moves its G2 scalar multiplication into G1 so both G2
   points are constants. A two-pair pairing is -59% cycles / -40% gas, a
   point evaluation -75% / -66%. `model.py` is the integer reference the C
   follows and `gen_constants.py` derives every constant from it; tested on
   the host against py_ecc, go-ethereum's vectors and the official
   `verify_kzg_proof` suite (`tests/pairing`, `tests/kzg`), and on SP1 in CI.
5. **Raw precompile shims** (`src/sp1_syscalls`) — one three-instruction leaf
   per SP1 syscall, for anything the standard does not cover or that managed
   code wants to reach directly.

## Platform

This package also defines the SP1 target for bflat: `--libc sp1` selects
the platform that `platform/` describes, so bflat itself knows nothing about
SP1. `platform/build.sh` builds it into `output/` (`sp1_entry.o`, `sp1.ld` and `sp1.bflat.manifest`):

- `entry.S` is the guest's `_start` and the SP1 halt protocol, plus the 64-bit `memcpy`/`memmove`/`memset`, and `__wrap_main`, which returns the guest's exit code to SP1.
- `entry.S` also implements the platform interface that bflat's modules call
  (bflat itself has no code for any one zkVM): `zkvm_platform_exit` (`zkvm_halt` of libzkevm, or the commits and `HALT` without it) and `zkvm_platform_write` (the `WRITE` syscall).
- the linker script is the SP1 memory map;
- the platform manifest gives the instruction set, the ABI, the RyuJIT
  options, the defines and the post-link steps, and lists the bflat modules
  that the guest needs (format: `docs/manifest.md` in bflat-riscv64).

`--extlib` with a `.bflat.manifest` path reads every `*.bflat.manifest` in that
directory, so the platform and the bindings come together. A guest that does
not use the accelerators can be built with the platform files alone.
`tests/platform/run.sh` runs the unit tests of the entry point under qemu-user.

## Usage

```console
$ bflat build app.cs --os linux --arch riscv64 --libc sp1 \
      --extlib path/to/libsp1.bflat.manifest
```

Managed code then calls the accelerators through `Nethermind.Zkvm.Abstractions`,
whose `[LibraryImport("__Internal")]` declarations bind to these symbols
statically.

## Packaging

`src/runtime` packs the static library, the platform files and the manifests into
`Nethermind.Sp1.Runtime`, which is what a guest consumes:

```console
$ bflat build app.cs --os linux --arch riscv64 --libc sp1 \
      --extlib Nethermind.Sp1.Runtime
```

`.github/workflows/build-release.yml` builds the library, checks the exported
symbol surface, packs the nupkg on every push, and publishes to NuGet plus cuts
a GitHub release when run manually with `publish` set to Staging or Production.

## Signature

The release workflow signs the `.nupkg` before it publishes it. The build
job lists the package entries (`scripts/sign_package.py list-nupkg`). The
sign job, the reusable workflow `sign.yml` of bflat-riscv64, signs the lists
with the GitHub Actions secret `BFLAT_SIGNING_KEY`; it is the only job that
has the key, and it runs no build. The publish job adds the signatures
(`scripts/sign_package.py embed`) and checks them with the variable
`BFLAT_SIGNING_PUBLIC_KEY`. bflat refuses a package with a bad signature, and an
unsigned package unless `--allow-unsigned` is given. A local
`.bflat.manifest` is not checked. See `docs/signing.md` in bflat-riscv64.
`scripts/sign_package.py` is a copy of the script in bflat-riscv64; keep it
the same.

## Building locally

```console
$ ./build/build.sh
```

Needs `binutils-riscv64-linux-gnu`, `gcc-14-riscv64-linux-gnu` and `gh` (to fetch the SDK release; drop the
tarball into `tmp/` by hand to build offline). `SP1_REF` selects the SP1
release, default `v6.9.0`. Output lands in `output/`.

## Why some symbols are localized

Rust emits one codegen unit per crate, so a single member of `libzkevm.a`
defines the accelerators **and** `_start`, `exit`, `_exit`, `abort`,
`__assert_fail` and `memcpy`. Pulling in `zkvm_keccak256` therefore drags SP1's
entire entry/exit runtime along with it, colliding with the guest's own `_start`
(`platform/entry.S`), with pal's wrapped `exit`/`abort` and with musl's
`memcpy`. The build makes those local, so `libzkevm`'s internal calls still bind
to its own copies while the guest's versions stay the only globals.

`main` is deliberately **not** localized: `libzkevm` does not define it, it
*references* it — SP1's `__start` calls the guest's `main`. In a bflat guest
that reference is satisfied by `libbootstrapper.o`, or by
`--defsym=main=__managed__Main` under the zerolib stdlib.

## Coverage

Complete. Every symbol `Nethermind.Zkvm.Abstractions` imports is present:
`zkvm_keccak256`, `zkvm_sha256`, `zkvm_ripemd160`, `zkvm_blake2f`,
`zkvm_modexp`, `zkvm_secp256k1_ecrecover`, `zkvm_secp256k1_verify`,
`zkvm_secp256r1_verify`, `zkvm_bn254_g1_add`, `zkvm_bn254_g1_mul`,
`zkvm_bn254_pairing`, `zkvm_bls12_g1_add`, `zkvm_bls12_g1_msm`,
`zkvm_bls12_g2_add`, `zkvm_bls12_g2_msm`, `zkvm_bls12_pairing`,
`zkvm_bls12_map_fp_to_g1`, `zkvm_bls12_map_fp2_to_g2`, `zkvm_kzg_point_eval`,
`read_input`, `write_output`.

## Constraints

**Syscall ids are version-specific.** The shims in `src/sp1_syscalls` are taken
from SP1 v6 (`crates/zkvm/entrypoint/src/syscalls/mod.rs`), and the SDK is
pinned by `SP1_REF`. Keep both on the revision you prove with.

**An unknown syscall id is a hard `ExecutionError` in SP1.** This library and
pal's halt/console path are the only places a guest may issue an `ecall`.
