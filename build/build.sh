#!/bin/bash
# Builds libsp1.a - the native half of the SP1 bindings for bflat guests.
#
# SP1 ships a complete implementation of the eth-act zkVM accelerator standard
# as `libzkevm.a` (sources in sp1/zkevm/, published as the
# `zkevm-sdk-<version>.tar.gz` release asset), so this script fetches that
# archive and repackages it:
#
#   1. the SP1 SDK archive, with its runtime entry points made local,
#   2. sp1_syscalls.o - raw precompile shims for anything the standard does not
#      cover, callable straight from managed code, and
#   3. secp256k1_ecrecover.o - zkvm_secp256k1_ecrecover, replacing the SDK's
#      (see src/secp256k1/ecrecover.c for why), whose copy is made local, and
#   4. modexp.o and bn254_g1.o - zkvm_modexp, zkvm_bn254_g1_add and
#      zkvm_bn254_g1_mul on the UINT256_MUL and BN254 point precompiles (see
#      src/modexp/modexp.c and src/bn254/g1.c). The SDK's G1 copies are made
#      local; its modexp is renamed sp1_sdk_zkvm_modexp, the fallback for
#      moduli above 256 bits, and
#   5. bn254_pairing.o and bls12_381_kzg.o - zkvm_bn254_pairing and
#      zkvm_kzg_point_eval on the field precompiles (see src/pairing/tower.h),
#      whose SDK copies are made local.
#
# WHY THE SYMBOLS ARE LOCALIZED. Rust emits one codegen unit per crate, so a
# single member of libzkevm.a defines the accelerators AND `_start`, `exit`,
# `_exit`, `abort`, `__assert_fail` and `memcpy`. Pulling in `zkvm_keccak256`
# therefore drags SP1's whole entry/exit runtime in with it, which collides with
# the guest's own `_start` (platform/entry.S), with pal's wrapped
# exit/abort and with musl's memcpy. Making them local keeps libzkevm's internal
# calls bound to its own copies while leaving the guest's versions the only
# globals the link can see.
set -e

fail() { echo "$@" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/output"
TMP_DIR="${ROOT_DIR}/tmp"

# Pin the SP1 release the SDK is taken from. The syscall ids in
# src/sp1_syscalls are tied to the same revision.
SP1_REF="${SP1_REF:-v6.9.0}"
SP1_REPO="${SP1_REPO:-succinctlabs/sp1}"

AS="${AS:-riscv64-linux-gnu-as}"
# The compiler version alone moves the cost of a recovery on SP1, so it is pinned.
CC="${CC:-riscv64-linux-gnu-gcc-14}"
AR="${AR:-riscv64-linux-gnu-ar}"
RANLIB="${RANLIB:-riscv64-linux-gnu-ranlib}"
OBJCOPY="${OBJCOPY:-riscv64-linux-gnu-objcopy}"

for tool in "${AS}" "${CC}" "${AR}" "${RANLIB}" "${OBJCOPY}" ; do
    command -v "${tool}" >/dev/null 2>&1 || fail "${tool} not found (apt install binutils-riscv64-linux-gnu gcc-14-riscv64-linux-gnu)"
done

mkdir -p "${OUTPUT_DIR}" "${TMP_DIR}"
rm -f "${OUTPUT_DIR}/libsp1.a"

# --- 1. SP1 zkEVM SDK ------------------------------------------------------
SDK_TARBALL="${TMP_DIR}/zkevm-sdk-${SP1_REF}.tar.gz"
if [ ! -f "${SDK_TARBALL}" ] ; then
    echo "Fetching zkevm-sdk ${SP1_REF} from ${SP1_REPO}..."
    command -v gh >/dev/null 2>&1 || fail "gh not found; download zkevm-sdk-${SP1_REF}.tar.gz to ${SDK_TARBALL} by hand"
    gh release download "${SP1_REF}" --repo "${SP1_REPO}" \
        --pattern "zkevm-sdk-*.tar.gz" --output "${SDK_TARBALL}" --clobber \
        || fail "failed to download the zkevm SDK"
fi

# Stream the one member we need straight out of the tarball. Unpacking the
# whole tree would also create include/ and zkvm.ld, which we do not use, and
# fails outright on some bind-mounted filesystems.
tar -xzOf "${SDK_TARBALL}" --wildcards '*/libzkevm.a' > "${OUTPUT_DIR}/libsp1.a" \
    || fail "failed to extract libzkevm.a from the zkevm SDK"
[ -s "${OUTPUT_DIR}/libsp1.a" ] || fail "libzkevm.a missing from the SDK archive"

# The guest owns these; see the note at the top. `main` is deliberately NOT in
# the list: libzkevm does not define it, it REFERENCES it (SP1's `__start` calls
# the guest's main), so localizing it would turn a resolvable undefined symbol
# into an unresolvable one. In a bflat guest that reference is satisfied by
# libbootstrapper.o, or by --defsym=main=__managed__Main for the zerolib stdlib.
#
# zkvm_secp256k1_ecrecover and the BN254 G1 entry points are localized for a
# different reason: steps 3 and 4 below supply the guest-facing definitions.
LOCALIZE="_start exit _exit abort __assert_fail memcpy zkvm_secp256k1_ecrecover zkvm_bn254_g1_add zkvm_bn254_g1_mul zkvm_bn254_pairing zkvm_kzg_point_eval"
LOCALIZE_ARGS="--redefine-sym=zkvm_modexp=sp1_sdk_zkvm_modexp"
for sym in ${LOCALIZE} ; do
    LOCALIZE_ARGS="${LOCALIZE_ARGS} --localize-symbol=${sym}"
done
echo "Localizing SP1 runtime symbols:${LOCALIZE}; renaming zkvm_modexp to sp1_sdk_zkvm_modexp"
"${OBJCOPY}" ${LOCALIZE_ARGS} "${OUTPUT_DIR}/libsp1.a" || fail "objcopy failed"

# --- 2. Raw precompile shims ----------------------------------------------
echo "Assembling sp1_syscalls.S..."
"${AS}" --march=rv64im --mabi=lp64 \
    "${ROOT_DIR}/src/sp1_syscalls/sp1_syscalls.S" \
    -o "${OUTPUT_DIR}/sp1_syscalls.o" || fail "assembly failed"
# Clear the float-ABI marker so ld.lld accepts the object against the guest's
# soft-float crt1.o. The SDK members are already 0x0.
printf '\x00' | dd of="${OUTPUT_DIR}/sp1_syscalls.o" bs=1 seek=48 count=1 conv=notrunc status=none

# --- 3. secp256k1 recovery, 4. modexp and BN254 G1, 5. pairings -----------
# SP1 charges per executed instruction, not per byte of code, so optimize for
# speed alone.
compile() {
    echo "Compiling $1..."
    "${CC}" -march=rv64im -mabi=lp64 -mcmodel=medany -fno-pic -ffreestanding \
        -fno-stack-protector -O3 -funroll-loops -std=c11 -Wall -Wextra -Werror \
        -c "${ROOT_DIR}/src/$1" -o "${OUTPUT_DIR}/$2" || fail "compilation failed"
}
compile secp256k1/ecrecover.c secp256k1_ecrecover.o
compile modexp/modexp.c modexp.o
compile bn254/g1.c bn254_g1.o
compile pairing/bn254_pairing.c bn254_pairing.o
compile pairing/bls12_381_kzg.c bls12_381_kzg.o

"${AR}" r "${OUTPUT_DIR}/libsp1.a" "${OUTPUT_DIR}/sp1_syscalls.o" \
    "${OUTPUT_DIR}/secp256k1_ecrecover.o" "${OUTPUT_DIR}/modexp.o" \
    "${OUTPUT_DIR}/bn254_g1.o" "${OUTPUT_DIR}/bn254_pairing.o" "${OUTPUT_DIR}/bls12_381_kzg.o" || fail "ar failed"
"${RANLIB}" "${OUTPUT_DIR}/libsp1.a" || fail "ranlib failed"

# --- 6. Manifest -----------------------------------------------------------
cp "${ROOT_DIR}/bflat-manifest.json" "${OUTPUT_DIR}/libsp1.bflat.manifest"
if command -v jq >/dev/null 2>&1 ; then
    jq --arg ref "${SP1_REF}" '.metadata.sp1_ref = $ref' \
        "${OUTPUT_DIR}/libsp1.bflat.manifest" > "${OUTPUT_DIR}/libsp1.bflat.manifest.tmp" \
        && mv "${OUTPUT_DIR}/libsp1.bflat.manifest.tmp" "${OUTPUT_DIR}/libsp1.bflat.manifest"
fi

# --- 5. Platform ---------------------------------------------------------
# The entry point, the memory map and the platform manifest (platform/).
AS="${AS}" "${ROOT_DIR}/platform/build.sh" "${OUTPUT_DIR}" || fail "platform build failed"

echo "Build completed"
echo "Output: ${OUTPUT_DIR}/libsp1.a"
echo "        ${OUTPUT_DIR}/libsp1.bflat.manifest (sp1_ref: ${SP1_REF})"
