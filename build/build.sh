#!/bin/bash
# Builds libsp1.a - the native half of the SP1 bindings for bflat guests.
#
# There is nothing to compile. SP1 ships a complete implementation of the
# eth-act zkVM accelerator standard as `libzkevm.a` (sources in sp1/zkevm/,
# published as the `zkevm-sdk-<version>.tar.gz` release asset), so this script
# fetches that archive and repackages it:
#
#   1. the SP1 SDK archive, with its runtime entry points made local, and
#   2. sp1_syscalls.o - raw precompile shims for anything the standard does not
#      cover, callable straight from managed code.
#
# WHY THE SYMBOLS ARE LOCALIZED. Rust emits one codegen unit per crate, so a
# single member of libzkevm.a defines the accelerators AND `_start`, `exit`,
# `_exit`, `abort`, `__assert_fail` and `memcpy`. Pulling in `zkvm_keccak256`
# therefore drags SP1's whole entry/exit runtime in with it, which collides with
# the guest's own `_start` (modules/zkvm_sp1/module.S), with pal's wrapped
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
SP1_REF="${SP1_REF:-v6.5.0}"
SP1_REPO="${SP1_REPO:-succinctlabs/sp1}"

AS="${AS:-riscv64-linux-gnu-as}"
AR="${AR:-riscv64-linux-gnu-ar}"
RANLIB="${RANLIB:-riscv64-linux-gnu-ranlib}"
OBJCOPY="${OBJCOPY:-riscv64-linux-gnu-objcopy}"

for tool in "${AS}" "${AR}" "${RANLIB}" "${OBJCOPY}" ; do
    command -v "${tool}" >/dev/null 2>&1 || fail "${tool} not found (apt install binutils-riscv64-linux-gnu)"
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
LOCALIZE="_start exit _exit abort __assert_fail memcpy"
LOCALIZE_ARGS=""
for sym in ${LOCALIZE} ; do
    LOCALIZE_ARGS="${LOCALIZE_ARGS} --localize-symbol=${sym}"
done
echo "Localizing SP1 runtime symbols:${LOCALIZE}"
"${OBJCOPY}" ${LOCALIZE_ARGS} "${OUTPUT_DIR}/libsp1.a" || fail "objcopy failed"

# --- 2. Raw precompile shims ----------------------------------------------
echo "Assembling sp1_syscalls.S..."
"${AS}" --march=rv64im --mabi=lp64 \
    "${ROOT_DIR}/src/sp1_syscalls/sp1_syscalls.S" \
    -o "${OUTPUT_DIR}/sp1_syscalls.o" || fail "assembly failed"
# Clear the float-ABI marker so ld.lld accepts the object against the guest's
# soft-float crt1.o. The SDK members are already 0x0.
printf '\x00' | dd of="${OUTPUT_DIR}/sp1_syscalls.o" bs=1 seek=48 count=1 conv=notrunc status=none

"${AR}" r "${OUTPUT_DIR}/libsp1.a" "${OUTPUT_DIR}/sp1_syscalls.o" || fail "ar failed"
"${RANLIB}" "${OUTPUT_DIR}/libsp1.a" || fail "ranlib failed"

# --- 3. Manifest -----------------------------------------------------------
cp "${ROOT_DIR}/bflat-manifest.json" "${OUTPUT_DIR}/libsp1.bflat.manifest"
if command -v jq >/dev/null 2>&1 ; then
    jq --arg ref "${SP1_REF}" '. + {sp1_ref: $ref}' \
        "${OUTPUT_DIR}/libsp1.bflat.manifest" > "${OUTPUT_DIR}/libsp1.bflat.manifest.tmp" \
        && mv "${OUTPUT_DIR}/libsp1.bflat.manifest.tmp" "${OUTPUT_DIR}/libsp1.bflat.manifest"
fi

echo "Build completed"
echo "Output: ${OUTPUT_DIR}/libsp1.a"
echo "        ${OUTPUT_DIR}/libsp1.bflat.manifest (sp1_ref: ${SP1_REF})"
