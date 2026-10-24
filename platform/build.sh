#!/bin/bash
# Builds the SP1 platform for bflat guests into the output directory (the
# first argument; default: output/ in the repository):
#
#   - sp1_entry.o: entry.S assembled; the _start of the guest and the halt protocol
#   - sp1.ld: the memory map (linker script)
#   - sp1.bflat.manifest: the platform manifest (docs/manifest.md in bflat-riscv64)
#
# It needs only binutils for riscv64, not the bindings library, so bflat's
# own CI uses it to link guests for this platform. build/build.sh calls it
# for the package.
set -e

fail() { echo "$@" >&2; exit 1; }

PLATFORM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-$(cd "${PLATFORM_DIR}/.." && pwd)/output}"
AS="${AS:-riscv64-linux-gnu-as}"

command -v "${AS}" >/dev/null 2>&1 || fail "${AS} not found (apt install binutils-riscv64-linux-gnu)"
mkdir -p "${OUTPUT_DIR}"

# rv64ima and the soft-float ABI: the flags bflat used for its entry modules.
"${AS}" --march=rv64ima --mabi=lp64 "${PLATFORM_DIR}/entry.S" -o "${OUTPUT_DIR}/sp1_entry.o" \
    || fail "failed to assemble entry.S"
# Clear the float-ABI marker (e_flags, offset 0x30) so that ld.lld accepts the
# object against the guest's soft-float crt1.o.
printf '\x00' | dd of="${OUTPUT_DIR}/sp1_entry.o" bs=1 seek=48 count=1 conv=notrunc status=none

for f in sp1.ld sp1.bflat.manifest ; do
    cp "${PLATFORM_DIR}/${f}" "${OUTPUT_DIR}/${f}" || fail "failed to copy ${f}"
done

echo "Platform: ${OUTPUT_DIR}/sp1_entry.o sp1.ld sp1.bflat.manifest"
