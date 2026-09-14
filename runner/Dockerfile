# Executes a bflat-built SP1 guest ELF and prints its cycle count and public
# values.
#
# WHY THIS EXISTS. SP1 publishes no image that runs an arbitrary ELF:
# ghcr.io/succinctlabs/sp1 carries the Rust toolchain for BUILDING guests and
# nothing that executes one, and the SDK is a library, not a CLI. Consumers -
# this repository's own integration job, and nethermind's stateless tests -
# would each have to compile a harness from source, ~15 minutes a run. They
# pull this instead.
#
#   docker run --rm --shm-size=8g -v "$PWD:/n" nethermindeth/sp1-runner:v6.5.0 \
#       /n/nethermind /n/input.raw [expected-hex]
#
# The input is RAW SSZ. The .ssz files in the test bucket are ZisK-framed (a
# u64le length, the payload, padding to 8); ziskos strips that, SP1 does not.
#
# --shm-size is not optional: SP1's native executor maps guest memory through
# /dev/shm. Docker's default of 64 MB fails and so does 1g; 4g is the smallest
# tested value that carries a mainnet block (actual usage ~2.7 GB). Too small
# and the run prints an empty output and exits non-zero, which reads exactly
# like a broken guest and is not.
# protobuf-compiler alone is not enough: sp1-prover-types compiles .proto files
# that import google/protobuf/empty.proto, and those well-known definitions ship
# in libprotobuf-dev. Without it the build dies in a build script with
# "File not found" rather than anything that names the missing package.
# PORTABLE=1 builds the variant whose executor prints the guest's console
# output (see runner/Cargo.toml). Slower, and published under its own tag.
FROM rust:1.91-bookworm AS build
ARG PORTABLE=
WORKDIR /src
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      pkg-config libssl-dev cmake \
      protobuf-compiler libprotobuf-dev \
 && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release ${PORTABLE:+--features portable}

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/sp1runner /usr/local/bin/sp1runner
ENTRYPOINT ["/usr/local/bin/sp1runner"]
