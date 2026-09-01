# SP1 runtime

[![Nethermind.Sp1.Runtime](https://img.shields.io/nuget/v/Nethermind.Sp1.Runtime)](https://www.nuget.org/packages/Nethermind.Sp1.Runtime)

SP1 zkVM accelerators for the Nethermind guest for [SP1](https://github.com/succinctlabs/sp1),
consumed by [bflat-riscv64](https://github.com/NethermindEth/bflat-riscv64)
guests through `--extlib` and called from managed code through
[Nethermind.Zkvm.Abstractions](https://www.nuget.org/packages/Nethermind.Zkvm.Abstractions).

The package ships `libsp1.a` together with the `*.bflat.manifest` that tells
bflat which target triple it belongs to.

## License

This package contains a statically linked build of SP1's zkEVM SDK
(`libzkevm.a`), licensed under the
[Apache-2.0](https://github.com/succinctlabs/sp1/blob/main/LICENSE-APACHE) and
[MIT](https://github.com/succinctlabs/sp1/blob/main/LICENSE-MIT) dual licenses.
