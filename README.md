# Falcon512 Solidity Verifier

Gas-optimized Foundry/Rust repo for a prepared-input Falcon512 verifier.
The fixed valid signature costs **859,391 execution gas**, or **912,399 gas
as a transaction**, down from 1,048,550 execution gas (18.0% reduction).

## Gas

Actual transactions on a fresh local Anvil instance, Shanghai rules, Solidity
0.8.36, IR compiler, optimizer runs 1,000,000. Each verification starts with a
cold helper. Transaction gas includes the 21,000 base and calldata costs:

| Message bytes | Execution gas | Transaction gas |
| ---: | ---: | ---: |
| 0 | 859,780 | 912,816 |
| 16 (fixed Rust vector) | 859,391 | 912,399 |
| 95 | 908,355 | 962,987 |
| 96 | 903,060 | 957,524 |
| 232 | 994,468 | 1,051,108 |
| 512 | 1,080,959 | 1,141,755 |
| 1,024 | 1,211,702 | 1,280,966 |

These are deterministic vectors, not a worst-case bound. SHAKE rejection
sampling changes the number of permutations, and longer messages need more
absorption blocks. **The sub-million target is met for the tested short
messages; it is not a guarantee for every message/signature.**

Verifier deployment: 2,078,631 gas; runtime: 9,431 bytes; initcode: 9,623 bytes
before constructor arguments. The separate, reusable SHAKE helper costs
4,716,332 gas to deploy and has a 21,622-byte runtime.

Optimizations include fused packed NTT stages, deferred inverse reductions
with bounded lanes, direct calldata key multiplication in the existing buffer,
compact twiddle-table loads, parallel coefficient validation, unrolled hash
sampling, and early norm rejection. See [the optimization notes](OPTIMIZATION.md).

## Provenance

Core verifier logic comes from ZKNOX/ETHFALCON and has been further gas optimized here.

## Run

```sh
cargo test -p falcon512-oracle
cargo build -p falcon512-oracle
forge build
forge test
forge test --gas-report
forge test --match-contract 'PackedArithmeticTest|ShakeSamplingTest' --fuzz-runs 1024
forge test --match-test 'testFuzz_' --match-contract Falcon512ZKNOXOptimizedTest --fuzz-runs 64
python3 scripts/benchmark.py
```

## ABI

The contract verifies prepared inputs:

```solidity
verifyPrepared(bytes message, bytes salt, uint256[] s2, uint256[] ntth) returns (bool)
```

It does not decode raw Falcon signatures or public keys onchain. Each array has
32 words, with sixteen little-endian uint16 coefficients per word. `s2` contains
canonical residues below 12,289; `ntth` contains the prepared NTT public key.
The application must bind that prepared key to its authorized signer. The ABI,
SHAKE256 construction, helper code-hash requirement, and existing strict norm
comparison (`norm < 34,034,726`) are preserved.

Tests use the Rust Falcon512 implementation to generate signatures and
differential fuzz accept/reject behavior. Independent checks cover a scalar NTT,
schoolbook negacyclic multiplication, Python SHAKE256 hash-to-point, rejection
sampling boundaries, malformed inputs, and helper failures. CI checks both
execution gas and real transactions submitted with a one-million gas limit.

Requires Foundry (including Anvil and Cast for transaction benchmarks), Rust,
Python 3.9+, `ffi = true`, and the checked-in Keccak-f[1600] helper runtime in
`test/fixtures/f1600_170.hex`. The benchmark script starts and stops its own
loopback-only Anvil node; it uses no external RPC or wallet.

Experimental and unaudited.
