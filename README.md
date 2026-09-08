# Falcon512 Solidity Verifier

**695,970 gas per verification transaction** for the fixed valid Falcon512
signature with a 16-byte message. This includes **642,962 execution gas** plus
53,008 gas for the transaction base and calldata. Execution gas is **38.7% lower**
than the original 1,048,550 gas.

These figures measure `Falcon512Verifier.verifyPrepared` with a cold SHAKE
helper. Inputs are prepared offchain; deployment is a separate, one-time cost.
The measured 512-byte-message transaction also fits below one million gas,
at **918,273 gas**. Costs for each tested message length are below.

## Gas

Actual transactions on a fresh local Anvil instance, Shanghai rules, Solidity
0.8.36, IR compiler, optimizer runs 1,000,000. Each verification starts with a
cold helper. Transaction gas includes the 21,000 base and calldata costs:

| Message bytes | Execution gas | Total transaction gas |
| ---: | ---: | ---: |
| 0 | 646,121 | 699,157 |
| 16 (fixed Rust vector) | 642,962 | 695,970 |
| 95 | 687,230 | 741,862 |
| 96 | 688,068 | 742,532 |
| 232 | 772,538 | 829,178 |
| 512 | 857,477 | 918,273 |
| 1,024 | 984,282 | 1,053,546 |

These are deterministic vectors, not a worst-case bound. SHAKE rejection
sampling changes the number of permutations, and longer messages need more
absorption blocks. **The sub-million target is met for the tested
messages through 512 bytes; it is not a guarantee for every message/signature.**

The 0-, 16-, 95-, and 512-byte cases also produce the same transaction gas under
Osaka rules, checked in CI with `--hardfork osaka`.

Verifier deployment: 4,657,364 gas; runtime: 21,487 bytes; initcode: 21,679 bytes
before constructor arguments. The separate, reusable SHAKE helper costs
4,241,537 gas to deploy and has a 19,392-byte runtime.

The verifier processes eight polynomial coefficients per EVM word, using
32-bit Montgomery lanes and stage-specific bounds. Its assembly kernel fuses
the inner transforms with key multiplication and merges inverse normalization
into the final butterflies. Signature packing and hash sampling both use this
layout directly, with no intermediate polynomial conversion. One packed
multiplication sums eight signature squares, and hash sampling folds centering
into modular reduction without a branch. Candidates are read directly from the
SHAKE state, which keeps four copies of each lane between helper calls to
avoid repeated representation conversions. Full sampler blocks omit redundant
output bounds checks; partial blocks retain output bounds. Groups of four accepted candidates share one
branch and offset update; mixed groups use individual checks. The final block
stops once all 512 coefficients are consumed. The NTT word butterfly bodies
are unrolled, while final normalization processes 16 pairs per iteration to
control bytecode size.
The runtime is 3,089 bytes below the 24,576-byte contract size limit. See [the optimization notes](OPTIMIZATION.md).

New deployments require `test/fixtures/f1600_resident.hex`; the constructor pins
its code hash, `0xc5087c236ef4a48e463c4732a78010e18bb213a3c917965376b445b784cd5fcb`.
The original helper remains a test reference. Generate/check the new wrapper
with `scripts/generate_resident_helper.py`; its permutation body is unchanged.

## Provenance

Core verifier logic comes from ZKNOX/ETHFALCON and has been further gas optimized here.

Contract and source names are now project-specific. Original attribution for the
utility and arithmetic code is retained here: Copyright (C) 2026 - ZKNOX.
The SHAKE glue and helper derive from [Fireblocks' MIT-licensed implementation](https://github.com/fireblocks-labs/evm-ml-dsa-verifier/tree/cca262b537a5ac2ee55efb427e5c61de0308e566);
the source retains its Fireblocks notices. The original utility header stated:
"This Code may be reused including this header, license and copyright notice."

The following MIT notice applies to the reused portions:

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Run

```sh
cargo test -p falcon512-oracle
cargo build -p falcon512-oracle
forge build
forge test
forge test --gas-report
forge test --match-contract 'PackedArithmeticTest|ShakeSamplingTest|ResidentKeccakTest' --fuzz-runs 1024
forge test --match-test 'testFuzz_' --match-contract Falcon512VerifierTest --fuzz-runs 64
python3 scripts/benchmark.py
python3 scripts/check_twiddles.py
python3 scripts/generate_ntt_loops.py
python3 scripts/generate_resident_helper.py
```

Before moving to another optimization target, run the fresh-signature gate:

```sh
cargo build --release -p falcon512-oracle
FALCON_ORACLE=./target/release/falcon512-oracle forge test \
  --match-test testFuzz_GeneratedSignaturesReachVerifier --fuzz-runs 1024
```

Each case generates a key and signature from fuzzed seeds, then compares Rust
and Solidity on the valid signature and altered message, salt, signature
coefficient, and public-key coefficient. All five variants must prepare
successfully and reach the Solidity verifier. Messages range from 0 to 1,024
bytes. CI runs the same gate; Foundry reports a reproducible counterexample
if either implementation disagrees.

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
`test/fixtures/f1600_resident.hex`. The benchmark script starts and stops its own
loopback-only Anvil node; it uses no external RPC or wallet.
CI uses Foundry nightly; older formatters can produce different assembly
formatting, so use a recent Foundry version for `forge fmt`.

Experimental and unaudited.
