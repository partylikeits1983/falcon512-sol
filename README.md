# Falcon512 Solidity Verifier

**741,010 gas per verification transaction**, including **687,762 execution gas**
and 53,248 gas for the transaction base and calldata, for the fixed benchmark.
**Every benchmark signs and verifies a 32-byte Keccak-256 message digest.**

Hash the original message offchain, sign the 32 raw digest bytes with Falcon512,
and pass those same digest bytes to `Falcon512Verifier.verifyPrepared`.
The verifier accepts variable-length `bytes` and performs no implicit Keccak
prehashing. Longer inputs remain supported by the API.

## Gas

Actual transactions on a fresh local Anvil instance, Shanghai rules, Solidity
0.8.36, IR compiler, optimizer runs 1,000,000. Each verification starts with a
cold helper. Input preparation, offchain message hashing, and deployment are
separate from verification. Transaction gas includes the 21,000 base and calldata.

All rows pass **32 signed bytes** to the verifier. Source length describes the
message *before* Keccak-256; the fixed source is `00112233445566778899aabbccddeeff`.

| Source message bytes | Signed digest bytes | Execution gas | Total transaction gas |
| ---: | ---: | ---: | ---: |
| 0 | 32 | 688,144 | 741,248 |
| 16 (fixed vector) | 32 | 687,762 | 741,010 |
| 95 | 32 | 645,680 | 699,192 |
| 96 | 32 | 687,522 | 740,878 |
| 232 | 32 | 645,916 | 699,416 |
| 512 | 32 | 645,400 | 698,420 |
| 1,024 | 32 | 644,454 | 697,786 |

The measured transactions range from **697,786 to 741,248 gas**, all below one
million. Digest/signature contents change SHAKE rejection sampling and calldata
cost; these vectors do not establish a worst-case bound. Original message length
does not increase the bytes verified when only its digest is passed.

The digests of the 0-, 16-, 95-, and 512-byte sources also produce identical
transaction gas under Osaka rules, checked in CI with `--hardfork osaka`.
`--lengths` in `scripts/benchmark.py` selects source lengths before hashing;
the signed input is always 32 bytes and every transaction has a 1,000,000 gas limit.

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

Each case generates a key and signs the Keccak-256 digest of a source message
from fuzzed seeds, then compares Rust and Solidity on the valid signature and
altered digest, salt, signature coefficient, and public-key coefficient. All five variants must prepare
successfully and reach the Solidity verifier. Source messages range from 0 to
1,024 bytes; each signed digest is exactly 32 bytes. CI runs the same gate;
Foundry reports a reproducible counterexample if either implementation disagrees.

## ABI

The contract verifies prepared inputs. For the benchmarked signing flow,
`message` is the 32-byte Keccak-256 digest, not its ASCII hex encoding:

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
