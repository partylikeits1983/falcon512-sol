# Falcon512 Prepared Solidity Verifier

Standalone Foundry/Rust workspace for differential testing an optimized Solidity Falcon512 prepared verifier against the no-std Rust implementation from `partylikeits1983/falcon512-stm32`.

The Rust oracle is pinned to commit `ce324854bd66c7dc1ce4418f9573efdb21c6b048` and is used from Foundry through FFI. There is no JavaScript test harness in this repo.

## Layout

- `src/Falcon512ZKNOXOptimized.sol`: prepared-input verifier using the ZKNOX/ETHFALCON helper-backed SHAKE256 and packed NTT core.
- `src/ZKNOX_NTT_falcon_packed.sol`: packed-SWAR Falcon512 NTT/iNTT implementation.
- `src/ZKNOX_falcon_core_packed.sol`: packed NTT product builders used by the verifier.
- `src/ZKNOX_shake_fast.sol`: NIST SHAKE256 hash-to-point over the external Keccak-f[1600] helper.
- `src/ZKNOX_falcon_utils.sol`: Falcon512 constants and compact polynomial helpers.
- `crates/falcon512-oracle`: Rust CLI oracle for deterministic key/signature generation and verification.
- `test/Falcon512ZKNOXOptimized.t.sol`: differential fuzzing for the prepared ZKNOX path against the same Rust oracle.
- `test/fixtures/f1600_170.hex`: Keccak-f[1600] helper runtime used by the fast SHAKE path.

## Canonical Encoding

The Rust oracle generates and verifies the fixed Falcon512 NIST encoding:

- Signature: `0x59 || 40-byte salt || 625-byte padded compressed s`
- Public key: `0x09 || 896-byte 14-bit encoded h`

The Solidity contract intentionally does not expose a raw NIST decoding ABI. Tests decode Rust-generated signatures and public keys into prepared verifier inputs, then assert Solidity accepts/rejects the same cases as the Rust verifier.

## Prepared ZKNOX Path

`Falcon512ZKNOXOptimized.verifyPrepared(message, salt, s2, ntth)` is a lower-gas prepared verifier. It does not accept raw NIST signature/public-key bytes. The caller provides:

- `message`: raw message bytes.
- `salt`: the 40-byte Falcon salt from the signature.
- `s2`: the decoded signature vector in compacted ZKNOX form, 32 `uint256` words.
- `ntth`: the public key transformed to ZKNOX NTT form and compacted into 32 `uint256` words.

The fast SHAKE path requires the deployed `f1600_170.hex` helper and `evm_version = "shanghai"`.

## Verification

Install Foundry and Rust, then run:

```sh
cargo test -p falcon512-oracle
cargo build -p falcon512-oracle
forge build
forge test -vv --match-contract Falcon512ZKNOXOptimizedTest
```

The Foundry tests require `ffi = true` because they invoke `./target/debug/falcon512-oracle`.

## Gas Snapshot

Measured with:

```sh
forge test --gas-report --match-contract Falcon512ZKNOXOptimizedTest
```

Current optimized snapshot:

- `Falcon512ZKNOXOptimized` deployment: `2,057,898` gas, deployment size `9,547` bytes.
- Prepared `Falcon512ZKNOXOptimized.verifyPrepared`: `1,046,050` min, `1,071,323` avg, `1,071,522` median, `1,094,480` max gas in the current differential test run.
- Fixed valid Rust-vector `verifyPrepared` call: `1,048,550` gas.
- Helper-backed NIST `hashToPoint` alone is about `441,008` gas, before NTT/core verification work.

The current NIST-compatible verifier cannot get near `300,000` gas with this architecture: hash-to-point alone is already above that. Hitting that range would require a precompile/custom chain support or changing the trust/ABI model so the contract no longer performs full NIST hash-to-point and Falcon relation checks onchain.

Major optimization choices:

- Removed the legacy raw verifier contracts from this standalone repo; the Solidity surface is the prepared optimized verifier.
- Specialized verification to Falcon512 constants.
- Matched the Rust verifier's Falcon512 shortness bound, `34,034,726`.
- Matched the Rust public-key parser by reducing 14-bit public-key chunks modulo `q`.
- Added the ZKNOX helper-backed SHAKE256 path and packed-SWAR NTT verifier core.
- Avoided redundant calldata-to-memory copies for the prepared verifier's `salt`, `message`, `s2`, and `ntth` inputs.
- Fused hash-to-point sampling with the `s1` norm check instead of materializing a 512-word hash array.
- Consumed the inverse NTT product in 128-word packed form instead of unpacking it to 512 memory words.
- Computed `s2` range and norm while packing `s2` for the NTT, avoiding a second 512-coefficient pass.
- Pinned the Keccak helper in the constructor and removed the redundant per-call codehash check.

This code is experimental and unaudited.
