# Falcon512 Solidity Verifier

Standalone Foundry/Rust workspace for differential testing a Solidity Falcon512 verifier against the no-std Rust implementation from `partylikeits1983/falcon512-stm32`.

The Rust oracle is pinned to commit `ce324854bd66c7dc1ce4418f9573efdb21c6b048` and is used from Foundry through FFI. There is no JavaScript test harness in this repo.

## Layout

- `src/Falcon512Verifier.sol`: public `verify(bytes signature, bytes publicKey, bytes message) returns (bool)` wrapper for canonical Falcon512 encodings.
- `src/FalconLegacy.sol`: minimized and optimized Solidity verifier core derived from the legacy PQClean/OQS port.
- `src/Falcon512Tables.sol`: packed NTT/iNTT tables kept in bytecode instead of verifier storage.
- `crates/falcon512-oracle`: Rust CLI oracle for deterministic key/signature generation and verification.
- `test/Falcon512Differential.t.sol`: Foundry tests and differential fuzzing against the Rust oracle.

## Canonical Encoding

The Solidity wrapper accepts the same fixed Falcon512 encoding as the Rust oracle:

- Signature: `0x59 || 40-byte salt || 625-byte padded compressed s`
- Public key: `0x09 || 896-byte 14-bit encoded h`

Messages are raw byte strings. The wrapper rejects messages longer than 65,535 bytes to keep internal length casts bounded.

## Verification

Install Foundry and Rust, then run:

```sh
cargo test -p falcon512-oracle
forge build
forge test -vv --match-contract Falcon512DifferentialTest
```

The Foundry tests require `ffi = true` because they invoke the Rust oracle.

## Gas Snapshot

Measured with:

```sh
forge test --gas-report --match-contract Falcon512DifferentialTest --match-test 'test_'
```

Current optimized snapshot:

- `Falcon512Verifier` deployment: `1,486,508` gas, deployment size `6,788` bytes.
- `Falcon512Tables` deployment: `1,006,400` gas, deployment size `4,444` bytes.
- Valid `verify`: `12,640,407` gas.
- Full-path rejecting `verify` examples: about `13.30M` gas.

Major optimization choices:

- Removed legacy storage-backed SHAKE/Keccak state and moved hashing to memory-only code.
- Moved NTT tables into a packed bytecode table contract and read entries with assembly loads.
- Specialized verification to Falcon512 constants.
- Packed Keccak rotation, pi, and round-constant lookup tables.
- Matched the Rust verifier's Falcon512 shortness bound, `34,034,726`.
- Matched the Rust public-key parser by reducing 14-bit public-key chunks modulo `q`.

This code is experimental and unaudited.
