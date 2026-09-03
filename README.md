# Falcon512 Solidity Verifier

Gas-optimized Foundry/Rust repo for a prepared-input Falcon512 verifier.

## Gas

Latest local snapshot:

| Item | Gas |
| --- | ---: |
| Prepared verify, fixed valid Rust vector | 1,048,550 |
| Prepared verify, min / avg / median / max | 1,046,050 / 1,071,323 / 1,071,522 / 1,094,480 |
| Deployment | 2,057,898 |
| NIST hash-to-point alone | 441,008 |

Runtime size: 9,304 bytes. Deployment size: 9,547 bytes.

Hash-to-point alone is already above 300k gas, so getting full NIST-compatible verification below 300k would require a precompile, custom chain support, or a different trust model.

## Provenance

Core verifier logic comes from ZKNOX/ETHFALCON and has been further gas optimized here.

## Run

```sh
cargo test -p falcon512-oracle
cargo build -p falcon512-oracle
forge build
forge test
forge test --gas-report
```

## ABI

The contract verifies prepared inputs:

```solidity
verifyPrepared(bytes message, bytes salt, uint256[] s2, uint256[] ntth) returns (bool)
```

It does not decode raw Falcon signatures or public keys onchain. Tests use the no-std Rust Falcon512 implementation to generate canonical NIST signatures, prepare the Solidity inputs, and differential fuzz accept/reject behavior.

Requires Foundry, Rust, `ffi = true`, and the Keccak-f[1600] helper runtime in `test/fixtures/f1600_170.hex`.

Experimental and unaudited.
