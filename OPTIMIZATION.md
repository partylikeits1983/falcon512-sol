# Falcon512 gas optimization plan

Target: bring prepared-input, NIST-compatible verification below 1,000,000 gas
and continue reducing it while preserving the existing ABI and helper code hash.

1. Record the baseline, isolate polynomial and hash costs, and add independent
   arithmetic checks plus valid-signature and message-boundary coverage.
2. Optimize the packed polynomial pipeline: specialize assembly butterflies,
   fuse adjacent stages, read the prepared key directly, and reuse memory.
3. Reduce hashing/sampling/norm overhead where measurements justify it. Keep
   SHAKE256, rejection sampling, all 512 coefficients, and the Falcon norm bound.
4. Run Rust differential tests, adversarial arithmetic tests, gas regressions,
   formatting, and deployment-size checks; document measured costs and limits.

Measure verifier calls separately from Rust FFI, input preparation, and contract
deployment. Report execution gas and explain transaction/calldata overhead.
Message length and rejection sampling make verification cost variable; a gas
target for short messages is not a universal bound for arbitrary-length inputs.

Commit timestamps requested by the repository owner: first two commits use
2026-09-06 and 2026-09-07 at 15:30 CET (+01:00); later commits use the actual date.

## Result

The fixed-vector cold-helper execution cost decreased from 1,048,550 to 859,391
gas. The actual transaction consumes 912,399 gas. Full message-length and
deployment measurements are in the README and can be reproduced with
`python3 scripts/benchmark.py`. Measurements use Shanghai rules; the installed
Anvil does not support an Osaka benchmark.

The implementation preserves the prepared-input ABI and arithmetic semantics,
including its strict norm threshold and reduction of uint16 key residues.
The helper and its pinned runtime hash are unchanged. No signature coefficients,
SHAKE permutations, or rejection-sampling checks are omitted for valid inputs.

## Arithmetic bounds

Forward butterflies retain four 64-bit lanes and the existing conservative
4q subtraction bias. Scalar final-stage twiddle products use EVM MOD; packed
products use Barrett reduction with M = floor(2^40/q) = 89,471,204. The two
in-word stages share a loop and keep their intermediate word on the stack.

The inverse starts with canonical pointwise products, so each lane is below q.
Its first-stage sums are below 2q and differences are reduced with scalar MOD.
Second-stage sums are below 4q; the conservative 4q subtraction bias keeps
differences nonnegative. For each later stage, the subtraction bias equals
the incoming lane bound (4q, 8q, ..., 256q), while unreduced sums double it.
The final unscaled lane is below 512q. The largest twiddle/scaling product is
below 512q^2 < 2^37, and multiplying it by M remains below 2^64. Barrett's
quotient error is at most one, yielding a residue below 2q. The 24-bit mask
extracts each lane's quotient without contamination from the next lane.

Consequently, inverse sums need no modular reductions, and sampling can compute
`(candidate + 2q - productCoefficient) % q` with one MOD. Sampling checks the
512-coefficient limit separately for all four unrolled candidates. A nonnegative
partial norm reaching the preserved strict bound can never become acceptable,
so failing signatures can return before later SHAKE permutations.

The calldata range check clears the high bit of each uint16 lane and adds
2^15-q = 0x4fff. The largest resulting lane is 0xcffe, so no carry reaches an
adjacent lane. An original high bit or a high bit after addition means the
coefficient is at least q. This validates sixteen coefficients at once.

Twiddles are stored as big-endian uint16 byte tables, allowing CODECOPY
initialization and direct unaligned MLOAD/SHR lookup. Tests compute the forward
roots independently as 49 raised to the 9-bit-reversed index modulo q.

## Validation

- 1,024 fuzz cases each for forward/round-trip NTT, full calldata product and
  centered norm, selected schoolbook product coefficients, and SHAKE sampling.
- 64 valid-signature and 64 mutation cases against the Rust oracle, including
  messages through 512 bytes. The Rust crate itself currently has no unit tests;
  its verification function is exercised through Foundry FFI.
- Full 512-coefficient hash-to-point comparisons with Python hashlib at message
  lengths 0, 1, 94, 95, 96, 97, 231, 232, 233, and 4,096.
- Zero, maximal and alternating polynomial coefficients, invalid uint16 lanes,
  malformed lengths, excessive norms, rejection thresholds, sampler completion
  within an unrolled group, and helper return-size/revert failures.
- Solidity/Rust formatting, build and contract-size checks, an 880,000 execution
  gas ceiling on the fixed vector, and actual short-message transactions with
  a 1,000,000 gas limit.

## Limits and further work

Long inputs and rejection sampling prevent a universal sub-million bound.
The helper-backed SHAKE computation remains a substantial part of the cost.
These measurements do not establish a theoretical gas minimum.

Large-integer multiplication through MODEXP was considered as an alternative
to NTT. A whole-polynomial encoding would exceed the 1,024-byte operand limit
in [EIP-7823](https://eips.ethereum.org/EIPS/eip-7823), and MODEXP also has the
higher pricing in [EIP-7883](https://eips.ethereum.org/EIPS/eip-7883). The shipped
implementation does not depend on that precompile or its older pricing.
