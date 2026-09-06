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
