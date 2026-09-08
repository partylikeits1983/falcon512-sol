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

The fixed-vector cold-helper execution cost decreased from 1,048,550 to 642,962
gas. The actual transaction consumes 695,970 gas. Full message-length and
deployment measurements are in the README and can be reproduced with
`python3 scripts/benchmark.py`. The complete table uses Shanghai rules.
The 0-, 16-, 95-, and 512-byte transactions were also tested with Osaka rules on a
newer Anvil and have identical gas costs; both forks are covered in CI.

The implementation preserves the prepared-input ABI and arithmetic semantics,
including its strict norm threshold and reduction of uint16 key residues.
The helper and its pinned runtime hash are unchanged. No signature coefficients,
SHAKE permutations, or rejection-sampling checks are omitted for valid inputs.

## Four-lane reference bounds

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

## Eight-lane production kernel

`FalconNTTMontgomery.sol` uses eight 32-bit lanes. Twiddles are Montgomery
encoded with R=2^16, so inputs and outputs remain ordinary field residues.
For a lane product x, the reduction is `(x + m*q) >> 16`, where
`m = ((x & 65535) * 12287) & 65535`. The initial mask makes the correction
multiplication fit each 32-bit lane; -q^-1 modulo R equals 12287.

Starting from canonical input, the six word-aligned forward stages use biases
2q, 2q, 2q, 3q, 3q, 4q. Their output bounds are 3q, 5q, 7q, 10q, 13q, 17q.
No reductions of the additive branches are needed. Before the middle kernel,
a packed Barrett step using floor(2^18/q)=21 reduces each lane below 2q.
The masked quotient is at most 16, and the multiplier product fits 32 bits.

The middle kernel combines the remaining three forward stages, the pointwise
key product, and three inverse stages. Scalar products use MULMOD for arbitrary
uint16 key residues. Its output lanes are below 4q. Inverse word-aligned sums
are conditionally reduced by 4q using lane guard bits; differences receive a
4q bias and Montgomery reduction. Both branches stay below 4q.

The final inverse butterflies incorporate normalization. Their Montgomery
multipliers are 128 (=R/512) and 4977 (=inverseRoot[1]*R/512 mod q).
Both products are below q*R for incoming differences/sums below 8q, so the
final coefficients are below 2q, as required by the norm sampler.
`python3 scripts/check_twiddles.py` checks the table contents, constants,
and conservative integer inequalities establishing all these bounds.

The signature is validated and packed directly into 64 eight-lane words.
The norm sampler reads the result in this same layout; it never expands into
individual coefficients or the older four-lane representation. The old kernels
and conversion helpers remain independent comparison paths for tests and are
eliminated from the deployed verifier by the compiler.

## Packed sum of squares and centered sampling

Signature packing spreads eight uint16 coefficients into eight uint32 lanes
with three mask/shift steps. Adding 0x67ff independently to each lane exposes
the comparison with 6144 in bit 15. A conditional complement and addition of
q+1, masked to 16 bits, produces each centered magnitude without a branch.

Let B=2^32 and A=sum(a[i]*B^i), where 0<=a[i]<=6144 for each of eight lanes.
Multiply A by its lane reversal. The coefficient of B^7 is sum(a[i]^2).
Every convolution coefficient is at most 8*6144^2=301,989,888, below B, so
there are no inter-lane carries. SHR(224, MUL(A, reverse(A))) therefore returns
all eight squares summed exactly. Higher polynomial terms are discarded by
EVM word truncation. Invalid signature lanes still set the range flag and are
rejected before this norm is used.

The sampler uses `(t + 30722 - productCoefficient) % q - 6144`, with
30722=2q+6144. The MOD argument is nonnegative because product lanes are below
2q. This combines reduction and centering into one MOD and one subtraction,
without a comparison or conditional branch. Negative results are represented
modulo 2^256; squaring with MUL returns the exact nonnegative square since
its magnitude is at most 6144.

The Python constant checker exhausts all q scalar centering inputs. Solidity
fuzz tests compare the full-range packed norm with scalar sums and exercise
all lanes at both 6144 and 6145, as well as random valid signatures and mutations.

## Direct-state sampling

A 136-byte SHAKE rate block has at most 68 candidates. If the starting count
is at most 444, even accepting every candidate cannot exceed 512 outputs.
This path omits per-candidate output bound checks. Later blocks retain each
check, including completion within a group of four candidates.

The production sampler reads lanes 0 through 16 directly from the helper's
25-word state. Each lane is a uint64 with little-endian bytes. Swapping the
bytes within each uint16 yields Falcon's big-endian candidates; no serialized
rate block is allocated or written. Sampling leaves the state unchanged for
the next permutation and never consumes the capacity lanes.

Tests compare this path with both byte-buffer samplers and the scalar loop,
including counts 444/445, completion within a group, all-rejected blocks, and
nonzero capacity lanes. A further per-iteration completion check increased the
fixed-vector cost for this initial direct-state sampler.

## Four-candidate acceptance batches

The sampler tests all four candidates in a state lane together. For a uint16
candidate `t`, `((t & 0x7fff) + 0x0ffb) & t & 0x8000` is nonzero exactly when
`t >= 5q = 61445`. Adding 4091 to the low 15 bits never reaches 65536, so the
same mask works independently across all four adjacent lanes. The Python
checker exhausts all 65,536 candidate values.

When every candidate passes, four scalar centered squares are accumulated
together, with one output-offset update and no individual acceptance branches.
Mixed groups retain the scalar fallback. The partial-block path also requires
four remaining output slots before batching; its fallback checks each slot.
Tests exercise all 16 acceptance patterns, every packed-word alignment, and
counts 507 through 511, in addition to random sampling and fresh signatures.

The combined path makes stopping the final loop as soon as 512 outputs are
consumed profitable: it now skips both the batch threshold and fallback work.
This was measured again with the new body, rather than assuming the earlier
completion-check result still applied.

## Resident replicated SHAKE lanes

The permutation already represents each uint64 lane as four identical copies
within an EVM word. Keeping that representation in the caller removes the
helper's repeated entry multiplication and exit masking. Absorption replicates
each message lane before XOR; sampling reads only the low uint64. Zero state,
replicated XOR, and the existing permutation preserve the representation.

`scripts/generate_resident_helper.py` extracts the unchanged straight-line
permutation from the SHA-256-pinned original helper. It checks the extraction
boundaries and absence of control flow or calldata access, then emits a new
wrapper. Its 832-byte interface ignores a prefix word and consumes 25 replicated
lanes; it returns all 25 replicated lanes. The caller passes the already
allocated word preceding the state as the ignored prefix, without modifying it.
The 800-byte clean-lane interface remains available for independent reference
checks. Other input lengths revert.

The constructor pins the new helper's code hash. Tests compare all 25 lanes
in both interfaces against the original helper on 1,024 random states, check
full replication of every output, and test malformed lengths. Sampler tests
also exercise replicated input states. The resident permutation costs 40,454
gas versus 41,373 for the original wrapper; full verification measurements
include the changed absorption, masking, and call-data copying costs.

## Loop specialization

Word-aligned butterfly bodies are unrolled. Final normalization uses two
iterations of 16 pairs, freeing space for the sampler specialization.
The field operations, twiddle ordering, and bounds above remain unchanged.
`scripts/generate_ntt_loops.py` derives each offset, stage bias, and root index
from the stage width and checks the checked-in assembly. Regenerate with
`--write`, then run `forge fmt`; CI checks the generated sections.

The measured runtime is 21,487 bytes, leaving 3,089 bytes below the deployment
limit. This deliberately prioritizes per-verification gas over deployment gas:
the verifier now costs 4,657,364 gas to deploy, plus the reusable resident
helper's 4,241,537 gas deployment. Both deployments were exercised on Shanghai
and Osaka.

## Measured progression

| Kernel | Fixed-vector execution gas |
| --- | ---: |
| Original implementation | 1,048,550 |
| First optimized implementation | 859,391 |
| Fused four-lane transforms and normalization | 823,743 |
| Eight-lane Montgomery, before packing refinements | 787,114 |
| Deferred forward reductions | 770,603 |
| Native signature packing | 752,761 |
| Native product sampling | 737,593 |
| Fully unrolled word butterflies and normalization | 713,557 |
| Branchless scalar centering | 703,195 |
| Packed signature sum of squares | 682,907 |
| Centering folded into sampler reduction | 674,203 |
| Full-block bounds specialization and smaller normalization loop | 667,896 |
| Direct SHAKE-state sampling | 662,960 |
| Four-candidate batches in full blocks | 651,624 |
| Batches in partial blocks with four remaining slots | 650,364 |
| Stop the final batch loop at completion | 649,308 |
| Keep replicated SHAKE lanes resident between calls | 642,962 |

## Validation

- 1,024 fuzz cases each for forward/round-trip NTT, full calldata product and
  centered norm, full-range fused products (four- and eight-lane kernels),
  selected schoolbook product coefficients, and SHAKE sampling in both layouts.
- 1,024 valid-signature and 1,024 mutation cases against the Rust oracle, including
  messages through 512 bytes. The Rust crate itself currently has no unit tests;
  its verification function is exercised through Foundry FFI.
- 1,024 newly generated signatures with messages through 1,024 bytes, each
  checked alongside four canonically encoded mutations: 5,120 Rust/Solidity
  acceptance comparisons, with no preparation skips or mismatches.
- Full 512-coefficient hash-to-point comparisons with Python hashlib at message
  lengths 0, 1, 94, 95, 96, 97, 231, 232, 233, and 4,096.
- Zero, maximal and alternating polynomial coefficients, invalid uint16 lanes,
  malformed lengths, excessive norms, rejection thresholds, sampler completion
  within an unrolled group, and helper return-size/revert failures.
- Solidity/Rust formatting, build and contract-size checks, a 645,000 execution
  gas ceiling on the fixed vector, and actual short-message transactions with
  a 1,000,000 gas limit, including the 512-byte vector (918,273 transaction gas).

## Limits and further work

Long inputs and rejection sampling prevent a universal sub-million bound.
The helper-backed SHAKE computation remains a substantial part of the cost.
These measurements do not establish a theoretical gas minimum.

Large-integer multiplication through MODEXP was considered as an alternative
to NTT. A whole-polynomial encoding would exceed the 1,024-byte operand limit
in [EIP-7823](https://eips.ethereum.org/EIPS/eip-7823), and MODEXP also has the
higher pricing in [EIP-7883](https://eips.ethereum.org/EIPS/eip-7883). The shipped
implementation does not depend on that precompile or its older pricing.

## Continuing optimization work

The naming cleanup is complete: production/test/script identifiers and filenames
use project-specific names, with original attribution retained in the README.
The global optimization goal remains active. A theoretical minimum has not
been proven; a successful gas regression test cannot establish that claim.

The helper-backed Keccak-f permutation and sponge integration remain candidates
for further work. Any replacement must match all state lanes and Python SHAKE
vectors, respect EIP-170, and win under Osaka transaction accounting. The NTT
word butterfly bodies are unrolled and sampling reads the state directly.
Four accepted candidates now share one branch and offset update. Remaining
candidates include packed arithmetic for their norms and different Keccak
permutation layouts. Bytecode tradeoffs should be measured together, including
reductions in unrolling when needed.

A packed-column Keccak prototype matched all 25 lanes of the original helper
on 64 random states, but was slower. The original wrapper costs 41,373 gas;
the best prototype compilation measured 77,292 gas. The standard Solidity
optimizer duplicated large expressions across memory stores. The prototype
was not integrated. A subsequent raw-EVM packed-column implementation matched
1,024 random states but still cost 69,034 gas per permutation, so it was also
rejected. Production retains the original permutation body with the resident
wrapper described above.

Before moving between optimization targets, generate 1,024 fresh signatures
with fuzzed key/signing seeds and run the prepared-mutation gate documented in
the README. Each case must reach Solidity for the valid signature and all four
mutations, and match the Rust verifier. Preparation failures must fail the test
rather than silently skip a case.
