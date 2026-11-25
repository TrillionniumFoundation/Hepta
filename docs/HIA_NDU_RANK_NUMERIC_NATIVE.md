# Native NDU caller arithmetic

This checkpoint qualifies two HIA roles used by the ranking caller. It does not qualify the complete ranking operation, evaluator, background optimizer, multiversion publication or production activation.

## Exact costs

ndu_rank_cost uses the six-argument owned-buffer ABI. Input HIANRC01 is 128 bytes; output HIANRR01 is 256 bytes; scratch is at least 256 bytes. Mode 0 converts a nonnegative nanosecond count to signed Q32.32 milliseconds using nearest rounding with ties to even. The original exact integer and representability checks remain separate. Modes 1, 2 and 3 calculate preproof, selected-proof and final cost gates respectively.

For cost modes, offsets 16, 24, 32, 40, 48, 56, 64, 72 and 80 hold baseline runtime, baseline uncertainty, candidate runtime, candidate uncertainty, expected calls, supplied search cost, elapsed nanoseconds, cap and requested proof timeout. Public integer operands retain the original signed-63-bit nonnegative bounds, calls are positive and proof timeout is 1 through 5000 ms. Elapsed time occupies its original native u64 clock domain. The reserved tail is zero.

Products and sums use two u64 limbs, and signed differences use sign plus unsigned magnitude. This accommodates the complete 127-bit product range implied by the bounded public operands; it is not a limit on background or multiversion counters. Their independent arbitrary decimal owner remains required.

Output offsets: 8 mode; 16 conversion status; 24 ordered gate reason; 32 admitted proof timeout; 40 Q32 result; 48/56 spent cost; 64/72 baseline total; 80/88 candidate total; 96 budget sign with 104/112 magnitude; 120 margin sign with 128/136 magnitude; 144 baseline lower bound. The rest is zero. Conversion statuses distinguish nanosecond-domain refusal from Q32 overflow. Proof reason ordering, zero versus negative remaining budget, and strict one-millisecond margin checks match the original caller.

The actual sealed HIA role passed 8,126 comparisons: 1,249 against the original Q32 converter, 6,603 full-width arithmetic cases, 243 priority and threshold cases and 31 atomic private-frame guards.

## Exact binary64 allowance

ndu_rank_clock_budget accepts HIANRB01, 64 bytes: offset 8 contains the actual binary64 bits; 16 is the exact-integer classification obtained from the caller's own typed JSON admission; 24 is positive remaining nanoseconds; the tail is zero. The output is HIANBR01, 64 bytes; scratch is at least 128 bytes.

The role validates the original positive, finite, at-most-60-second interval; selects the minimum of the typed bridge timeout and remaining_ns / 1e9; preserves Python's first-argument behavior at an equal minimum; and calculates int(selected * 1e9) with the original binary64 multiply and rounding. It does not substitute decimal floor arithmetic. A fresh controller clock must still start the native deadline before image admission, and identity/sealing time must be deducted from that same deadline.

Output offsets: 8 status (0 admitted, 1 original timeout refusal, 2 no remaining budget); 16 selected binary64 bits; 24 selected exact-integer classification; 32 duration nanoseconds; 40 computed remaining-seconds bits (zero when remaining is at least 60 seconds); 48 selected integer value when applicable; 56 source (0 bridge, 1 remaining budget). Refusal outputs zero the data fields.

The actual sealed HIA role passed 6,356 cases, including 1,080 exact-integer cases, 3,200 floating budgets, 1,839 adjacent binary64 minimum boundaries, 36 original timeout refusals, 180 subnormal and extreme cases, and 21 atomic guards.

## Reproduction and custody

The companion JSON records the exact compiler, source, flat-image and independent qualification pins. The two qualifier tools take --flat and --output, load the actual native image through a sealed memfd, compare against the original Python arithmetic outside the native product, and verify immutable input and buffer canaries. The original 128-function, 1536-block, 8192-operation and 16-block-parameter compiler caps are unchanged.

Returning these pure results grants no program-safety, evaluator identity, publication or execution authority. The complete caller must still perform canonical admission, fresh proof, measured wall-time accounting, native image admission, owned process execution, exact response binding and final proof/cost checks.
