# Bounded x86_64 byte-sum lowering

This native lowering recognizes one complete loop shape after immutable Core
verification. It does not add a Core opcode or change the checked reduction
proof. The original source, Core, allocation attempts, refusal values and owner
release operations are retained.

## Admission and equivalence

The loop header must compare an unsigned machine-size index with an unchanged
limit using strict less-than. Its body must have exactly seven operations:
read borrow, byte load, end loan, unsigned byte-to-u64 cast, wrapping u64 add,
usize constant one, and wrapping index add. The sole predecessor, complete
identity transport and backedge must match. Checked additions, a different
stride, extra writes/calls, a different predecessor or transport do not qualify.

Only the existing x86_64 Linux target uses the SSE2 intrinsic
llvm.x86.sse2.psad.bw. SSE2 belongs to that target's baseline instruction set.
AArch64 and RV64 retain ordinary scalar lowering.

Before any vector pointer or read, both the logical loop bound and the actual
owner extent must satisfy index <= bound and bound - index >= 16. The order
test is required because the subtraction alone can wrap. The vector load is
unaligned and has exactly sixteen bytes. Its two eight-byte sums are at most
2040 each. Adding both to the accumulator modulo 2^64 equals sixteen source
wrapping additions, including an arbitrary nonzero initial accumulator.
The range guard also ensures that advancing the index by sixteen cannot wrap.

The native lowering consumes a SIMD prefix in one loop and then a separate
fixed-stride scalar tail. Once either complete-range check fails, the ordinary
scalar emitter repeats the original seven operations, including the original
bounds abort, until the original logical limit is reached. Tail bytes never
reenter the SIMD checks. The invariant is accumulator = initial accumulator
plus bytes from the original start through the current index, modulo 2^64.
This preserves the invalid-tail behavior and does not load across the allocation
boundary. Each recognized body has no write or external call that could
observe the regrouped pure arithmetic. The whole Core verifier still checks
owner/loan rules. The compiler, LLVM lowering, linker and hardware remain
trusted; the structural match and arithmetic checks are not a machine-checked
end-to-end backend refinement theorem.

## Zero-length entry layout

The opt-in guarded-outline dispatch retains its actual zero branch and its
real body, including possible traps. A static 2:1 branch-layout hint favors
zero fall-through. It is not a measured profile probability. The unsigned
eligibility guard, complete fast/fallback components, argument transport and
inherited whole-function initialization decision remain unchanged.

## Validation

The dedicated tests exercise the exact match and refusal shapes, alpha
renaming, both non-x86 targets, immutable Core and independently regenerated
IR, modular arithmetic/range lemmas, both registered workload formulae,
allocation refusal, and actual checked-overflow/bounds SIGABRT paths.

A native allocator places every allocation's last byte immediately before a
PROT_NONE page. It deliberately returns unaligned addresses. The test checks
2304 successful cases spanning zero, 15/16/17/19/29/30/31/32/33-byte boundaries, later vector
boundaries, 255/256/257 and page boundaries through 8193 bytes, with independent
logical/start/initial-sum parameters. All owner allocations/frees are counted.
Six invalid-tail/huge-index/checked-overflow children must abort, not fault
on the guard page. These are finite regressions, not a memory-safety theorem
for every future native emitter.

## Frozen evaluation

The old benchmarks/hia_outlined_aot/PROTOCOL.json and its runner are unchanged.
Its exact file SHA256 is
66d45590cfcd6e7e0a09f31ea91e93d8b04af32eaf974ed2da563648e1ddb31b;
its canonical JSON SHA256 is
8706e62e4069669a0a8155c7d6b93e9701f23e4836ffa93c9bf14630ffa9ddfa.

The campaign retains all six arms, all 31 discrete registered lengths in four
groups, both workloads, three seeds per group, batch sizes 1/16/64, three warmup
calls and 21 samples per request. It retains 3348 requests, 70308 batch samples
and1,898,316 timed kernel calls. Median/p95/p99 limits remain 1.10/1.20/1.20
against both original Rust 1.95.0 release sources, for 372 comparisons.
No sample exclusion, selected-cell repetition or best-of selection is allowed.
Batch tails do not estimate individual-call tails.

The backend optimization can apply to matching wrapping loops in all HIA
arms, not only the outlined arm. The original checked sum and its checked
fallback cannot match. The two Rust fixture sources and compiler flags remain
unchanged. This experiment measures the chosen generic release baselines,
not every possible manually vectorized Rust program.

A separate predeclared resource/cost protocol in
benchmarks/hia_byte_sum_resource_cost.json applies stricter observed gates:
each candidate requested/usable total and peak, allocator-hook stack distance,
mapped/resident loader observation and file size must be no greater than each
Rust counterpart. There is no additional memory allowance. Actual
frontend/proof/build wall and median loader wall must be no greater than each
Rust arm. Every matched first-library-call latency must be within 1.20.
Every original warm-median cost horizon must be no greater than each Rust arm.
The read-only assessor tools/assess_hia_byte_sum_resources.py recomputes the
old assessment and cost ledger, checks complete inventories, and preserves
negative gates. It never reruns a native program.
Historical load rows omit the seed. The assessor uses the fixed registered
schedule only as a candidate association, then reconciles every actual load,
mapping, timed request/response and final child-close acknowledgement with
its retained timing JSONL log. A missing log, unknown order, changed sample
or incomplete cleanup invalidates the replay. The raw logs must remain next
to the input RESULT.json; no missing seed is silently guessed.

Allocator-hook stack distance is an observation, not a whole-function stack
bound. File bytes, loader backing pages, requested/usable heap and process RSS
are different quantities. RSS is retained but cannot be attributed to one
kernel's heap. Amortization is actual per-arm build/proof wall plus median
load wall plus horizon times measured warm median/calls. Actual cold calls and
whole campaign wall remain separate; nested clocks are not added twice.

Development checks, tool-copy/preparation and evidence postprocessing are
separately accounted. Human engineering time, energy and historical
acquisition costs remain unknown. Passing finite gates would not establish
universal Rust parity or full lifecycle superiority.

## Reproduction

Use a clean committed checkout, actual Clang 20 and Rust1.95.0, and the
registered single CPU. Set HIA_TEST_CLANG20 for the native test suite.

    python -m unittest tests.test_hia_byte_sum tests.test_hia_byte_sum_resources \
      tests.test_hia_entry_layout tests.test_hia_program_llvm -v
    python tools/qualify_hia_outlined_aot.py --output /absolute/new-campaign \
      --clang /absolute/clang-20 --rustc /absolute/rustc --cpu 0
    python tools/assess_hia_byte_sum_resources.py \
      --result /absolute/new-campaign/RESULT.json \
      --output /absolute/new-resource-assessment.json

Replace --cpu0 above with the actual CLI spelling --cpu 0.
The measurement host is shared and nonexclusive even with CPU affinity.
