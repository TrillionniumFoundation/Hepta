# Guarded byte-sum AOT: complete second-round evidence

The final branch candidate is `d482f36cfa5f77558bd664749a37973a28083a6c`, tree
`69ac2654a653146c40a408636008305e8b660773`. The exact three-commit history is
included as a Git bundle with prerequisite
`3707b871ecbe563233ee9a3b69299fc627408936`.

## What changed

An exact verified pure forward byte-sum loop may lower to guarded x86_64 SSE2
16-byte sums. Both the logical loop limit and actual owner extent must admit
the complete read. Other declared targets retain scalar lowering. The final
candidate separates the SIMD prefix from a fixed-stride scalar tail; every
original scalar operation, including the first invalid-load abort, remains.
The accumulator is explicitly wrapping u64. Checked or nonmatching loops are
refused. An entry-layout hint preserves the actual empty body and its traps.
This is a trusted-backend optimization, not a machine-code refinement theorem.

The actual final native checks passed 36 tests in 32.646 seconds, including
2,304 unaligned guarded-page cases, six abort children, target fallback,
ownership, allocation, rejection, and existing native regressions. A separate
15-test resource/protocol suite passed. Read-only peer reviews are scoped in
the retained delivery input. Earlier development failures remain in the archive.

## Fixed observations, including failures

| Source/cohort | Runtime gates | Median misses | Tail-only misses |
| --- | ---: | ---: | ---: |
| Original 3707 composition r3 (context; archived in the previous round) | 293/372 | 7 | 72 |
| First new lowering db98, campaign r1 | 318/372 | 11 | 43 |
| Split-tail d482, campaign r2 | 348/372 | 0 | 24 |

The final 24 misses comprise two p95 failures and 22 p99 failures. These are
batch tails. The complete fixed cohort includes four length/seed groups,
two workloads, 31 distinct lengths from 0 to 340157, batch loads 1/16/64,
three warmups and 21 timed samples per request: 3348 requests, 70308 timed
batches, and 1898316 timed kernel calls. Nothing was excluded or retried.

Both conventional and explicit-byte Rust references use Rust 1.95.0,
`-C opt-level=3 -C lto=fat -C codegen-units=1`, the other registered flags,
and the unchanged generic target. No target-native or PGO exception was added.
The original six-arm protocol and evaluator bytes are unchanged.

All 5680 final registered memory comparisons passed. Build/proof cost passed
4/4, median load cost 4/4, and the registered estimated automated-cost horizons
1116/1116. Cold first-call cost passed 38/48; all ten failures occur at n=0.
The first candidate passed only 32/48 cold-call gates. Therefore
**all-runtime=false, all-cost=false, broad Rust parity=false, and full-lifecycle
net benefit=false remain explicit**. Allocator-hook stack distance is not a
whole-function stack bound. Loader mapped/resident segment pages are not
private RSS. Human engineering, historical acquisition and energy are unknown.

Each candidate ran one complete fixed cohort on CPU 0. Source, driver and
selected runtime inventories were unchanged; direct children were reaped.
The host was shared and nonexclusive. Team heavy jobs were coordinated, but
external jobs were not stopped. Independent campaign differences do not
establish causal isolation or statistical confidence. Every old failed gate
and every new failed gate is retained.

## Costs and the original assessor failure

Campaign r1 native lifecycle was 85.418424303 seconds and its outer driver
115.197005314 seconds. That outer driver exited 1 because the first resource
assessor incorrectly expected a seed field in historical loader summaries.
The native campaign itself completed with all raw measurements intact.

Commit ee2 fixes only read-only attribution: it validates every original raw
loader and timing stream, its registered order, seeds, responses and cleanup.
Its successful reanalysis used the unchanged r1 RESULT and took 1.469036222
seconds in its separate outer wrapper. The original failed assessor and
failed outer receipt are preserved; r1 was not rerun or relabelled.

Campaign r2 native lifecycle was 82.870557955 seconds and its complete outer
driver 115.217911745 seconds. The two actual campaign outer walls sum to
230.414917059 seconds. Native, inventory, and assessor timers are nested
components, not additional charges. COSTS.json retains development clocks
and unknowns separately; delivery compression/restoration/upload costs are
separate from the experiment.

## Restore all retained bytes

Keep every public file in this directory together and run:

```sh
python3 RESTORE.py --output /absolute/new/aot-evidence --receipt /absolute/new/aot-restore.json
```

The restore program verifies every split, the concatenated XZ SHA256, the
complete regular-file member inventory and each file's exact byte count and
SHA256. It rejects duplicate, unknown, missing, escaping and nonregular
members, and refuses an existing output directory. It does not execute
native artifacts, compilers or models. The archive preserves both full
campaigns, raw request/response streams, native artifacts and build/proof
receipts, development failures, driver/launch plans, freezes, reviewed source
files and the exact Git history bundle. The original raw XZ is retained at
the experiment host; public split files reconstruct it exactly.

With the prerequisite commit available in a disposable checkout, inspect
the bundle before importing its branch:

```sh
git bundle verify source-history.bundle
git fetch ./source-history.bundle work/hia-round2-aot-20261104:refs/heads/aot-evidence-candidate
```

RESTORE_VERIFICATION.json records one actual strict restoration. Publication
of these evidence blobs does not change any repository ref or qualify the
remaining failed performance/cost gates.
