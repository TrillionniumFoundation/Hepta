# P0–P7 follow-up: partial records, constexpr migration and incremental verification

This review records actual work on implementation
`d942f18b07c8811aa1418b6f67fabc23212317d1`, published in [draft PR #338](https://github.com/TrillionniumFoundation/Hepta/pull/338).
The current finite implementation passes the completed regressions and native
qualifications below. **The complete P0–P7 product acceptance is still open.**

## Source identity and review stack

| Identity | Value |
| --- | --- |
| Executed implementation | `d942f18b07c8811aa1418b6f67fabc23212317d1` |
| Git tree | `44823c1858d52e9043edebb83f2414d91087d743` |
| Preserved local implementation | `46cf53b0a29e4c234434ed5ab39a0046dc4e51dd`, identical tree |
| Official source snapshot | `4a64e1a353585d0ee88985e4942c008bd82ec1482be7ce1158a60f24f550e8db` |
| Source snapshot files | 1,065 |
| Changed implementation paths | 24, including 15 new paths |
| Parent | `06fc2d1c52d66a224ce96f520675525580fc5f00`, draft PR #334 |

All 24 remote Git blobs matched their local Git identities. The complete remote
tree matched the local tree; the actual remote commit was fetched and checked
out cleanly before final execution. Before/after source and selected tool
identities are retained in the original reports. The later evidence and
documentation publication is not substituted for the executed implementation.
After execution, one documentation paragraph is narrowed to describe accepted
canonical no-op patches correctly. Executable source, tests, examples and tools
remain byte-identical to the executed commit. The separate delivery snapshot is
recorded in [machine-readable status](current-status.json); it is not represented
as the original full-suite snapshot.

## Completed execution

| Check | Actual result | Evidence |
| --- | --- | --- |
| Full Python discovery | **2548 passed**, zero skips, failures or errors; 2548 unique canonical method IDs | [Completion and identity](integrated/execution-completion.json), [raw stderr](integrated/unit.stderr.log), [method IDs](integrated/canonical-unittest-ids.txt) |
| Full locked/offline Rust crate tests | **54 passed**, zero failed/ignored; 9 harness summaries | [Raw Cargo output](integrated/cargo.stdout.log), [completion](integrated/execution-completion.json) |
| Partial-record scenario differential | 94 scenarios: nominal Python, normalized Core Python and independent Rust agree; independently authored value/allocator/Owner expectations pass | [Qualification report](native/partial-records.json) |
| Partial-record budget boundaries | 11: ten budget stops and one normal-return control | [Qualification report](native/partial-records.json) |
| Partial-record production LLVM path | 188 positive native executions; separate missing-free and wrong-byte controls detected | [Qualification report](native/partial-records.json) |
| C++ concrete constexpr migration | 80 defined unsigned boundary cases, 160 original-C++/standalone-HIA native calls; independent arithmetic expectations agree | [Qualification report](native/cpp-constexpr.json) |
| Two live payload cleanup/cancellation | 32 fixed inputs, 64 Python runs, 32 Rust runs, 64 positive native executions, four wrong-order controls detected | [Qualification report](native/two-owner-cancel.json), [final seal](native/two-owner-final-seal.json) |

Python took 2187.813 seconds according to unittest's terminal
footer and 2191.86941 seconds for the outer command. Rust took
1.223091 seconds. The predeclared 3,600/240 second limits were
unchanged. Locked/offline Cargo metadata and build preflights also passed;
preflights are not counted as tests. The actual unit-process environment was
observed separately and matched the declared external Cargo home/target and
pinned Rust compiler.

The native counts are per finite experiment. They are not counts of independent
real-world applications and are not added to unittest's method count. The full
suite also executes some native tests internally; those executions are not
added again to these separately retained qualification totals.

## P1: exact partial-record states with actual resource obligations

`hepta.hia.composite.v3` adds `record.begin`, `record.insert`, `record.take`,
`record.finish` and `record.abandon`. Initialized fields form an exact typestate
in declaration order. Missing fields have no primitive slot or invented value.
Incomplete or mismatched states cannot pass a CFG edge or function signature
that requires a different state.

The new profile normalizes to the existing primitive v7. Its private zero-length
buffer token makes even an empty or scalar-only partial state linear. The token
is an actual Owner in the Python and Rust ledgers, requires the existing alloc
effect and must be consumed. It makes no physical allocation attempt and no
`free(NULL)` call. Taking an owning field emits real primitive ownership moves,
so a conflicting loan prevents the move even when the owner is nested.

Unused declarations now receive the same concrete partial-reference checks as
used declarations. Six independently authored inputs that were initially
accepted now reject: primitive/enum/partial bases, unknown or out-of-order
initialized fields, and stored-loan bases. An unconstrained `partial(T)` rejects.
Symbolic `partial(Box<T>)` retains its actual type arguments; known constraints
are checked immediately and unknown argument constraints are rechecked on real
instantiation. No arbitrary placeholder type is used as proof. Memoized symbolic
analysis has 32,768 total steps, including key construction, and a 64-level key
expansion limit.

The 94-case qualification covers field construction and replacement, generic
records, calls and blocks, byte contents, zero-sized payloads, allocator
refusals, cooperative task states and exact partial-execution budget ledgers.
The nominal and normalized routes produced byte-identical LLVM and a
byte-identical 2,056-byte object for this corpus. Object equality is a measured
property of this corpus, not a theorem about every program or a speed benchmark.

The missing-free control still returns 177 but retains three allocations and
21 live bytes; the observer returns 91. The wrong-byte control returns 178 with
clean resources. Both are detected independently of mere scalar equality or
mere leak freedom.

The original 94-case tool explicitly does not claim cancellation ordering of
two live payloads. A separate, predeclared 32-input qualification now covers
that finite gap: explicit error return cleanup, pending cancellation, cancellation
after start, and cancellation after one poll yields pending. The 24 positive
native executions with two successfully allocated payloads observe `[2,1]`;
the remaining fixed cases match their independently specified zero- or
one-allocation order. Four valid-but-non-equivalent Core controls observe `[1,2]`
while preserving returns, allocation/free counts, peak bytes and final zero
leaks. All four controls are detected.

The extra qualification uses public, reverified LLVM emission followed by
captured direct Clang compilation, object inspection and linking. It does not
claim to have used the production compile/publication API; the 94-case study
separately covers that route. Python and Rust compare values, steps and complete
resource ledgers. Their public reports do not expose release-order event streams;
release order is measured by the native allocator observer.

These are explicit cooperative cleanup paths. They do not certify exception
unwinding, asynchronous preemption, cleanup after abort/budget exhaustion,
escaping stored loans, arbitrary address-based initialization or real concurrency.

## P4: captured constexpr selection without losing definition identity

The frontend now accepts the finite supported C++20 `if constexpr` shape from
the actual captured Clang AST. It requires a concrete Boolean ConstantExpr,
selects only the correct branch and records discarded branches. Type and integer
template parameters, nested selections, no-else forms, branch-local scalars and
return control flow have actual examples.

Whole template patterns remain part of cross-file definition admission. Two
concrete instances with equal selected bodies cannot hide different discarded
patterns. Conflicting ODR inputs are rejected, not executed as supposedly
defined C++ oracles. Local-class member references use stable declaration
bindings instead of temporary Clang addresses; the normalization preserves
which member is referenced.

The retained native study captures two translation units, seven distinct
concrete template instances and thirteen constexpr selections. Its HIA library
links only the generated HIA object, with no original C++ implementation linked
into the target. Eight scalar exports each have ten fixed boundary inputs.

Unknown conditions, constexpr init/condition-variable forms, `if consteval`,
selected unsupported object lifetimes and unmodeled operations remain refused.
A discarded object or throw was not executed and provides no lifecycle or
exception qualification. This does not certify arbitrary templates, STL,
complete C++ object layout or a general source-equivalence theorem.

## P6: bounded local incremental verification

`IncrementalVerifier` starts with actual full verification. It retains only a
local, immutable snapshot; caller receipts, supplied hashes, forged verified
objects, serialization, subclassing and copying cannot seed trusted admission.

Every candidate is strictly decoded and all global declarations, function and
block shapes, operations, SSA definitions and CFG edges are checked. An unchanged
body is reused only when its bytes and every direct callee's immutable parameter,
return and effect interface are unchanged under the same verifier policy.
Changed callees, removed definitions and changed verifier/registry policy
invalidate the appropriate reuse or force a full fallback. Nominal inputs also
fall back to full verification. New primitive versions do not opt in implicitly.

Failed verification or a forbidden/stale patch leaves the preceding accepted
baseline intact. Session locking and digest checks serialize patch attempts.
For the tested pair of valid conflicting patches that change the same baseline,
one commits and the other is rejected as stale. Public execution, native compilation, the existing
editor and publication continue their full checks. The incremental receipt uses
its own schema and reports actual work instead of claiming every body was rerun.

Development evidence includes 957 fixed candidate comparisons: 56 accepted,
901 rejected, with no canonical-byte, rejection-code or diagnostic-message
differences between the previous full-checker file, the refactored full checker
and incremental verification. The previous file was loaded with the current
registry; this is not execution of an entire old compiler environment. Those
development records retain their actual source identities. An instrumented
36-function edit checks one changed body while reusing 35; all 36 function shapes
and 70 operation shapes are still checked.

This establishes bounded static admission and measured checker work counts.
It does not prove behavior preservation, safe test skipping, lower wall time,
lower model token cost or positive model productivity. Historical real-model
benefit failures remain open.

## Preserved failures and independent review

[Development archive](archives/development.tar.gz) and its
[member inventory](archives/development.manifest.json) preserve the initial
unused-partial admission errors, cross-file template conflict, temporary-member
address false rejection, development tests and the old checker comparison.
Fixture mistakes are kept separately from compiler defects. Where the original
first stderr file was not available, a record explicitly says it is a transcribed
tool-output summary; it is not labeled a raw stream or another execution.

The independent native evidence review reconstructs 105 Rust requests and 188
positive native observations from retained argv/stdin/stdout and separate
scenario formulas. It checks two negative controls and every retained stream
identity. That is 295 independently reconstructed execution mappings; five
additional compile/link records have their original stream identities checked.
The review also checks the C++ native observations. Its first checker attempt
mistakenly compared complete interpreter report objects with scalar values;
that failure and script are preserved, and a separate corrected attempt passes.
No applications were rerun by this review.

The extra two-owner collector created an intermediate manifest before its final
stdout summary. Its `execution.stdout` entry consequently grew from zero bytes.
The original manifest is preserved; the separate final seal identifies that
single discrepancy and binds all 276 completed files. Use the final seal for
this qualification's finished file set.

The public archives preserve exact text/source/JSON/process-stream bytes and
provide round-trip-verified member inventories. Original absolute paths in
receipts are not rewritten. Native binaries and tool binaries are identified
by size/hash and explicitly omitted from this text projection. Each omission is
listed; an archive is not represented as containing a binary it does not contain.

## Remaining P0–P7 acceptance

| Stage | Current finite result | Remaining requirement |
| --- | --- | --- |
| P0 | Shared version registry, explicit old-version rejection, unchanged old canonical regressions; new meaning has a new composite v3 namespace | Continue exact agreement for every future frontend/backend and retain correctness regressions; no whole-language refinement inferred |
| P1 | Partial nominal records and selected cleanup/cancellation paths now implemented and executed | General typed addresses/layouts, escaping stored loans, arbitrary heap ADTs, concurrent scheduling/atomics/channels |
| P2 | The new Core has Python/Rust/native finite agreement and active behavioral/resource controls | End-to-end source/normalization/Core/LLVM refinement, justified optimization assumptions for every construct and all-target soundness |
| P3 | Existing closed C migration, declaration inventory and explicit pointer contracts remain | General build/configuration and pointer provenance coverage, automatically established contracts, representative full-project migration cost |
| P4 | Concrete constexpr templates join the existing selected C++ profiles | General object model, templates/STL, exception boundaries; ABI, lifetime, safety and equivalence beyond these examples |
| P5 | Historical measurements and regressions retained | Stable same-semantics representative CPU evidence, layout/vector/device implementation and actual GPU execution |
| P6 | Local incremental static checking and existing semantic editing | Complete diagnostics, independent maintenance tasks, equal-budget real-model success/cost benefit |
| P7 | Existing Linux/native and selected emulator profiles retained | Physical MMIO/IRQ/DMA/coherence, real workloads, endurance, resource boundaries and fault recovery |

Historical CPU qualification remains measurement-inconclusive: all nine
relative-MAD groups exceed the frozen five-percent threshold. Historical real
model trials did not pass their benefit criteria. No new real model, GPU or
physical-board execution is claimed here. The full 19-gate release qualification
was not rerun; remote CI completion and a merge are not claimed.

## Run the new entry points

```sh
python -m hepta hia verify examples/hia_program/partial_record.hia
python -m hepta hia run examples/hia_program/partial_record.hia \
  --function replace --arguments '[7]'

python tools/qualify_hia_partial_records.py \
  --output-directory /tmp/new-partial-qualification \
  --clang /path/to/clang --rust-vm /path/to/hia-core-shadow

python tools/qualify_cpp_constexpr.py \
  --output-directory /tmp/new-constexpr-qualification \
  --clang /path/to/clang --clangxx /path/to/clang++
```

Each output path must be new. Use the documented supported compiler/host and
the actual independent Rust executor. A receipt is evidence of the operation
that produced it; reading or hashing a receipt does not perform native execution.

See [machine-readable status](current-status.json),
[partial-record semantics](../../../docs/HIA_PARTIAL_RECORDS_V3.md),
[constexpr migration](../../../docs/CPP_CONSTEXPR_MIGRATION.md) and
[incremental verification](../../../docs/HIA_INCREMENTAL_VERIFICATION.md).
