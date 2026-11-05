# Typed packet consumers over existing source libraries

This is a bounded P01/P11/P12 application composition, not another compiler,
codec, resolver or library implementation. Base PR #708 exact
`b45d6621b0435dd8da4aabf87250b275dbe03927` supplies the Copy-ADT, Unit, numeric,
temporary-array and ordinary-store compiler. All 168 materialized parent inputs
remain byte for byte unchanged, including production, tests, gates and docs.

The four source libraries and their 48 original individual test methods come
unchanged from PR #709 exact `653b508336a470151b94f5e1c0448654c4782030`. Their
underlying byte/ordering/UTF-8/Base64 implementations are those already composed
in #699. All 35 selected library/test/oracle/document/example inputs retain
original Git blob identities. The original indexed_text packet implementation
is copied unchanged into a separate application package. This does not import
#709's package resolver or claim its whole versioned-consumer qualification.

`tools/verify_typed_stdlib_sources.py` checks these exact sources and counts.
No compiler, inherited test, manifest or provenance adapter is modified.

## Application contract

`examples/packages/typed_packet` is an application adapter, not a newly released
standard-library API. It uses the unchanged packet implementation to decode
canonical Base64 containing a big-endian u16 byte count followed by UTF-8,
then sort Unicode scalar values and locate a query range.

The public Hepta result is `Result<Committed<Bounds>, PacketError>`:

- Success contains scalar count and lower/upper indices in a concrete generic
  Copy record, plus an internal Unit marker.
- Errors distinguish `Decode(Unit)`, `ShortHeader(Unit)`,
  `LengthMismatch(Unit)`, `InvalidText(Unit)` and `ScalarCapacity(usize)`.
  The capacity payload is the supplied scalar slice length, including its
  reserved prefix slot. Decode includes invalid range, noncanonical encoding
  and insufficient scratch capacity; it does not identify a finer reason.

The Unit marker is just an ordinary value, not a linear capability, authority,
transaction receipt, durability claim or proof of compiler correctness.
Scratch prefix byte zero and scalar prefix element zero belong to the caller.
Decode failure leaves scratch unchanged. Later failures retain decoded scratch
bytes. Every failure leaves scalar storage unchanged. Empty valid text succeeds
with count zero and both bounds equal to one. All results and payloads are
internal Hepta values, not a public aggregate C ABI.

The `typed_text` consumer loads seven modules from six local packages using
ordinary fixed-path dependencies and a checked-in content lock. No registry,
version-resolution or compatibility claim is added. Both examples remain 0.1.0
source fixtures, not published releases.

## Qualification

```
python -B tools/qualify_typed_stdlib.py
python -B tools/typed_stdlib_oracle.py
python -B tools/validate_c_store_adt_composition.py
python -B -m hepta run examples/packages/typed_text --locked --backend c --json
```

The new strict C-only inventory contains **407 unique methods**: all 349 parent
methods in the same order, all 48 unchanged individual library methods, and ten
new joint methods. The new tests exercise every typed error and exact mutation
boundary, empty/repeated scalars, generic Result copy snapshots across later
calls and raw stores, temporary arrays, source lock invalidation/recovery,
relocation, exhaustive-match refusal and the real public CLI example. Native
successful joint controls execute O0/O3 with nonrecovering UBSan.

The gate requires exact planned, started, finished and passed IDs, no skips,
failures, expected failures or unexpected successes, and stable full materialized
source hashes across both tests and all nine oracle scripts. The four original
compiler oracles and four original library oracles run unchanged on this source.
Their counts are not added to imply independent whole-language coverage.

A separately authored Python oracle has **178 vectors**, including 64 seeded
Unicode success cases, all five error stages, UTF-8 boundaries, canonical Base64,
capacity/range edges and layered failure precedence. It checks every physical
input, scratch and scalar element, prefix/suffix sentinels, Unit extraction and
all typed result fields. Twelve batches execute at both O0/O3 under nonrecovering
UBSan, plus four deliberately wrong-output controls at both levels, for **32
native executions**. Controls alter success bounds, Decode tag, capacity payload
or a prefix sentinel and must abort. This is an independent expected-value model
with a shared compiler frontend, not an independent language interpreter.

The initial local test expected a thrown exception for nonexhaustive match.
The unchanged pipeline instead returned a structured E_MATCH_EXHAUSTIVE refusal.
That failed attempt is retained separately; the corrected test checks the actual
rejection report and absent generated C. No production logic was changed.

Required-Rust mode contains **415 methods**; eight inherited Rust-only methods
are unexecuted in local C-only mode. Inherited inapplicable resource/volatile
controls remain explicitly excluded, not counted as passing. The read-only
exact-head workflow requires pinned Rust 1.90.0 on Linux x86-64/AArch64 and Python
3.11/3.13, with separate C/Rust library-consumer lanes. Native Rust, ARM and Python
3.11 have not been executed locally. Old parent hosted results and queued jobs
do not qualify the new source.

## Limits

No compiler production change, generic functions, resource ADTs, recursive
execution, source-literal admission, signature audit, C-import publication,
output-path change, stable aggregate ABI or memory-safety claim. Unsafe raw
storage in the joint control is valid, aligned, live and in bounds; those remain
caller obligations. No performance advantage, full language refinement,
production standard-library qualification or complete blocker closure is
established. P01/P11/P12 remain PARTIAL. Draft only, no merge or deployment.
