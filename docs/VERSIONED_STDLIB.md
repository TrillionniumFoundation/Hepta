# Versioned local source-library consumer qualification

This bounded P12 integration stacks on [#699](https://github.com/TrillionniumFoundation/Hepta/pull/699)
at `fccbc1a9cf5f6639d29bb8e96aa10381be5141a6` and selectively incorporates the
local resolver and lock-review composition from [#698](https://github.com/TrillionniumFoundation/Hepta/pull/698)
at `999850195334cc8439cfbb95de09e6e49faeee2c`.

It supplies a reproducible source checkout in which the four real libraries,
the packet application, bounded candidate selection and offline lock review
operate together. It does not implement another resolver, byte codec, sorter,
UTF-8 validator or Base64 codec. Neither parent previously shipped this full
source/application qualification. No further compiler behavior is added.

## Preserved sources

All four package production files are exact #698 bytes. Every source-library
implementation and every inherited test, oracle, example and workflow is
unchanged. `tests/versioned_stdlib_components.json` binds **68 supplied files**
to their exact Git blobs, SHA-256 identities and parent commits. The shared
blocker ledger retains both contracts, with P12 still PARTIAL.

The sole adapted inherited qualification input is
`tools/stdlib_integration_components.json`. Its `hepta/cli.py` and
`hepta/packages.py` expectations now identify the exact #698 supplier; the other
15 original compiler/toolchain identities are unchanged. The byte-identical
original manifest is retained in `tests/versioned_stdlib_parent_manifest.json`.
The joint gate checks both manifests and proves that replacing exactly these
two entries recovers the original manifest bytes. No test assertion is disabled,
no origin test is removed, and no provenance mismatch is treated as success.

## User-facing example

From this checkout:

```sh
python -m hepta run examples/packages/versioned_text --locked --backend c --json
```

The new example uses explicit package names, `>=0.1.0, <0.2.0` requirements and
local candidate lists for all four existing libraries. Its packet and entry
sources are byte-identical to the original `indexed_text` example, and its
content lock is reproducible. The only actual candidates shipped are the
existing 0.1.0 packages; no fictitious release is published.

For migration review, save the current `Hepta.lock`, intentionally edit the
local candidate declarations, then run `hepta lock` and
`hepta lock-diff BEFORE_LOCK AFTER_LOCK --check`. An existing stale lock must
not be silently refreshed by `--locked`. `lock-diff` always reports
`compatibility: not_assessed`.

## Joint qualification

Eleven new methods construct disposable version-1/version-2 fixtures using the
four real library sources and the original packet consumer:

- A candidate packet library has transitive candidate dependencies on all four
  libraries. Explicit upgrade selects a complete new graph; root/transitive
  constraints force backtracking to the older complete graph.
- Unsatisfiable refresh preserves the previous lock, refuses the locked
  consumer, and permits explicit recovery to the original selection.
- Each selected source edit invalidates the content lock. Unselected source
  edits do not. Equivalent ranges/candidate ordering and equal-version path
  replacement are distinguished in complete lock review.
- Layout-preserving relocation and the checked-in versioned example execute
  through the actual public CLI with reproducible locks.
- An intentionally broken ordering candidate has a valid refreshed lock and a
  successful compilation but fails the native packet assertions. Explicit
  rollback restores success. Valid version constraints and locks therefore do
  not imply behavioral compatibility.

Successful native consumers run at O0/O3 with C UBSan and no recovery, or with
actual pinned Rust when the Rust lane is selected. Packet fields, original
inputs, scratch and scalar arrays are asserted against Python Base64, UTF-8,
integer conversion, sorted and bisect expectations. Build receipts retain
actual compiler identity, flags, generated-source/artifact hashes and outcomes.

The **285 unique-method inventory** is exactly 65 inherited package methods,
60 inherited source-library methods, 149 unchanged parser/checker controls and
11 new joint methods. Planned, started, finished and passed identities must
match in order. Missing/duplicate discovery, skips, expected failures and
source changes are failures. The existing three package oracles run on the
same source. C lanes also run all five inherited native library oracles.

A separately authored joint oracle constructs complete expected snapshots and
deltas independently of production resolver/range/diff helpers. Each execution
covers 16 mixed candidate states, 46 complete comparisons, 15 stale-lock
refusals and two unsatisfiable operations preserving lock bytes. Four native
low/high-version × O0/O3 executions cover 8,192 packet calls, all six result
stages, complete input/output backing arrays and physical canaries. Four
separately compiled wrong-output controls must fail the independent oracle.
Compiler, target, flags, source and artifact identities are retained. These
ctypes bindings are compiler-private C qualification, not public aggregate ABI.

```sh
PYTHONDONTWRITEBYTECODE=1 python -B tools/qualify_versioned_stdlib.py
# Actual pinned Rust executable required, never a skipped substitute:
HEPTA_VERSIONED_STDLIB_BACKEND=rust RUSTC=/path/to/pinned/rustc \
  python -B tools/qualify_versioned_stdlib.py
```

The exact-head read-only workflow requires Linux x86-64/AArch64 × Python
3.11/3.13 × C/Rust, selects the real pinned Rust compiler path, and retains
complete logs even when a qualification step fails. Earlier parent CI does not
qualify this new source. Native Rust, ARM and Python 3.11 were not run locally.
The source-exact local evidence is reported in the PR after the final gate.

The initial new-test run correctly observed the broken C candidate abort, but
its test incorrectly required Rust-style assertion text on stderr. That failed
attempt is retained. The corrected test requires the actual C SIGABRT with
empty stderr, and separately requires Rust SIGABRT and assertion text, matching the
unchanged compiler’s explicit `panic=abort` flag. Source review caught the
initial unexecuted Rust exit-101 expectation before publication; the incomplete
full-gate attempts were stopped and retained before final-source reruns. These
are fixture expectation corrections, not production changes.

## Limits

Synthetic candidate versions are test fixtures, not new package releases.
Finite candidate/application checks are not a general solver proof, compiler
refinement theorem, API/ABI compatibility checker, automatic migration, online
registry, package distribution, signing, production library qualification or
performance comparison. No whole-project/release/formal gate was run. P12 and
all unrelated blockers remain open/partial. Draft only; no merge or activation.
