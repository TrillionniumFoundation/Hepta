# HIA P0–P7 integration: source-bound execution evidence

This directory preserves completed attempts, including failures. The candidate
integrates HIA v7 and the distinct native migration/hosted work from PRs #319,
#318 and #115. A passed finite gate does not close the entire P0–P7 roadmap.

## Attempt 2: published source `b917f5f`

Full Git commit: `b917f5fcdaa13a6a7b237010b46b0f411b7e9ecf`. Execution ran from
`2026-10-27T14:23:32Z` to `2026-10-27T14:42:17Z`. The exact source inventory remained
`52b03bb9b3e945e947e74ebf8749026e229fae4f8d738528b9bd9e4b11e607cc` before and after all gates.

**All 35 gates completed; 34 passed. Overall qualification remains false.**
The sole failed gate is `standalone_performance`, with the completed status
`measurement_inconclusive`. The repaired direct `llvm_local_stored_views`
producer now passes its actual native gate. No acceptance threshold changed.

| Check on b917 | Actual observation |
| --- | --- |
| Full Python regression | 2,498 tests; zero failures, errors or skips |
| Rust crate | 52 tests; zero failed, ignored or filtered |
| Python/Rust parity | 45 tests; 124 byte-owner full-ledger differential observations |
| Agent query/edit mechanisms | 53 tests; zero skips |
| All other non-standalone-performance gates | Passed within their declared profiles |
| GCC / Clang native host ABI | Each compiler: 181 actual calls at O0 and 181 at O2, with negative controls |
| Standalone performance | 63 samples, none excluded; four quality failures |

The fixed maximum relative MAD is 5%. The failed series are:

| Series | Actual relative MAD |
| --- | --- |
| `constructor_error` / `handwritten_rust` | 9.533520% |
| `full_lifecycle` / `llvm` | 6.363798% |
| `two_stage` / `handwritten_rust` | 8.449895% |
| `two_stage` / `rust` | 8.545447% |

Neither paired-time-ratio threshold failed. The descriptive aggregate
LLVM/handwritten-Rust ratio is 0.9260795783100729, and LLVM/same-source-Rust is
0.9324829865173611. The failed measurement-quality gate prevents performance
qualification; these observations do not establish broad Rust superiority.
The separately passed application protocol retains **49 slower metric
comparisons** across three trials of 96 requests with 16 warmups. It measures
instrumented sequential ABI work, not a network-service SLO.

Read [`run2/qualification.json`](run2/qualification.json),
[`run2/performance.json`](run2/performance.json),
[`run2/applications.json`](run2/applications.json) and the compact
[`delivery-summary.json`](delivery-summary.json). Raw reports are unmodified.

The second archive is 18,172,756 bytes, SHA-256
`e587209bffca1b5e697585747b495605ab8bd096e864efc5cfcc8ea0b92314e0`.
All five parts and 2,276 tar members were independently verified, including
four byte-identical internal/external metadata files. There are 28 referenced
temporary/artifact files no longer available; no missing binary was recreated.
See [`run2/archive-validation.json`](run2/archive-validation.json) and
[`run2/REASSEMBLE.txt`](run2/REASSEMBLE.txt). The retained
[`verify_hepta_archive.py`](verify_hepta_archive.py) checks package integrity
without executing any archived code or upgrading the qualification result.

## Strict P0–P7 closure status

All eight broad stages remain **open**. [`stage-status.json`](stage-status.json)
links source-specific current validation, separately preserved historical
observations, implementation references and the remaining obligations.

| Stage | Actual progress and remaining boundary |
| --- | --- |
| P0 | v7/#115/later branches converge in the candidate; standalone Python Core is authority. Historical IR paths are not all unified under it. |
| P1 | Finite owners, loans, provenance, reborrows, recursive buffer chains and cooperative cancellation execute. General escaping/returned borrows, arbitrary recursive heap ADTs and general partial initialization remain open. |
| P2 | Direct LLVM and finite Rust checker/scalar/byte-owner shadows are exercised. Rust has not qualified a general resource VM or taken production admission authority. |
| P3 | Actual Linux GCC/Clang ABI gates pass. Windows/MSVC, macOS and other physical hosts need completed native evidence; external lifetime obligations remain. |
| P4 | Declared C/C++ scalar/template/owner/composed implementation migrations and explicit configuration inventories execute. Arbitrary C++ libraries and full end-to-end migration cost remain unqualified; retained foreign bridges are distinct. |
| P5 | Bounded query/context and atomic batch verification are tested. Historical real-model trials exist but failed both models' criteria; no b917 productivity qualification or independent total-cost result exists. |
| P6 | Emulated devices and finite workload/resource observations pass their scoped gates. Both standalone performance attempts remain inconclusive; physical protocols and production service SLOs remain open. |
| P7 | Selected actual-Core arithmetic export and separate abstract Lean models are checked. Exporter/verifier/backend refinement, whole-language soundness and broad release qualification remain open. |

The read-only [`stage-audits/`](stage-audits/) preserve their original b917
source references and pre-run2 timing; the final status file supplies the
completed run2 outcome. The exact-source CI observation is retained in
[`ci-observation.json`](ci-observation.json): both workflows were still queued,
so workflow declarations are not treated as completed host results.

The delivery also corrects the stale 19-gate/Rust-scope wording in
`docs/HIA_SEVEN_STAGE.md`. [`publication-provenance.json`](publication-provenance.json)
separates the tested b917 source from this documentation/evidence-only commit.
Compiler, runtime, analyzers, tests, tools, profiles, locks and CI definitions
are unchanged after the completed run. No full-suite execution on the later
artifact commit is claimed.

## Attempt 1: published source `a4ba75b`

Full Git commit: `a4ba75b92fd22d41ef39d29307fb92cea4bad131`.
Source inventory SHA-256:
`896553e31174d11dbe570dfb6f8674da9878261066215404f451c0e026073c3f`.

The unchanged source completed **35 gates; 33 passed**. See
[`run1/qualification.json`](run1/qualification.json) for every command, process
result, bounded log digest, report digest and the before/after source inventory.

| Completed check | Actual result |
| --- | --- |
| Full Python regression | 2,495 tests, zero failures/errors/skips |
| Rust crate | 52 tests, zero failed/ignored/filtered |
| Python/Rust parity | 45 tests, zero skips; includes the byte-owner VM |
| Agent query/edit mechanism | 53 tests, zero skips |
| Remaining native/resource/migration/ABI/formal/application gates | 29 passed; see the exact plan/report inventory |
| `llvm_local_stored_views` | Failed at direct script import: `ModuleNotFoundError: hepta` |
| `standalone_performance` | All 63 samples retained; `measurement_inconclusive` |

The performance attempt did not exceed its paired-time-ratio thresholds.
It failed the fixed 5% relative-MAD quality limit for `constructor_error/llvm`
(0.08300516377483902) and `two_stage/llvm` (0.07620544908304734).
The observed aggregate paired ratios are descriptive; this attempt grants no
host-performance qualification. No sample was excluded and no threshold changed.
Full data: [`run1/performance.json`](run1/performance.json).

## Entry-point correction

The producer now establishes the repository root before importing `hepta` or
`tools`. New subprocess tests derive the real producer list from the unified
plan and start 28 distinct direct scripts with an external working directory
and an empty `PYTHONPATH`; two module entries are also checked. They reproduce
the original import failure and exercise the corrected startup/argparse paths.

The supporting 48-test development run and its dirty-tree/file-hash provenance
are retained under [`entry-repair/`](entry-repair/). The repaired producer was
also executed against the actual LLVM/Rust/C tools on committed local source
`1fdb50b1737c338854e248ed5cf13daf926bab0d` and passed. Its exact local commit is
recoverable from `entry-repair/repaired-source.bundle`, with the published a4
commit as prerequisite. These checks do not replace the next integrated run.

## Raw archives and verification

`run1/` contains five ordered 4 MiB parts (the final part is shorter) encoding
an 18,150,640-byte archive with SHA-256
`5990bf30abe33dbb5f6bf2c0ecf2c9cc8fb9a1ed8fdf2c391e92461c9075abf4`.
Use [`run1/REASSEMBLE.txt`](run1/REASSEMBLE.txt), then verify the whole-archive
digest and the per-file inventory. All 2,275 archive members and five ordered
parts were independently checked. The raw input inventory contains 2,271 files.

The archive includes the completed run's reports, process streams and retained
native artifacts, the actual Rust shadow executable, the wrapper log, and
separately scoped restoration evidence/toolchain receipts. The restoration
source bundle preserves otherwise local Git identities without duplicating
the complete repository history. Original report bytes and paths are unchanged.

Some producers delete temporary binaries and explicitly state
`native_binaries_retained=false`. The package records those limits and missing
references; it does not fabricate missing files or claim every executed binary
survives. Toolchains remain external reproducible dependencies. Cargo build
cache is excluded. See `dependencies.json`, `path-mapping.json`, the inventory,
packaging receipt and the retained packaging script for the exact boundary.

## Qualification limits

Rust remains opt-in and finite; Python Core retains production admission.
General recursive ADTs, full escaping/returned resource loans, arbitrary C/C++
translation, real-model productivity gains, whole-compiler soundness,
physical-device protocols and broad Rust-performance superiority remain open.
QEMU execution is recorded as emulation. Application timing measures the
declared sequential ABI workload, not a production network-service SLO.
Windows/MSVC and other physical host claims require actual completed host CI.
