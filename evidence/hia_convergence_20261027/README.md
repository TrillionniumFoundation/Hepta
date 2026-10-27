# HIA P0–P7 integration: source-bound execution evidence

This directory preserves completed attempts, including failures. The candidate
integrates HIA v7 and the distinct native migration/hosted work from PRs #319,
#318 and #115. A passed finite gate does not close the entire P0–P7 roadmap.

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
