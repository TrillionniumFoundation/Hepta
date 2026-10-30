# Rust finite-entry heap development evidence

This bundle retains the actual development and regression attempts for source
commit `958790711467018ffb0da56c4834e6bfb5f29f3e`, based on
`73922c1a3971125dfb9703555e50e5cf6444e842`. It qualifies neither a later integration
commit nor the whole Hepta language. The tests reuse existing resource/partial
initialization fixtures; `new_holdout=false`.

The source change adds independent bounded Rust abstract heap analysis to the
existing private raw-byte-DAG admission snapshot and existing v4 Machine. Old
`raw-byte-dag-v1` semantics and default/source/native admission are unchanged.
The contract is `docs/HIA_RUST_FINITE_ENTRY_HEAP.md` in the source commit.

## Actual recorded outcomes

| Attempt | Actual outcome | Recorded subprocess wall |
| --- | --- | ---: |
| `001-initial-build` | Rust analysis compiled | 4.134045479 s |
| `002-route-build` | Same-snapshot heap admission and CLI compiled | 1.773216008 s |
| `003-first-differential` | 6 methods; 31 failing subcases in the new test adapter | 43.335183350 s |
| `004-expanded-differential` | 15 methods; 192 test-adapter errors and 1 refusal-code expectation failure | 45.296590369 s |
| `005-contract-fix-check` | Both targeted test methods passed | 0.715952728 s |
| `006-rust-suite` | 116 Rust tests passed, 0 failed/ignored | 4.759268934 s |
| `007-focused-regression` | 51 Python methods passed, 0 failures/errors/skips | 52.554609119 s |

The final Python run covers the new heap module and existing raw-byte-DAG,
static-budget and route-inventory regressions. Its new heap corpus contains
296 actual direct Rust processes, 253 complete static-bound/Machine/Python
comparisons, 28 raw refusal controls and one additional isolated Python child
whose semantic verifier/analyzer/VM imports are blocked. The 296 processes also
include analysis-only and other policy controls; they are not 296 successful
program executions. These categories overlap and must not be added together.

The first differential failures compared the Python diagnostic message with
Rust's established error-code-only envelope. The next test adapter used that
established exact v4 validator but omitted its required JSON-line newline.
It also expected schema refusal before the existing primitive shape check for
nominal input. Only those test expectations/serialization were corrected. The
analysis and VM were not relaxed. All failed source snapshots, captured process
outputs and costs remain in the archive.

The final passing analyzer, consumer, Machine and test bytes match the source
commit. After the passing run, independent review corrected two descriptions:
the optional legacy `exports` behavior and the difference between arithmetic
refusal and unknown abstract facts. `SUMMARY.json` records the tested and
committed hashes for the resulting documentation and route-scope text changes.
It does not present those pre-commit runs as a clean final-commit execution.

The actual final executable was 4,527,792 bytes with SHA-256
`eca5c05c474471506dd375f17a4bb8e79bce8d5f7239934885d02e3a32dc685e`.
Its full bytes were rehashed after commit and matched every final process
record. Binaries, Cargo targets and toolchains are not packaged. The isolated
target used Rust 1.90, `--locked --offline`, no incremental compilation and
zero development/test debug information. Exact commands and selected environment
are in every `execution.json`; current tool identities are in the summary.

## Cost and scope

The seven recorded subprocess spans total **152.568865987 seconds**, including
both failed test runs. Those spans include nested compilation, test and actual
Rust process time. Do not add nested observations or per-test wall figures to
that total. Recorder source snapshots, human/agent development, review and other
orchestration were not fully timed; their complete costs are **unknown**, not
zero. Packaging and offline verification are separate observed operations.

The static statement covers logical live byte payload for one exact scalar
primitive v7/v8 invocation in the admitted acyclic profile. The bound includes
conservative branch joins, owned transfer, v8 caller-derived borrowed extents,
fallible empty owners and stopped prefixes. It does not establish whole-language
soundness, source/native refinement, general termination/cleanup, chain/recursive
heap bounds, host RSS, allocator metadata, or native execution authority.

## Offline verification

Run `python -B verify.py` from this directory, or provide the bundle directory
as its single argument. The verifier uses only the standard library. It hashes
all 94 archived members (17,206,873 uncompressed member bytes), checks all seven
attempt receipts and failed runs, recomputes the final counts, and compares
each retained positive Machine observation with its recorded Python oracle.
It extracts no files and executes no native code. Its result is archival
consistency, not renewed program admission or proof of a hostile producer.

The archive preserves a base Git revision plus every modified/untracked source
file at each attempted run. The separate source inventory hashes 855 files at
the final commit; actual bytes were also checked against that commit's raw Git
blob identities. The original external execution directories remain retained.
No prior integrated, migration, model or optimization evidence was rewritten.
