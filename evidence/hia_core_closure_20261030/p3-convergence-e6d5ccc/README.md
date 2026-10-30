# P3 source-provenance convergence on PR405

## Outcome and exact identities

The remaining strict C importer source-path binding gap is fixed in local commit `e6d5ccc2c5d1bfc8479f92b0385428ac578c358a`, tree `34c4cf0f49982b9c9865021cb818cf90b6b27b7e`, directly based on public PR405 `192d2cbba7e49bde3b03af73685ecf96f6fb1b05`. The frozen local commit passed the required migration workflow selection: **177 methods across27 modules, zero failures/errors/skips/expected failures/unexpected successes**. All1087 materialized source blobs/modes match that Git tree before and after execution, and the recorded Python/Clang/GCC/Rust executables remained stable. The sparse worktree intentionally excludes historical archives and other directories; this is not a full-tree or full-language qualification.

Only these three source paths changed:

- `tools/c2hepta.py`: initial and final bounded reads now use the admitted canonical source pathname; direct leaf symlinks are rejected before compiler execution; `O_NOFOLLOW`, when available, rejects terminal symlink replacement at the actual open.
- `tests/test_c2hepta_source_provenance.py`: six real-Clang regression methods, including normal regular-file and stable parent-directory-alias positives.
- `.github/workflows/hepta-migration.yml`: adds that one module to the existing strict no-skip selection.

The source commit is local, and the independent execution identity is retained here. A later common405 integration commit must execute its own relevant tests. No public execution, remote mutation, general P3/P4 closure, production Rust authority switch, or optimization policy change is claimed.

## Why selective convergence was necessary

PR407 and PR405 diverge from `e4b30b2884486145c352beb9611fcdc2a5ca9d3a`; neither is an ancestor of the other. The old security branch has only149 files, whereas405 contains many subsequent language, capture, migration and evidence changes. Whole-tree replacement would discard newer capabilities.

| Audited branch | Original obligation | Actual405 disposition |
| --- | --- | --- |
| #393 (`69a6bf3`) and preceding AST fixes | Canonical source/output/report isolation and fail-closed malformed AST handling | Already present, with stricter JSON shape/byte/depth checks and POSIX directory-fd publication |
| #401 (`e0dbffb`) | Reject unsafe emitted function and parameter symbols | Already present through ASCII identifiers and lexer-derived reserved names |
| #402 (`5953674`) | Bound decimal text before integer conversion | Already present: scalar type/length validation and at most10 decimal digits before `int` |
| #403 (`5870dcb`) | Deep direct-IR rejection reproducer | This head is test-only despite its title; its required fix arrives in #406 |
| #406 (`56f418e`) | Bound expanded IR visits, depth and malformed children before recursive consumers | Already present in405 with iterative preflight for checking, hashing and emission, including DAG visits/cycles |
| #407 (`e06b5ff`) | Bound parameter containers and scalar IR fields | Already present in405; its256-parameter/256-token domain is preserved instead of imposing the older64/128 limits |
| #404 (`67e8228`), sibling of403 | Bind source receipt and reads to the admitted canonical pathname; retain terminal-source-symlink refusal | Receipt admission already used canonical A, but both reads still used the mutable caller alias. This is the missing semantic fix adapted here |

405's newer negative-expression payload guard, emitted-parser budget, byte-preserving shared capture, live output/time/process cleanup bounds, frozen source stdin, macro/alternate-token rejection, canonical output/report admission and pinned POSIX artifact directories remain unchanged. No second checker, interpreter, migration backend or compiler path was added.

## Reproduced failure and corrected behavior

The caller chooses `alias/source.c`, initially resolving to A. Rebinding only the caller's parent alias to B after admission previously caused the first bounded read and final recheck to read B while the receipt still named A. Real Clang consumed B's bytes and emitted B's function under that mismatched attribution. A second control changed admitted A after its initial snapshot while rebinding the alias to B containing the original bytes; the old final recheck incorrectly accepted the persistent A change.

The fix uses admitted A for both bounded reads. Stable parent-directory aliases remain accepted. Direct source leaf symlinks are refused explicitly; leaf substitutions after the explicit check fail at the actual non-following open where supported. Canonical pathname binding does **not** pin every ancestor directory or source inode. Arbitrary ancestor replacement, whole-filesystem race freedom, crash atomicity and general memory/RSS guarantees remain outside this finite scope. The pre-existing non-POSIX publication fallback is not newly qualified against hostile directory renames.

## Actual execution records

| Observation | Execution identity | Outcome | Retained compiler observations |
| --- | --- | --- | --- |
| Initial harness development | Exact405 implementation; new uncommitted test module |5 semantic failures plus2 positive-subtest serialization assertion failures |7 migrations,28 actual Clang calls |
| Corrected red harness | Exact405 implementation; corrected new test module |6 methods:5 fail,1 passes with2 positive conversions; no errors/skips |7 migrations,28 actual Clang calls |
| Focused fixed green | HEAD405 with final candidate source bytes before commit |6 methods pass, no nonordinary outcomes |7 migrations,20 actual Clang calls |
| Frozen required workflow | Exact local e6d5ccc commit/tree |177 methods pass across27 modules, no nonordinary outcomes |Raw unittest output retained; per-compiler-call instrumentation was intentionally disabled for this broader selection |

The precommit fixed bytes are verified identical to the later frozen execution bytes in `source-export/manifest.json`; the original precommit observation has not been relabeled as a committed or public run. First-run positive assertion mistakes compared tuple-valued in-memory IR directly with JSON arrays. `baseline-405-red/harness-finding.json`, the original test module and all original logs preserve that mistake. The correction compares the full JSON representation without dropping fields; all five product assertions still fail on unmodified405.

The new green contains three successful conversions (ordinary path, stable parent alias, parent alias rebound before initial read) and four refusals (direct leaf symlink, initial leaf substitution, final leaf substitution, persistent admitted-source change hidden behind a rebound parent alias). Twenty retained real Clang calls are five migrations with three probes and one actual AST invocation each; the two admission-stage refusals invoke no compiler.

The required177 includes the existing `test_guarded_migration_executes_original_and_generated_native_code`: actual original GCC C and generated Rust libraries are called for66 selected signed/unsigned input cases, and a deliberately wrong compiled Rust target is observed to disagree. These are assertions executed inside the177-method gate, not a separate extra66-test suite. Other native tests also execute; this package does not claim an aggregate native-call total. Native temporary binaries from those existing tests are not retained; exact test source, executable tool identity and original execution output are retained. The emitted source/AST captures in the focused provenance tests are real compiler observations, not claims that those focused functions themselves were natively executed.

## Contents and reproduction

`qualification-summary.json` indexes all four attempts without rewriting outcomes. Each attempt retains actual argv/cwd/selected environment/start/end/duration, source/tool before/after identities, selected test IDs and full stdout/stderr. Focused attempts additionally retain original raw Clang stdin/stdout/stderr and migration reports/emitted source before temporary directories are removed.

`source-export/manifest.json` contains raw changed UTF-8 bytes, modes, SHA256 and Git blob IDs against public405; `source-export/source-change.patch` is the exact full-index patch. `inspection/` and `metadata/` retain the read-only branch comparison and original PR metadata. Collector scripts only execute the repository test assertions and passively retain observations; they do not define migration semantics.

On a checkout of the frozen source, provide the pinned Rust1.90 executable through `RUSTC`, plus working Clang/GCC and their normal runtime libraries. The workflow's actual27 pattern strings are preserved in `frozen-migration-workflow/tests.json`. To rerun the focused module use `python3 -m unittest discover -s tests -p test_c2hepta_source_provenance.py -v`. To rerun the exact required selection use the Python `patterns`/suite block from `.github/workflows/hepta-migration.yml`; reject skips as that workflow requires. The retained external `collect_validation.py` records both selections in this workspace with the pinned Rust1.90 and restored LLVM20.1.2 environment.

Parent integration and public publication are separate actions. The broad27 strict blocker obligations remain OPEN, all eight universal closure claims remain false, Python remains the production authority, and optimization policy remains `no_change`.
