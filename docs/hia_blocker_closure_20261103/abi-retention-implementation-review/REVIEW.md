# ABI matrix original-artifact retention — local review

## Delivery

- Commit: `d2d7268c802eb838839e7a7482f3915305b6d780`.
- Parent: `23af1df3eed65230137aa54ab8b10eac3520abd3`.
- Tree: `0e2e8c982dada17251e9c97c746689ee85f69f37`.
- Isolated worktree: `/workspace/scratch/299d77caaebb/Hepta-abi-retention`.
- No remote publication, model request, benchmark, or change to the frozen 23af model workspace/owner/protocol was made by this task.

Four committed files change the native-host validator, its focused adapter controls, and the two existing native-host/P3-Windows upload entrypoints. The original ABI matrix, two optimization profiles, 181 calls per profile, three ill-typed declarations, and compiled wrong echo keep their existing semantics and denominator.

## Evidence contract

`hepta.native-host.v3` requires a create-only persistent artifact directory. Before the temporary execution directory is removed, the producer copies the actual matrix object, both profile executables, the wrong-echo executable, and any other files actually produced there. Failed/partial compiler outputs remain unqualified evidence.

The archive separately preserves the positive C source/header, each changed type-control header, the wrong-echo source, and the C identity probe. These cannot be reconstructed by copying only the final mutated `matrix.c`/`matrix.h`. The qualifier's C probe/build/execution calls retain their original argv plus original bounded stdout/stderr bytes; capture failures retain the bounded prefix, reported total-byte counts, and an explicit incomplete flag.

Admission verifies the exact retained file set, ordinary files, relative paths, bytes/SHA-256 and manifest identity. It then checks native/source roles against the original report's object identity, O0/O2 executable identities, wrong-echo identity, source hashes, native build receipt, command order and raw streams. The existing `validate_report` still checks the generated program/header, compiler macros, exact target/toolchain, exact C argv, both profile observations and all original negative controls. Resealing an internally consistent manifest does not substitute for these cross-bindings.

`--artifact-directory` declares the persistent destination. The CLI default is `<report-stem>-artifacts` beside the JSON report. Both existing GitHub Actions entrypoints upload their matching persistent directories under the existing `if: always()` steps. The P3 Windows entrypoint now uploads `native-host-p3-artifacts/` as well as its JSON.

## Failure behavior

An existing artifact directory is refused. Missing, truncated, replaced, aliased, extra or linked evidence cannot qualify. Archive I/O failure also fails the attempt. If compilation/execution and archive retention both fail, `execution_failure` and `retention_error` remain separate and the original execution failure is not overwritten by the retention exception. A failed or partial receipt cannot be promoted by the new admission helper.

Historical v2 receipt-only artifacts are unchanged; they are not relabeled as containing independently inspectable original binaries.

## Actual local verification

The same committed source executed `tests.test_native_host_evidence`: **17 tests passed, zero failures/errors/skips**. `adapter-tests.log` retains the complete output; `report.json` records the actual duration, all test IDs, exact commit/tree and four source-file identities. `git diff --check` passed and the worktree was tracked-clean.

The focused controls cover temporary-directory cleanup, original CRLF bytes, create-only publication, native-role deletion/truncation/replacement, mutation followed by manifest resealing, original-command substitution, extra/path-alias/symlink rejection, legacy receipt refusal, bounded capture-prefix retention, O0 success followed by O2 failure, and simultaneous execution/archive failures.

These are explicitly synthetic adapter controls. This local environment has no Rust compiler, so no genuine Rust/C ABI matrix was executed here. The unchanged actual seven-host matrix remains required in CI after integration; local adapter success is not substituted for it.

## Exact limits

The archived `inputs/matrix.rs` is the canonical UTF-8 string passed to `compile_rust`. The backend's actual temporary `program.rs` can have platform newline materialization and is not retained by this patch. `native-build.json` is the backend's structured receipt. The backend's internal Rust compiler argv and original stdout/stderr are also not captured by this patch. Those exclusions are enforced in the retained scope fields, not only stated here.

The increment closes the missing matrix object/executable retention path once actual-host execution passes the new gate. It is not a proof of arbitrary receipt authenticity, Rust compiler refinement, FFI memory safety, all ABI features, physical-board execution, or whole P0–P7 closure.
