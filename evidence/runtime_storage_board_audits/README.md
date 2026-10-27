# Historical runtime, stored-borrow and board audit evidence

This directory preserves the development attempts and scoped independent audits from the structured-task-tree, bounded I/O, stored-borrow and board-execution increment. It is a historical evidence archive. A report whose own status is `passed` remains attached to the compiler and source identities inside that report; copying it here does not qualify a later compiler.

The root source was frozen at `d8c4e8578bff5dc6e8b474d43e2dfbd6442ec38e` when this archive was prepared. Its compiler-content digest is `d711649fed69aed280b9d401a104e87542988fcaf1afe0e2c293e43055cc33ac`. The digest hashes sorted `hepta/*.py` files as basename, NUL, contents, NUL; it is not a digest of the entire repository. The independently started 36-gate frozen release is separate. Its outcome is not supplied or inferred by this archive.

## What is preserved

| Directory | Preserved original records | Interpretation |
| --- | --- | --- |
| `root_board/` | Board analyses, generated Rust, build/link/execute records, qualification attempts 1–4 where a file exists, pre-integration/focused logs, unsafe-export acknowledgement, execution prerequisites | Development history for QEMU system-model and cross-execution work; no physical-board qualification |
| `storage_branch/` | Original stored-borrow qualification, generated Hepta/Rust inputs, independent board-validator audit | Branch qualification and a separate report-validator review; native executables are identified in the manifest, not copied |
| `tree_branch/` | All seven original task-tree attempt reports | Includes the first two failed builds, development runs, and later three-repeat qualification reports |
| `io_history/` | All five external I/O reports, attempts 001–005 | Keeps sandbox failure, metadata-validator failure, historical pass, pre-audit pass, and repaired audited pass |
| `io_independent/` | Preliminary, initial and final independent review; raw native probe source and records; failed non-UTF8/timeout retention experiments; repair verification | Distinguishes source review, report mutation checks, one independent runtime probe, and actual producer-boundary output tests |
| `storage_integration/` | Original `qualified-audit.json` | Six-method cross-capability test output and commands are embedded in the original JSON |
| `io_validator_history/` | Exact old `tools/validate_io.py` Git blob and full repair diff | Preserves the original validator that accepted four malformed-report controls, alongside the repair |

`manifest.json` records each original path, byte length and SHA-256, and each stored path, byte length, SHA-256 and encoding. JSON reports, logs and sources were not reformatted. The two board reports larger than 1 MiB use deterministic gzip with `mtime=0` and no embedded filename; decompression reproduces their exact original bytes. Original absolute paths inside reports remain intact. Generated documentation and execution notes are labelled separately from original process evidence.

Native ELF files and the Rust object archive are not stored as binaries. Their original paths, sizes, formats and SHA-256 values are retained in `omitted_native_binaries`. This is an explicit omission, not a claim that an executable can be reconstructed from a checksum.

## Failures, repairs and review boundaries

### Board development

`qualification-attempt1.log` records failure when the generic `rust-lld` driver was invoked without selecting its linker flavor. `qualification-attempt3.log` records rejection because pinned Rust release metadata was not accepted. No corresponding JSON report files were present; none were reconstructed. Attempts 2 and 4 have both original JSON and log files and report `passed` against their own compiler digests.

`unit-preintegration-attempt1.log` preserves the actual 930-test run with 2 failures and 8 errors, plus its append-only-output refusal. `focused-attempt1.log` preserves a 37-test run with one failure; `focused-attempt2.log` records 12 passing tests. `integration-focused-attempt1.log` records 87 passing tests. These are distinct historical runs, not a substituted log for the current frozen release.

`cross-export-ack.json` records AArch64 QEMU user-mode execution using a Rust extern-C caller. It expressly does not qualify an independent cross C compiler or physical hardware. Board reports qualify a pinned Cortex-M4 QEMU system model with trusted BSP/interrupt/MMIO obligations. The prerequisite record is an environment inventory, not a successful device or model trial.

The storage branch's `board-validator-audit.json` records baseline report validation and ten in-memory malformed-report checks. Its `actual_native_runs` is zero: that independent review did not execute QEMU, ELF images or a compiler.

### Stored borrows and cross-capability integration

The standalone storage qualification is bound to compiler digest `a0a20eed22d475e98afd440f00d689504ec0872015d211d1ea6278b70605479e`. It covers a finite explicit-lifetime record profile with mandatory Rust region/alias checking. General lifetimes, traits, independent lifetime IR and stored-borrow C lowering are not claimed complete.

The integration audit records compiler digest `d711649fed69aed280b9d401a104e87542988fcaf1afe0e2c293e43055cc33ac` and source commit `df34e41b25504496f3aee3e647e2347a339ddc0b`. Matching the current compiler-content digest does not turn its recorded commit into the frozen release commit. Its denominator is 61 frontend rejections, 5 native metadata rejections, 3 no-std rejections, 2 cross-module rejections, 8 unsupported declarations checked across 4 backend profiles, and 3 valid native programs. These overlapping categories must not be summed as independent completed tasks.

Invalid region candidates received **Rust metadata checks only**. `actual_invalid_native_runs` is zero; invalid programs were not linked or executed. The six-method unittest transcript is preserved at JSON pointer `/test_output`, with argv and outputs at `/commands`; no separate text log was available.

The storage agent reported 937 passing full-suite tests and 13 passing final regressions only through conversation tool output. No separate original log files were supplied. This archive records that absence and does not present inherited unit logs as new evidence.

### Structured task trees

Attempts 01 and 02 remain failed, including their native-build diagnostics. Attempt 03 is a one-repeat development pass; attempts 04–07 retain their original source/compiler identities and counts. Final branch attempt 07 reports compiler digest `a8dad79850fef8b3b5b6271f9aa444a60b8a464953e9eeb428d827449d11782f`, 3 repeats, 6 source executions, 3 native control runs, 384 adoption/failure races, 192 spawn/close races and 4 wrong-runtime controls.

The profile is bounded to 256 groups and depth 16, uses consuming child adoption, and requires cooperative cancellation. Legacy joins and tree joins wait for descendants; a refused adoption consumes, cancels and joins the child. The report does not prove arbitrary worker termination, bounded cancellation latency, global process-resource bounds, source-to-runtime refinement or race freedom, and it does not qualify a C backend or a general async scheduler.

The reported 86-test focused unit result was not saved as a separate original disk log. Its absence is explicit in `execution-notes.json`.

### Bounded I/O and the independent audit

I/O attempts 001 and 002 retain `failed` status. Attempt 001 contains an actual native assertion failure in the sandboxed attempt; its filename documents the original sandbox diagnosis. This archive does not infer an errno that its transcript does not print. Attempt 002 records `native toolchain/target changed`. Attempt 003 is a one-repeat historical pass. Attempt 004 is the three-repeat report reviewed before the evidence repairs. Attempt 005 is the three-repeat repaired report bound to I/O branch commit `50f91fc759775bdcf3163f59370dd1ab3500d7a8` and compiler digest `affd25fe20493fbe5d226122aeefe16cabea37795a10cfac7ed8209c06a01602`.

The preliminary and initial audit records preserve four **report mutations** that the old validator incorrectly accepted: contradictory overflow flags, contradictory optimization flags, a false C-compiler argv, and an artifact path not bound to the executed binary. These are metadata-validator findings. No claim is made that four altered applications were compiled or executed.

The final audit preserves the repair verification: the original four controls and two additional raw-output/executable-hash controls are rejected. The pre-repair non-UTF8 retention finding was established by source inspection, not an executed pre-repair experiment. The post-repair failed and timed-out local subprocess experiments were actually executed at the producer boundary, preserve raw bytes via base64, and remain failed reports. They test evidence retention, not I/O application behavior or productivity.

The independent native probe exercised consuming a ticket through a foreign reactor. It observed status 10, one retained origin slot and 4093 retained bytes, subsequent capacity refusal status 7, and one deallocation of the exact original buffer at origin shutdown. This matches an explicitly bounded origin-capacity limitation. It does not establish a general memory-safety proof. The adjacent Hepta counterpart was native-checked; the independently executed body was the archived Rust probe using the production runtime.

The reviewer did not independently rerun the full I/O producer or independently execute all partial-write, readiness/EINTR, descriptor-reuse and RLIMIT controls. The full list of exclusions remains in the original final audit. I/O/task-tree composition, general network/file I/O, background execution, cross-thread interruption, other platforms and hard real-time cancellation remain outside these records' claims.

## Historical validator material

`io_validator_history/validate_io-before-audit.py` is the exact Git blob `674d21d012c2341d2a29bf44ca90d41b2bdfc148:tools/validate_io.py`, SHA-256 `4365cb371447ce39ade2bf1e7712c5c1cac0ca4d3764df9e8b95017dabb161a9`. The full-index diff is the exact output of `git diff --no-ext-diff --binary --full-index 674d21d012c2341d2a29bf44ca90d41b2bdfc148 50f91fc759775bdcf3163f59370dd1ab3500d7a8 --`; it covers seven files, including the validator, tests, runtime profile scan and unsupported-IR refusals.

These preserve the history required to inspect or replay the findings with the corresponding complete Git trees and pinned toolchains. The archived Python source is not imported by the archive verifier. Running a historical qualification validator against a different current compiler is not a valid qualification replay. Environment paths, native toolchain identities and other prerequisites in the original reports still matter; this archive makes no environment-independent replay claim.

## Interrupted command and absent evidence

`execution-notes.json` separately records the parent's reported `python tools/release_check.py --help` invocation: the script did not implement argparse, started work, and was immediately interrupted in session 41307 with exit 130 and empty stdout. No complete release report exists for that invocation. It counts as neither success nor frozen qualification. This is an attributed execution note, not a fabricated process log.

The same notes identify the separate frozen session 76452 and its reported in-progress state when archival was requested. They do not assert its final result. No original record missing from the enumerated source directories has been recreated.

## Integrity verification

From the repository root:

```sh
python -B evidence/runtime_storage_board_audits/verify_archive.py
```

While the original workspace paths still exist, add `--check-originals` to compare every copied filesystem record and omitted binary identity with its original. This optional mode reads those files; it does not execute them.

The verifier checks exact file inventory, stored digests/sizes, decompressed original digests/sizes, zero gzip timestamps, absence of symlinks/direct native binaries, and manifest totals. It imports no Hepta compiler modules, calls no native test programs, and reruns no qualification. Its success establishes archive byte consistency, not authenticity of arbitrary third-party reports or correctness of their claims. `manifest.json` is explicitly excluded from its own payload hash list; its digest is reported by the verifier and can be pinned by the enclosing Git commit or review record.
