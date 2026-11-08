# Machine-plan workspace observation repair — 2026-11-08

## Failure and cause

The unified source run [42516123434](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42516123434), job `128839412395`, failed at the machine-plan independent byte-hash oracle on source commit `50c1578b4d4597e3070a9abc3700c9aacbf99851`. Its retained child reported seventeen 8-byte workspace fields, including offset `248`. The oracle and its synthetic test fixture still expected only sixteen fields. Their exact-dictionary comparison consequently rejected an intact native observation.

This is separate from the compiler's optional `alloc` effect node-accounting defect. The independent byte-hash program used here starts with zeroed workspace and only writes its first byte; its observed field at offset `248` must remain zero. No compiler, child loader, allocation rule, Core limit or machine-plan admission rule is changed by this repair.

## Minimal change

`tools/qualify_hia_selfhost_machine_plans.py` now includes `248: 0` in the complete expected header and accurately describes all seventeen retained observations. The equality check remains an exact comparison of the whole dictionary. Missing fields, additional fields and incorrect field values fail.

`tests/test_hia_selfhost_machine_plans.py` uses the complete observer contract, checks corruption and omission of each of its seventeen fields, and rejects an extra field. With those regression cases and the old oracle, the intact observation fails and omission of `248` is incorrectly accepted. After the oracle repair, all seven tests pass. Both before/after logs are retained.

## Original CI observation replay

Nine selected original artifact members were checked against their inventory and the original `SEALED.json`. The source artifact is `13631354671`; its ZIP SHA256 is `ff257fe3bb005283fd1a69cce925c0f86c59e81748dcce855aca9e4094d2cf92`.

The original first child stdout, empty input and complete 1 MiB output were fed unchanged to the retained old oracle and the fixed oracle. The old oracle returned the recorded workspace-header mismatch; the fixed oracle accepted all seventeen fields. All sixteen previously expected values already matched. The sole additional field was `248: 0`. Both expected and actual Core results were `5381`; the generated native sample SHA256 was `373a052b3b1e94546b3112ba922854bbe048b1dd33044ee296feb40a82432f9c`.

This step rechecks the original observation rather than reexecuting or rewriting the failed CI campaign. The original failed `RESULT.json`, seal, native image, request, receipt, stdout, stderr and input/output bytes remain retained as failure evidence.

## Fresh finite qualification

An isolated source export contains 252 baseline files individually checked against the exact Git blobs at `50c1578b4d4597e3070a9abc3700c9aacbf99851`, with exactly the two source/test changes above. The repair source commit is `9ca46007956a24674343400e556a5cc8a7e56b4d`. Source imports use a new directory without copied bytecode caches, `-B`, and an empty separate bytecode-cache prefix.

The original CLI was run with seven repetitions and followed by its `verify` command. Results:

- All **81 native invocations** completed successfully.
- Three legal machine-plan arms were built; four invalid plans were rejected by the existing gate.
- All **15 independent byte-hash observations** matched the independent result/output oracle and all seventeen workspace fields, including zero at `248`.
- The campaign status is `passed`; sealed-evidence verification is `verified`.
- All 250 recorded source-identity entries still match the files used for the run.

The complete fresh campaign retains every child request, result, input and output buffer, generated image, linked artifact, plan, command receipt and timing record. A lossless archive also contains the exact source snapshot, original CI failure members, regression logs and original/fixed oracle replay record. Archive members are checked for exact length and SHA256 after writing.

## Scope

This closes the machine-plan observer inventory mismatch for the retained finite compiler workload. It does not establish general compiler or machine-plan preservation. The report continues to state `general_preservation_proved: false` and `ndu_incremental_value: NOT_EVALUATED`. Only the listed workspace header fields are observed; the full workspace tail is outside this oracle. Recorded timing is campaign cost evidence, not an economic-value result. The root's subsequently integrated source head still needs its own exact-source CI and release/install checks.
