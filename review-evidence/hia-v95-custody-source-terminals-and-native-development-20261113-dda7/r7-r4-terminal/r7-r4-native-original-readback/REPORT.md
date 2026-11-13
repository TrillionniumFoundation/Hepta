# R7-R4 original Source / Native evidence readback

## Outcome and authority

This is an independent, read-only review of the already completed product run **43459534648**, attempt 1, at commit **abeef212e34023534d91f8f952280e2a8d0cbde6**, tree **f2bc61c11104136d3f56e3c4aefa00a4dada910b**. No product code, compiler, VM, test body, or qualification was executed by this review; no product or audit ref was changed.

The evidence integrity review passed. The original **Native job remains failed**. Its earlier cold and component successes remain valid only for their recorded scopes and this fixed source. The final machine-readable result is `analysis-r3/ANALYSIS-RESULT.json`.

| Original layer | Observed result | Exact boundary |
| --- | --- | --- |
| Product Source job 132002438040 | 1,274 tests, `OK`, 804.168 s | Complete ordered log IDs equal the earlier formal R7-R4 1,274-ID report |
| Cold replay | 11 / 11 checks true | Original 180 s qualification and 3 s cleanup limits retained |
| Nested fixed-core selfhost qualification | 5,052 / 5,052 checks true | 38 complete phases, 17 independent reference workers, actual six generation images |
| Call graph native controls | 2 tests, `OK`, 4.382 s | Original two tests in the job log |
| Language coverage | 1,242 checks true, 10 assertion tests pass | Original language report and its SHA-bound assertion result |
| Selected-release launcher | 26 tests pass | Original ordered 21 local observations plus 5 required ptrace observations |
| Candidate build | 9 tests pass | Recorded 55 image/manifest pairs, 75 process observations, 69 independent VM frames |
| Store lifecycle | 8 tests, `OK`, 34.612 s | Exact eight IDs in original Native log |
| Store original Agent callers | 48 tests pass | Actual 41,764 machine returns and one mapping recorded |
| Store namespace caller | Outer 1 failure; nested 35 tests contain 3 failures | Original budget failures preserved below |
| Later work | 103 API steps skipped | No qualification is inferred for them |

The Native API inventory contains 122 step records: 18 successful, 1 failed, and 103 skipped. These counts include setup, evidence uploads, and post-job actions; 18 is not a count of passed business suites. The sole failed step is number 15, `Native Store lifecycle original namespace callers`.

## Complete original ZIP verification and restoration

The original files were read from `/workspace/scratch/dda74a4fae35/v92-r7-r4-native-original`. All original archive/log/DOWNLOAD bytes, permission modes, and modification timestamps were unchanged after restoration. ZIP integrity was checked through complete reads, with independent CRC32, SHA-256, and Git-blob SHA-1 calculation for every member. Restored outer members were then read back completely and their exact original file modes checked.

| Original archive | Original bytes | Artifact ID | Outer members | Uncompressed outer bytes |
| --- | ---: | ---: | ---: | ---: |
| `native.zip` | 98,307,377 | 14056462556 | 10,178 | 577,070,871 |
| `source-vm.zip` | 296,429 | 14057540922 | 69 | 616,820 |
| `wire.zip` | 67,563 | 14056368016 | 1 | 167,806 |

Original archive SHA-256 values:

- Native: `1f9590a096fab0ae05f87a296cd2db821e17929e7bc9111182add0d9f8f8a1c9`.
- Source VM: `8356b4fb59577e7ff809490c558f255368771c7753039f350a4399f06fd5695c`.
- Wire: `f5dd72900fb18a1c9e5d62fcef1194184a8b27c49a4661a708384db9dd4c1886`.

The 10,248 outer members contain 41 nested ZIP archives. All 55,616 nested members were read completely and independently hashed/CRC-checked. The original complete nested ZIP bytes remain in their restored outer-member locations; nested archives were not redundantly expanded to disk.

The Native archive records six actual Unix regular-file modes:

| Mode including regular-file type | Members |
| --- | ---: |
| `100400` | 1,452 |
| `100500` | 18 |
| `100600` | 71 |
| `100644` | 8,628 |
| `100700` | 7 |
| `100755` | 2 |

The outer ZIPs contain no directory entries. **Original directory modes were not recorded.** Restoration created local directories with mode `0700`; that is a local safety choice, not a reconstructed historical directory-mode claim. ZIP DOS date/time fields are preserved without inventing a timezone. Restored file mtimes are not claimed to reproduce the historical ZIP timestamps.

The 71,463,780-byte `MEMBER-MANIFEST.json` records every original ZIP metadata field used by the verifier, all hashes, actual modes, restoration readback, and nested inventories. Its SHA-256 is `528498d09e5ff306be28e666a5634fe967e667e71381ad5758c7f302b8584ac7` and Git blob identity is `ae804b5120b57a6f103b1e3de15bf7bf1eb32d7c`. The manifest's complete bytes are included in the separately indexed readback capsule; a computed identity alone is not a publication claim.

The restoration rejects absolute/traversal/backslash/drive/NUL paths, duplicate or colliding paths, encryption, symlinks, and special files. It uses exclusive creation and no-follow directory/file access. Original permissions are applied only after byte and CRC verification.

## Product Source result and earlier formal reference

The actual product Source log has 1,274 distinct ordered test IDs followed by `Ran 1274 tests in 804.168s` and `OK`. One negative CLI-parser test prints its expected usage diagnostic between the test label and its final `ok`; that complete span is retained in `SOURCE-ID-COMPARISON.json` rather than misclassified as an error.

The product log sequence is byte-for-ID equal to the full ordered list in the earlier formal R7-R4 report from run **43451128811**. That earlier report, its `terminal-worktree/INDEX.json`, and their exact bytes/modes were checked against its `EVIDENCE-MANIFEST.json`. The 3,055-file source index independently recomputes the same Git tree named by the actual product commit API. The formal reference retains the original main 530 IDs and a733 973 projected IDs; its current projection lists contain 554 and 1,005 IDs respectively, all present in the later product sequence.

These are two distinct executions. The earlier formal report's 1,060.561643572 s is not the later product log's 804.168 s. The earlier formal portable fixture/raw outputs remain in their own actual retention location. **They were not used as substitute raw output for the later product Source job.** For this product Source job, the retained raw evidence is its complete Source log and the actual 69-member Source VM archive. This review does not invent additional product-run portable fixture files.

The already-persisted original log blobs are:

- `SOURCE-JOB.log`: `7cd5bf57c7ac02807c1855f3403a0e80d5470f7b`, 370,073 bytes.
- `FULL-JOB.log`: `d304602ea70e0bcc541c215f1265e5b17448e22b`, 69,590 bytes.

## Cold binding and scope

All 1,430 actual cold-export files match the cold source manifest and the corresponding SHA-256, size, and Git blob identities in the fixed 3,055-file source tree. Their actual archived/restored permissions are `0400`, as the original export code deliberately sets; those export permissions are distinguished from repository Git permission modes. This binds the actual retained cold subset. It is not a claim that this product artifact contains a second full 3,055-file checkout.

The original process owner records normal return code 0, exit observed before its deadline, no timeout or interruption, a reaped leader, final `ECHILD`, no remaining direct children, and complete cleanup. Its recorded intervals are:

- Owner start-to-exit-observation: **130.927470587 s**.
- Nested qualification elapsed: **130.385133831 s**.
- Outer cold wrapper elapsed: **131.402971270 s**.
- Cleanup: **7.889183 ms**.

The owner explicitly records `historical_descendant_inventory_complete: false`; this review preserves that limitation and does not promote final cleanup into a complete historical descendant inventory.

All 38 phase receipts match their original report hashes and archive hashes. Every phase archive manifest and every archived file's bytes/hash/mode agree with the complete nested ZIP readback. The phase index has 38 completed entries and zero exceptions. All 17 reference-worker envelopes bind their canonical complete reference payload, source-manifest digest, PID, zero return, and completion before B0. No reference or VM was executed again.

The actual fixed points are:

- B1 = B2 = B3: `bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.
- M1: `166b7c524aa7018f7a7e1145dbe68f0df9889f724bafaa6a3efcc642239a9e93`.
- M2 = M3: `04ea7e20c64109b3ff3e6f96b4a35283b44d6051cc442d5d11d98e2be1044ed2`.

M1 differs from M2 by the original deliberate wrapper mutation. The original source explicitly requires M1 != M2 = M3 and M3 != B3. Each actual image is 673,413 bytes and is bound to its original full receipt and retained file. The scope remains the fixed canonical HIA v8 subset documented by the original qualification.

## Native failure preserved

The namespace outer test is:

`tests.test_hia_artifact_namespace_native.ArtifactNamespaceNativeTests.test_original_agent_tools_and_campaign_with_all_three_owners_and_no_namespace_reference`

It ran one test and failed because its nested original 35-test suite returned three failures, with no nested errors, skips, expected failures, or unexpected successes:

| Nested original method in `tests.test_hia_agent_native_tools.NativeLifecycleTests` | Original failure |
| --- | --- |
| `test_expired_evaluation_is_rejected_before_any_reference_or_native_runner` | Baseline emit at `build_pair` line 67 returned `E_HIA_BUDGET`, codegen phase: frozen context deadline expired before emission |
| `test_native_timeout_is_incomplete_terminated_and_not_adoptable` | `5.7218977530000075 not less than 5` |
| `test_reference_loop_cannot_restart_or_overrun_frozen_context_deadline` | Baseline emit at `build_pair` line 67 returned the same codegen budget refusal |

The original 3,000 ms total / 1,000 ms native budgets, strict less-than-5-second assertion, 1,800 s outer group limit, and 20 s compiler limit were unchanged. The outer child returned 1 without reaching its 1,800 s timeout. No performance cause is inferred from these records.

The separately named `wire.zip` contains only the same `hia-cold.json` bytes as the Native artifact. It does not show that the later JSON-wire tests ran. The API's 103 skipped steps remain skipped.

## Reader corrections and custody

Two readback-script errors were preserved with their exact scripts, stdout/stderr, partial reports, and narrow successor patches:

1. Reader R1 incorrectly required M1 = M2 = M3. Reader R2 restored the original intentional M1 != M2 = M3 relation.
2. Reader R2 incorrectly compared the launcher's globally declared 26-ID list to the concatenated execution order. Reader R3 checks the actual original `group_ids` partition: exact ordered 21 local plus exact ordered 5 ptrace, with all 26 literal IDs preserved and unique.

Neither error affected original product evidence. Reader R3 completed with `ORIGINAL_EVIDENCE_READBACK_PASS_NATIVE_QUALIFICATION_FAIL_PRESERVED`.

The readback capsule preserves the full member manifest, validators, all reader attempts, selected original reports, and the final analysis. Its Git chunk/index receipts establish custody of that capsule only. The three complete original ZIPs remain in the parent directory and in their original Actions artifacts; this readback task does not claim that those complete ZIP bytes have been uploaded to Git. In particular, the full 53,700,006-byte cold qualification report remains in its original Native ZIP and the verified restored member. Original logs already have the separate Git identities stated above.
