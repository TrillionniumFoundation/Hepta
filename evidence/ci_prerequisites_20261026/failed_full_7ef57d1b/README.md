# Original full-CI failure at 7ef57d1b

This appendix preserves the completed GitHub Actions failure for
`7ef57d1b380e73269f592fa26fe95f9636c88586`. Tool installation passed. Full source
qualification completed **50 gates, 48 passed**; HIA completed **15 gates,
14 passed**. The remaining failures were the zero-skip unittest requirements
and a `PermissionError` while collecting namespace qualification evidence.
All three native performance profiles reached their own passing terminal state.

These are the original 7ef results. They do not assert outcomes for the later
d8e1b676 or 44cb3257 CI runs.

## Provider identity and complete log

| Item | Identity |
| --- | --- |
| Run | [40435880235](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435880235) |
| Job | [121964313186](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435880235/job/121964313186) |
| Artifact | [12704884741](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435880235/artifacts/12704884741) |
| Provider observation | 2026-10-27 02:33:32 UTC |
| Original ZIP size | 76,482,230 bytes |
| Original ZIP SHA-256 | `e4294fa3f7638cb579011b7025d96d3fc785bb4f1afddfad29a1d53fd412c92d` |
| Complete decoded job log | 144,758 UTF-8 bytes, 1,378 lines |
| Job-log SHA-256 | `f70c250f4e2de09b145da08779f8744a5522393d725b0fa51c35a91c9b7f66ab` |

`provider-observation.json` preserves public provider metadata. The downloaded
ZIP exactly matched its provider size and digest. The job log is the complete
provider-decoded text, encoded as UTF-8 without newline translation; original
HTTP transport bytes are not separately claimed. No temporary signed download
URL is retained.

Distribution Bubblewrap startup, LLVM installation, locked Rust bootstrap,
selected Rust identity, and Lean/QEMU installation all passed (steps 7–11).
Source qualification and HIA then ran to failure (steps 12–13); upload succeeded
(step 14). The QEMU lock's exact source URL and bootstrap are retained under
`source/`. This attempt did not repeat the earlier QEMU download failure.

## Full source qualification: 48 of 50

`originals/candidate/release-validation.json` records the full interval
`02:03:18.103977+00:00`–`02:20:04.073451+00:00`, `status=failed`, and
`snapshot_unchanged=true`. Only these gates failed:

| Gate | Original result | Meaning |
| --- | --- | --- |
| `unit_and_integration` | Exit 0; `Ran 2099 tests in 582.709s`; `OK (skipped=15)` | The strict zero-skip qualification rule rejected this completed test process. |
| `strict_namespace_execution` | Exit 1; `PermissionError`; `qualified=false` | Namespace evidence collection could not complete. |

The aggregate's `test_count=0` is the strict qualification collector's accepted
test count. **It does not mean that zero tests ran.** The verbose original log
records 2,099 tests and 15 skip records, with no terminal assertion failures or
errors. The enclosing gate took 584.249 seconds.

### All 15 named source-suite skips

`named-source-unit-skips.json` preserves each exact original line, line number,
identifier and reason. One entry is a `setUpClass` skip; it is not an individual
test method. Names below are copied from the verbose log:

| Class/module | Skipped method or class setup |
| --- | --- |
| `test_hia_composite_bulk_native.CompositeBulkNativeTests` | `test_full_native_oracles_and_strict_retained_receipts` |
| `test_hia_edit_study.StudyActualNativeControlTests` | `test_actual_values_and_both_declared_overflow_boundaries` |
| `test_hia_selected_formal.SelectedFormalKernelTests` | `setUpClass` |
| `test_owned_aarch64_link.AArch64LinkProbeTests` | `test_actual_aarch64_static_link_resolution` |
| Same class | `test_actual_unreviewed_import_rejected_before_linker` |
| Same class | `test_link_receipt_cannot_use_changed_native_compiler` |
| Same class | `test_linked_image_negative_header_controls` |
| Same class | `test_linked_image_rejects_writable_executable_load_and_exec_stack` |
| Same class | `test_missing_or_wrong_export_refuses_source_claim` |
| `test_owned_aarch64_runtime.FiniteOwnedRuntimeTests` | `test_compiler_change_during_real_runtime_link_rejects` |
| Same class | `test_failed_actual_emulation_retains_the_bound_process_record` |
| Same class | `test_real_arm64_link_honestly_records_no_execution` |
| Same class | `test_real_native_linux_allocator_exercises_bounded_ownership` |
| Same class | `test_unreviewed_foreign_import_rejected_before_linking` |
| Same class | `test_wrong_export_and_unavailable_runner_reject` |

The recorded reasons identify pinned LLVM/lld/QEMU, pinned LLVM/Rust, `LEAN`,
or Clang/lld prerequisites. Source guesses are not substituted for these lines.

### Namespace qualification interruption

The exact error in `originals/candidate/sandbox.json` is:

```text
PermissionError: [Errno 13] Permission denied:
'/proc/1/root/tmp/hepta-sandbox-qualification-90koxy9m/parent_oracle_canary'
```

The report records `startup=passed` and the remaining nine checks as `not_run`.
Those are the retained report states; they do not prove that no internal probe
process had already executed before evidence collection raised the exception.
The exact historical `sandbox_qualification.py` is preserved for review.
This receipt demonstrates an interrupted qualification, not an observed escape.

## HIA qualification: 14 of 15

`originals/hia-unified/qualification.json` started at `02:20:04Z` and completed
at `02:32:30Z`, with `status=scoped_gates_not_all_qualified`, `ok=false`, and
`unchanged_source=true`. Only `unit_regression` failed acceptance:

```text
Ran 2102 tests in 586.083s
OK (skipped=2)
```

The process exited 0 with 0 failures and 0 errors. Its quiet log does not identify
the two skipped cases. Their names are not inferred from the separate source
suite's 15 skip records. Both `composite_bulk_targets` and
`standalone_aarch64_qemu` passed in this attempt, as did the other 12 non-unit
HIA gates, including performance.

## Three completed native performance profiles

All three originals have `phase=complete`, `status=passed`, `ok=true`; their
measurement-quality and performance-threshold failure arrays are empty.
The independent review recalculated the exact sample inventories and schedules,
per-cell timing statistics, MAD, paired ratios, geometric means and denominators.
It found no inconsistency. These are finite shared-host measurements, not a
prior-commit regression comparison or proof of universal Rust superiority.

| Profile | Timing samples | Correctness receipt | Geometric mean LLVM/baseline time |
| --- | ---: | --- | --- |
| Scalar native | 42: 7 groups × 3 kernels × 2 backends | 186 formula cases; reported 372 native calls | Rust: **0.9982020973399209** |
| Owned resource | 63: 7 × 3 × 3 | 196 formula cases; reported 784 native calls across four correctness backends, including C | Rust: **0.9530425287495398**; handwritten Rust: **0.7996616091737234** |
| Standalone HIA | 63: 7 × 3 × 3 | **588 actual observations**, 196 per measured backend, plus complete correctness-child stdout | Rust: **0.949731169577518**; handwritten Rust: **0.9478871761471579** |

For scalar native and owned, the report retains expected formula cases and
successful qualifier status but does not retain each actual native return value.
Owned additionally retains four observation digests. HIA preserves every actual
correctness observation and its child stdout. The evidence strengths are distinct.
C participates in owned correctness, not in its timed comparisons.

The three maximum observed relative MAD values were **0.004294010142668351**,
**0.0039647022293272**, and **0.0031673768740031337**, respectively. Fixed limits
were 1.2 per paired kernel ratio, 1.1 for the geometric mean, 0.05 for relative
MAD, and a 0.05-second minimum sample. Owned/HIA also require a 30-second maximum;
the scalar protocol does not declare that maximum.

| Profile | Complete process records | Retained telemetry/stream hashes checked |
| --- | ---: | --- |
| Scalar native | 0 complete stdout/stderr records | 42 completed process telemetry records; 252 raw PSI/cgroup hashes |
| Owned | 70: 69 exit 0, one expected negative exit 1 | 140 stdout/stderr hashes; 63 telemetry records with 378 raw hashes |
| HIA | 71: 70 exit 0, one expected negative exit 1 | 142 stdout/stderr hashes; scheduling fields embedded in 63 samples |

The owned and HIA missing-free controls each intentionally report 7 allocations,
0 frees, 7 live allocations, 1 refusal, and exit 1. Their positive controls each
report 7 allocations, 7 frees, 0 live allocations, 1 refusal, and exit 0. The
deliberate mutant leaks are rejected controls. HIA excluded no samples and
adjusted no acceptance thresholds. Telemetry does not isolate interference causes.

### Actual binary retention limits

All files actually supplied by this CI run are preserved. That does not recover
temporary build files the original qualifier never uploaded:

| Profile | Binary availability in this provider artifact |
| --- | --- |
| Scalar native | None of its six declared driver/library/object identities has a matching retained file. |
| Owned | Of nine main artifacts and three observer artifacts, only the handwritten Rust library has a same-hash copy in HIA's retained directory. The other 11 are absent. |
| HIA | All 16 retained files plus `artifact-retention.json` are present and verified against their recorded measured identities. |

The shared handwritten Rust library is 3,825,584 bytes with SHA-256
`123d8d5d9c20b23e9dc6f06ea43a52f018ef6690a5d9e20fd4257d17f40b9a77`.
This byte identity does not create a complete owned retention manifest.
The HIA retention manifest SHA-256 is
`3e5ad9a5ef2311f10975cf805997a9b34d0698b9c7208dac249add229404306e`.
No missing binary was rebuilt or substituted during archival.

## Source and complete selected-artifact retention

The full report's source snapshot and both HIA snapshots are identical: **922
files**, snapshot SHA-256
`ee23443f46646bf4bcc10e3b43950a8ab6283fdb4bd758ee13b3ef37084f4658`.
Every file was independently compared with the immutable 7ef Git blob.
`source-snapshot-git-audit.json` records that mapping; `source/` retains selected
exact workflow, qualifier and lock bytes. No current-checkout compiler hash was
substituted for an old receipt.

The source, HIA and three performance receipts agree on compiler SHA-256
`baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7`.
All 50 source gate log hashes and 43 evidence hashes/sizes match; all 44 HIA
linked identities and 30 log sizes match. `independent-review.json` records
separate data-only checks, their exact file identities and scope limits.

| Provider ZIP classification | Files | Raw bytes | Treatment |
| --- | ---: | ---: | --- |
| Added by this run | 1,306 | 180,828,498 | Every member byte retained |
| Byte-identical tracked artifacts | 89 | 4,277,480 | Git/source identities retained; not duplicated |
| Historical `evidence/` | 1,999 | 103,126,873 | Complete ZIP inventory retained; not recursively copied |

There were no changed tracked artifacts. The 1,306 selected files contain **176
ELF files totaling 110,401,880 bytes**. Eighteen principal original reports/logs
are additionally exposed under `originals/`, byte-identical to archive members.
The complete ZIP inventory has 3,394 regular members. File bytes and permission
bits are preserved; original filesystem timestamps are not retained.

The single XZ archive is **7,194,348 bytes**, SHA-256
`21543825194037369530e8945f34694aa4fd317aafa6de8f87e06435d077e27d`.
It was compressed once with preset 6, a 64 MiB dictionary and one thread, during
an explicitly coordinated slot with no root performance run. Its base64 is
**9,718,681 ASCII bytes**, split into 3,500,000, 3,500,000 and 2,718,681-byte parts.
All original archive parts remain unchanged after creation.

## Portable verification

From this appendix directory:

```sh
python3 verify_bundle.py
python3 verify_bundle.py --original-zip /path/to/12704884741.zip
```

The verifier checks sidecars, archive identities and bounded ordinary-file
membership, all original report links, named source skips, snapshots and selected
source bytes, performance statistics and available process/telemetry hashes,
HIA actual correctness records and retention, and each declared binary's actual
availability. The optional ZIP argument also rechecks the original provider
package and every retained member against it. It imports no project code,
extracts no files, runs no native program, and accesses no network.

The portable replay does not regenerate native observations or fetch Git objects.
The immutable Git comparisons and independent formula/schedule audit were
performed separately and are explicitly recorded. `verification.json` preserves
the successful portable data check including the original provider ZIP. Passing
archive checks preserve this failed CI attempt; they do not qualify all seven
project deliverables or close the report's open production blockers.
