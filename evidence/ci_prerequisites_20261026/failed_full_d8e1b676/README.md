# d8e full CI: 49/50 source gates and 15/15 HIA gates

This appendix preserves the failed full CI job for source commit `d8e1b676665093c416a3484c3d7d7e0ceffe3207` and independently reviews its retained results. The overall job remains **failure**: `strict_namespace_execution` is the one failing source gate. Both unit runs pass with **2,108 tests, zero skips, zero errors and zero failures**. All three completed performance profiles pass their original, unchanged thresholds.

- [Provider run 40438827706](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40438827706), job `121973952657`.
- Exact tested Git tree: `ad5dcb9118c392ef35cc8621916580eed474621c`.
- Compiler SHA-256: `baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7`.
- Source snapshot: **923 files**, SHA-256 `0aad7ec72ebeae72eae1d76099c959c8e1ce109526204b5086ab3e8296c08601`; the full-source snapshot and both HIA snapshots are identical.
- This is the d8e run. Earlier failed or inconclusive runs remain separate evidence. The archive does not establish completion of all seven development stages.

## Actual gate and unit results

| Run | Gates passed / completed | Actual unit tests | Skips | Errors / failures | Unit terminal seconds |
| --- | ---: | ---: | ---: | ---: | ---: |
| Full source | 49 / 50 | 2,108 | 0 | 0 / 0 | 560.403 |
| HIA | 15 / 15 | 2,108 | 0 | 0 / 0 | 562.808 |

The full-source driver records 562.545 seconds for its unit gate; HIA records 563.2829040710001 seconds. These enclosing gate durations are distinct from the terminal unittest durations above. `review.json` checks the terminal counts against the collector's accepted counts. Expected negative-test diagnostics in the quiet HIA stderr stream do not change its terminal `OK` outcome.

The failed namespace report contains `PermissionError`, errno 13, while inspecting a host `/proc/1/root/.../parent_oracle_canary` path. `startup` is `passed`; the other nine check records are `not_run`. Inspection of the exact frozen `sandbox_qualification.py` identifies a host-path metadata access in the boundary observation. The nine `not_run` values are retained report states: they do not independently prove that no boundary probe subprocess had already executed before report construction failed. This appendix neither repairs nor re-executes the candidate. The later host-observation repair has its own source identity and CI evidence.

All **50 source gate logs**, **43 source evidence files**, and **44 HIA evidence/log links** match their recorded SHA-256 values; 30 HIA log byte counts are also checked. Source evidence freshness flags are true. Provider steps 1–12 and artifact upload succeed; the source qualification step fails and the HIA step succeeds, consistently with the retained aggregate reports.

## Subsequent composed-driver defect

A follow-up audit during archival identified a separate limitation of the historical `cpp_composed_to_llvm` pass. The frozen `examples/cpp/composed_migration/harness.c` declares `uint64_t composed_case(...)` only in its C++ branch. Its C branch calls the function without that prototype. The original `cpp_composed_llvm.json` contains **nine** GCC link records with `implicit declaration of function composed_case` warnings and return code 0: three variants, each with a positive build and two negative controls. Their recorded flags include `-std=c11` without rejecting that diagnostic.

`posthoc-driver-finding.json` preserves those exact process records and the frozen harness text, linked to the original report and Git source snapshot. Implicit-int return handling can lose high bits of a 64-bit return. The historical collector's `passed` status is preserved as a historical observation; it does **not** establish high-u64 ABI fidelity or qualification of a repaired driver. The repair and its extended return-value tests require a new candidate and new full qualification. The performance tables below concern their separately identified drivers and protocols.

## Independent performance recomputation

`performance_audit.py` uses retained integers and independent formulas. It does not import production evaluators or execute any retained binary. `report_audit.py` reconstructs each protocol from the retained exact source using restricted AST literal handling. All samples stay in their original sequence: 42 scalar, 63 owned, and 63 HIA, **168 total**.

Every cell has seven samples. Relative MAD is `median(abs(x - median(x))) / median(x)`. Each kernel ratio is the median of its seven paired `LLVM elapsed / baseline elapsed` ratios; the profile ratio is the geometric mean of the three kernel ratios. The fixed limits are relative MAD ≤ 0.05, each kernel ratio ≤ 1.20, and each geometric mean ≤ 1.10. Samples must be at least 50 ms; owned/HIA samples also have the fixed 30-second upper limit. Threshold decisions use exact rational comparisons, including cubing the geometric bound. Floating presentation is compared with relative tolerance `1e-14` and absolute tolerance `1e-15`.

| Profile | Frozen protocol | Samples | LLVM / generated Rust geometric ratio | LLVM / handwritten Rust geometric ratio | Maximum relative MAD | Result |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| scalar | `hepta.llvm-native-scalar32-perf.v2` | 42 | 1.003017613786414 | — | 0.003688021048344245 | passed |
| owned | `hepta.llvm-owned-bytes-perf.v1` | 63 | 0.9512601598643909 | 0.7855336480984962 | 0.002034244909442441 | passed |
| hia | `hepta.hia.program.perf.v3` | 63 | 0.9504586575880595 | 0.947280112013114 | 0.004131961727089743 | passed |

The scalar profile alternates backend order using group plus rotated kernel position. The source-owned profile rotates backends using group plus rotated position, with reversal on odd groups. HIA uses the original kernel index for the rotation; its order is checked separately. No clipping, replacement samples, native reruns, acceptance changes, or selection of a more favorable run occurs in this review. The reports contain no measurement-quality or performance-threshold failures.

### Every kernel's MAD and paired ratios

Relative MAD is shown as a fraction, so `0.005` means 0.5%. Every paired ratio below divides LLVM time by that row's baseline time. All seven original sample values, all seven paired ratios, and their exact fractions are in `review.json`.

| Profile / kernel | Rust relative MAD | LLVM relative MAD | Handwritten Rust relative MAD | Paired LLVM / Rust | Paired LLVM / handwritten Rust |
| --- | ---: | ---: | ---: | ---: | ---: |
| scalar / `signed_walk` | 0.000101591855575 | 0.00013737226031 | — | 1.00008194805 | — |
| scalar / `unsigned_walk` | 0.000844992664293 | 7.00149292735e-05 | — | 0.992719406406 | — |
| scalar / `branch_accumulate` | 0.00368802104834 | 0.00112821836762 | — | 1.01639747841 | — |
| owned / `full_lifecycle` | 0.000436562264453 | 0.000813652556317 | 0.000408043437819 | 0.999292355578 | 0.998981761394 |
| owned / `constructor_error` | 0.000608708000084 | 0.000282084124758 | 0.00203424490944 | 0.862357005527 | 0.862072628184 |
| owned / `two_stage` | 0.000807997887303 | 0.000989149410445 | 0.000882987632734 | 0.998891376446 | 0.562850378782 |
| hia / `full_lifecycle` | 0.000803240708649 | 0.00144139202653 | 0.00107419794316 | 0.999474568336 | 0.999406033231 |
| hia / `constructor_error` | 0.00187923215802 | 0.000831313811802 | 0.00413196172709 | 0.860005255106 | 0.85168820122 |
| hia / `two_stage` | 0.0023987640862 | 0.000456775999499 | 0.00098056195468 | 0.998911101889 | 0.998648515321 |

### Correctness and observation scope

The scalar report retains 186 formula cases and reports 372 actual native calls. Source-owned retains 196 formula cases/digests and reports 784 calls across Rust, LLVM, handwritten Rust and C; C is a correctness-only baseline. These source reports do not retain every individual actual ABI output. The independent reviewer recomputes the formula domains without promoting a report assertion into a retained per-call output.

HIA retains **588 actual outputs** for 196 cases across its three backends. The reviewer compares them with independent formulas and the retained child stdout, and checks the rolling checksum for every owned/HIA timing row. The owned and HIA cleanup controls each record `allocations=7, frees=7, live=0, refusals=1` in the positive run. Their compiled missing-free controls record `7,0,7,1` and exit 1. These are untimed LLVM resource controls; they do not establish identical Rust allocator traces or the resource trace of each uninstrumented timed binary.

Source scalar and owned each retain one external process-observation record per sample, 42 and 63 respectively. Every before/after raw counter hash, parsed counter set, delta, status and sample identity is rechecked. For this run, all four observation sources are available for all samples, with no reset or unavailable state; the error-count maps are empty because their underlying records contain no errors. The code keeps missing/reset deltas as null and tests that malformed raw input cannot be relabelled as a permission failure.

| Source observation | Scalar total | Owned total |
| --- | ---: | ---: |
| Child involuntary context switches | 3,693 | 10,030 |
| Child voluntary context switches | 42 | 63 |
| Child minor page faults | 3,265 | 5,010 |
| Child major page faults | 0 | 0 |
| Host CPU pressure `some.total_us` delta | 120,099 | 337,544 |

HIA's separate in-driver observation has 63 records, 11,796 involuntary context switches, and zero recorded voluntary switches and page faults. Its CPU/wall ratio ranges from 0.9977149377961304 to 0.998593210758537, with median 0.9983505463678655. That CPU interval brackets the wall interval and has different scope from the source external wrapper. Neither fixed affinity nor these counters proves an exclusive host or establishes a causal explanation for timing differences. Informational observations neither adjust elapsed time nor filter samples. Missing host configuration fields such as `cgroup_cpu_max` remain null.

Owned supplies 70 complete process records (69 exit 0 and one expected exit 1); HIA supplies 71 (70 exit 0 and one expected exit 1). Their command, return code, stdout/stderr and hashes are checked. Scalar's report does not retain the same complete execution records; its telemetry hash records are kept distinct from full process streams.

## Retained files and exact source binding

The downloaded provider ZIP is **76,480,359 bytes**, SHA-256 `b193dd560a4edc3db013c4ce85865d49cab1d27348e92ebe2f3818932cce4a7b`, matching the provider's artifact metadata. Its **3,394 file entries** split as follows:

| Classification against exact d8e Git blobs | Files | Archive treatment |
| --- | ---: | --- |
| New artifact files | 1,306 | All bytes retained |
| Changed tracked files | 0 | None observed |
| Byte-identical tracked artifact files | 89 | Deduplicated with identities |
| Byte-identical historical evidence files | 1,999 | Deduplicated with identities |

Every ZIP file was read and hashed, including historical evidence. No whole directory was discarded solely by name. The new files total **180,829,178 bytes**, including **176 ELF files / 110,401,880 bytes**. This is the uploaded-file denominator, not an assertion that the provider uploaded every file from its remote filesystem. One tracked historical metadata file is absent from the provider ZIP and is not counted as a new or missing execution artifact.

`zip-source-tree-proof.json` holds the exact commit object and 168 Git directory objects covering the full source `artifacts/` and `evidence/` subtrees. Offline verification follows every ZIP path through those objects, establishing the existing blob ID or path absence for each deduplication/addition decision. `source-tree-proof.json` separately binds all 923 source paths to the tested commit through 111 directory objects. Every source SHA-256 was compared with its immutable Git blob at capture. Twenty selected source files in the main source index are retained byte-for-byte and can be checked offline against both Git SHA-1 and the snapshot SHA-256. The full 923 source-file contents are not duplicated in this appendix.

HIA's retention manifest supplies **16 exact files** (plus its manifest), including the driver and all three measured libraries; original/copy hashes, byte sizes and recorded paths match. Searching the entire provider ZIP by SHA-256 and byte size finds none of the scalar report's six recorded build artifacts. Of the source-owned report's twelve measured/resource artifact identities, eleven are absent; its handwritten Rust library has an exact byte match in HIA's retained files. This establishes byte availability for that one identity, without inferring its original filesystem path or execution history. The missing binaries remain explicit limits on subsequent disassembly or re-execution from this appendix.

The 1,306 new files were packed once into normalized USTAR and compressed with single-thread XZ preset 6 and a 64 MiB dictionary. The packed archive is **7,185,772 bytes**; its base64 representation is **9,581,033 ASCII bytes**, split into three parts of 3,500,000, 3,500,000 and 2,581,033 bytes. ZIP permission bits are retained as observed; tar owners and timestamps are normalized. No claim is made that upload ZIP permissions reproduce the runner's original filesystem metadata.

The complete provider-decoded job log is retained as `job-121973952657.log`: 147,241 UTF-8 bytes (147,153 decoded characters, 1,407 lines), SHA-256 `1aafaf8c1b82d0bac340ad6ade6b59607d6c31022c0b15bd633d1bd47037bc93`. It is decoded provider text re-encoded without newline translation; original HTTP transport bytes are not separately claimed. `zip-identity.json` and `zip-inventory.json` preserve the full original ZIP identity and every file's classification, size, SHA-256 and Git blob ID. The complete original ZIP was downloaded and verified; the Git appendix stores its new bytes with verified historical deduplication.

## Offline reproduction

From this directory, using Python 3.11 or later:

```sh
PYTHONDONTWRITEBYTECODE=1 python verify_bundle.py
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v test_audit test_archive
```

To additionally recheck the separately downloaded complete provider ZIP:

```sh
PYTHONDONTWRITEBYTECODE=1 python verify_bundle.py --original-zip /absolute/path/to/hepta-ci-d8e-evidence-12706895185.zip
```

The verifier checks every sidecar and archive part, rejects unsafe paths and special files, bounds decompression, verifies every retained member, checks Git-object proofs and all linked reports/logs, and independently recomputes the metrics. It uses no network, compiler, emulator, native execution, production qualifier, or performance timer. The 20 data-only tests cover actual retained outcomes and deliberate corruptions of checksums, source identity, sample order, binary identity, thresholds, unavailable observations, process capture, archive members and Git classifications.

`verification.json` records offline verification; `verification-original-zip.json` records the additional complete-ZIP comparison. `verification-tests.log` retains the terminal 20/20 zero-skip result. Successful archive verification means its originals and derived review agree. The recorded full CI qualification remains failed, and language-wide safety, universal performance superiority, physical hardware qualification and whole-project blocker closure are outside these results.
