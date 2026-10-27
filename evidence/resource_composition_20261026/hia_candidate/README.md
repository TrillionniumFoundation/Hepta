# Frozen composition candidate: independent HIA evidence review

The completed HIA attempt passes **14 of 15 gates**. Its only failed gate is
`standalone_performance`, with all **63 original samples** retained and
`status = measurement_inconclusive`. Four implementation/kernel groups exceed
the frozen 5% relative-MAD quality limit. Neither this archive nor its successful
integrity verification converts that result into a qualification pass.

An earlier attempt is also retained. It ended without a terminal qualification
report; its exit code and completed unit-test count are **unknown**. Its plan
and one `running` driver line are not completed execution evidence.

## Source and attempt identity

| Identity | Value |
| --- | --- |
| Tested source commit | `3a424e427b378400802c9e3c2fef558c0a352756` |
| Compiler tree SHA-256 | `baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7` |
| Source snapshot SHA-256, before and after | `339ed18eafd41c41e6b1e84f18bec100db5122cf60983c948aa721f54249c10b` |
| Source files, before and after | 920 / 920, identical path-to-hash maps |
| Attempt 2 qualification SHA-256 | `434d1139f753ca54b12b2e49450cdf58b387fb88d2781df23dab7dbf59d4b602` |
| Attempt 2 performance SHA-256 | `34d41fff6c99bc68f402f1ee81535e74f8779462082ed0c3f719428f21bb5e89` |
| HIA performance protocol | `hepta.hia.program.perf.v3` |
| Canonical protocol SHA-256 | `df1df380d1ddc84836093ac0e83824d907b9341d31b6e8c00ad230089a6f9891` |

The source hash is recomputed from the canonical sorted 920-entry file map in
the original qualification. This folder references the sibling
[`source_candidate`](../source_candidate/README.md) bundle for the actual 920
source files and its offline commit/tree/blob proof. It does not duplicate that
source archive. Run that sibling verifier as well to verify source bytes against
the Git commit; this folder verifies the identical recorded map, input hashes,
receipts, retained artifacts and arithmetic.

The source is the frozen `3a424e4` candidate. These are new execution records for
that candidate, not substituted reports from `bdb8690` or a later CI repair.

### Attempt 1: incomplete, unqualified

The original `composition-hia-20261026-run1` directory contains two files:
`plan.json` and `interruption-observation.json`, totaling 7,898 bytes. The
49-byte driver contains only `{"gate": "unit_regression", "status": "running"}`.
The observation records that tool session 92867 could no longer be found and
no matching qualifier/unit process was found. The underlying interruption cause
is unknown. There is no final report, completed gate log, or retained performance
sample. The observation correctly leaves both child exit code and completed
test count null. The archive preserves these facts without inferring a pass,
a completed zero-test run, or a performance result.

### Attempt 2: completed under a durable supervisor

The complete run started at `2026-10-27T02:08:27Z` and its qualification report
finished at `02:22:38Z`. The supervisor recorded completion at
`02:22:39.408132+00:00`, worker PID 475301, child PID 475311, and child exit
code **1**. The supervisor, exact specification, journal, driver, and empty
supervisor log are preserved byte for byte. The driver has all 15 running/terminal
pairs and its final 14/15 summary; the verifier binds these rows to the original
qualification and checks all 30 gate stdout/stderr files.

Restarting after attempt 1's missing terminal evidence is distinct from selecting
among performance runs: attempt 1 retained no performance samples. Attempt 2's
failed performance evidence is retained in full. No benchmark was repeated by
this review or archive operation.

## Complete gate outcomes

| Gate | Outcome | Original evidence in attempt 2 |
| --- | --- | --- |
| `unit_regression` | Passed: 2093 tests, 0 skipped, 0 failures, 0 errors | `unit_regression.stdout.log`, `unit_regression.stderr.log` |
| `standalone_native` | Passed | `native.json` |
| `standalone_resources` | Passed | `resources.json` |
| `composite_resources` | Passed | `composite/qualification.json` |
| `composite_bulk_targets` | Passed | `composite-bulk/qualification.json` |
| `source_migration` | Passed | `migration/qualification.json` |
| `cpp_template_migration` | Passed | `cpp-templates/qualification.json` |
| `c_configuration_matrix` | Passed | `c-matrix/qualification.json` |
| `cpp_configuration_matrix` | Passed | `cpp-matrix/qualification.json` |
| `selected_core_formal` | Passed | `selected-formal/qualification.json` |
| `standalone_aarch64_qemu` | Passed | `aarch64.json` |
| `legacy_executable_core` | Passed | `legacy-core.json` |
| `legacy_hosted_composition` | Passed | `hosted-composition.json` |
| `legacy_cortex_m4_qemu` | Passed | `board.json` |
| `standalone_performance` | Failed: measurement inconclusive | `performance.json` |

The actual unit stderr terminates with `Ran 2093 tests in 682.135s` and `OK`.
The outer collector duration is 683.2392015180012 seconds. These are different
measurement boundaries, not conflicting test counts. The preceding stderr
messages from intentional invalid-input controls do not replace the terminal
unittest result. Both the 2093 denominator and zero-skip requirement are checked.

The producer payloads retain their existing success conventions. In
particular, `board.json` uses `status = passed` without an `ok` field; the archive
does not invent that field. The exact original qualification bytes are pinned,
and each evidence file's recorded hash and reported outcome are checked.

## Independent performance recomputation

[`audit.py`](audit.py) reconstructs the frozen HIA v3 order, uses independent
integer/byte formulas for the 588 recorded correctness calls, recomputes the
three timed rolling checksums as integer arithmetic, and checks every native
sample's nine stdout fields, command, driver hash and library hash. It imports
neither Hepta nor the production `evaluate_samples` function. It does not execute
any retained source or binary. [`review.json`](review.json) contains all 63 raw
sample associations, all 63 durations, exact rational MADs and paired ratios,
and the independently derived result.

The seven groups rotate kernels. Backend rotation uses **group plus the kernel's
original index**, then reverses on odd groups. This HIA v3 rule is distinct from
the historical source-owned rule that uses the kernel's current rotated position.
The verifier rejects substituting that other schedule even if sample indices are
renumbered consistently.

Every sample uses size 4093 and 8192 warmup calls. Timed calls per sample are
1,048,576 for `full_lifecycle`, 8,388,608 for `constructor_error`, and 1,048,576
for `two_stage`. The frozen sample duration interval is 50 ms to 30 s. Relative
MAD must be at most 0.05; each median paired LLVM/baseline ratio must be at most
1.20; the geometric mean across the three kernel medians must be at most 1.10
for **each** Rust baseline. No sample is clipped, excluded, calibrated away,
retried, or replaced, and no threshold is adjusted.

### Every kernel/implementation quality result

MAD is the median absolute deviation from the seven-sample median, divided by
that median. All durations meet the frozen duration bounds. Four relative-MAD
values fail:

| Kernel | Implementation | Median ns | MAD ns | Relative MAD | Quality |
| --- | --- | ---: | ---: | ---: | --- |
| `full_lifecycle` | Same-source Rust | 1758293813 | 92802331 | 0.052779763150995064 | **Fail** |
| `full_lifecycle` | Independent HIA LLVM | 1727913761 | 84473651 | 0.048887654526874276 | Pass |
| `full_lifecycle` | Handwritten safe Rust | 1791657095 | 146859168 | 0.08196834562251992 | **Fail** |
| `constructor_error` | Same-source Rust | 202903412 | 6483341 | 0.031952843651539976 | Pass |
| `constructor_error` | Independent HIA LLVM | 174435057 | 8660171 | 0.04964696402742025 | Pass |
| `constructor_error` | Handwritten safe Rust | 202868320 | 8642174 | 0.042599919001645996 | Pass |
| `two_stage` | Same-source Rust | 3449426584 | 131910424 | 0.038241261493101544 | Pass |
| `two_stage` | Independent HIA LLVM | 2965931221 | 187093471 | 0.06308085287861771 | **Fail** |
| `two_stage` | Handwritten safe Rust | 3096534356 | 233579613 | 0.0754325921000697 | **Fail** |

### Every paired ratio

Values are LLVM elapsed time divided by the corresponding baseline elapsed time
in the same group. Display is rounded here; the JSON preserves full floats and
exact rational numerator/denominator values.

| Kernel / baseline | Group 0 | Group 1 | Group 2 | Group 3 | Group 4 | Group 5 | Group 6 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `full_lifecycle` / Rust | 0.782228596 | 1.189618858 | 0.776830710 | 1.071390534 | 0.986759841 | 0.965115069 | 1.014630296 |
| `full_lifecycle` / handwritten | 1.051679057 | 1.055129483 | 0.989761330 | 0.850415590 | 0.917273799 | 1.025447287 | 1.016316795 |
| `constructor_error` / Rust | 0.963066975 | 1.283343601 | 0.912515864 | 1.161130784 | 0.843006834 | 0.800779946 | 0.842515052 |
| `constructor_error` / handwritten | 0.672498467 | 1.008006158 | 0.896602696 | 0.874963701 | 0.861399241 | 0.817670354 | 0.853514779 |
| `two_stage` / Rust | 0.918264835 | 0.958799854 | 0.820965222 | 0.923203143 | 0.874781812 | 0.971129604 | 0.870294856 |
| `two_stage` / handwritten | 1.027143029 | 0.853184213 | 0.974046698 | 0.946255869 | 1.086849159 | 0.957866468 | 0.897402525 |

| Kernel | Median LLVM / same-source Rust | Median LLVM / handwritten Rust |
| --- | ---: | ---: |
| `full_lifecycle` | 0.9867598410209101 | 1.0163167953279866 |
| `constructor_error` | 0.9125158638739898 | 0.8613992412378837 |
| `two_stage` | 0.9182648353529347 | 0.9578664680973618 |
| Geometric mean across kernel medians | **0.9385842906691223** | **0.9430025184325354** |

These ratio thresholds have no failures. The four quality failures still make
the performance gate inconclusive. A single group's ratio exceeding 1.20 is not
the protocol's kernel failure condition; that threshold applies to the median
of seven paired ratios. Threshold decisions in the independent review use exact
rationals, including comparing the product of three medians with `1.10³`.
Geometric-mean display values are compared with the recorded float using relative
tolerance `1e-14` and absolute tolerance `1e-15`.

### Native observations and their limits

All 63 native stdout records retain process CPU time, context-switch counts,
page-fault counts, clock resolution and process peak RSS alongside elapsed time
and checksum. Every observation is matched to that sample's original stdout
hash and actual retained driver/library identity. CPU and counter fields are
required integers; missing or boolean values cannot be converted into measured
zeros. Real zero page-fault counts remain zero.

The independently recomputed CPU/wall ratios are minimum
`0.9853008315242971`, median `0.9955418165132804`, maximum
`0.9975071195282081`. Totals are 11,105 involuntary context switches, 4 voluntary
context switches, 4 minor page faults and 0 major page faults. There are zero
sample exclusions and no acceptance adjustment.

The native CPU interval brackets the wall interval; the resource-usage samples
also bracket that interval. They do not isolate overhead or prove why variance
occurred. The report explicitly records a shared host and
`exclusive_cpu_ownership = false`. CPU affinity is not exclusive access. No
causal attribution to another task or claim of exclusive host use is made.

This HIA data does not contain the newly added source-qualifier process-observer
schema. Source scalar/owned PSI availability counters must not be imputed to
this HIA report, and HIA observations must not be treated as a new source
performance qualification.

## Actual native artifact retention

The archive retains all 16 files copied by this HIA performance attempt plus its
original `artifact-retention.json`: three measured shared libraries, the actual
driver and driver object/source, generated Rust, handwritten Rust, HIA and LLVM
inputs, observer source, positive/negative observer executables and their
objects, and the missing-free LLVM mutation. Each original-to-retained path
mapping, byte count and SHA-256 is checked against both the retained bytes and
the premeasurement/observation identities recorded in the performance report.
No rebuild substitutes for a measured binary.

The positive untimed LLVM observer records 7 allocations, 7 frees, 0 live
allocations and 1 allocation refusal. The actual compiled missing-free negative
records 7 allocations, 0 frees, 7 live allocations and 1 refusal, exiting 1 as
expected. Its return code, stdout hash and actual retained binary are bound.
This is an untimed LLVM cleanup/refusal control. It does not compare allocator
traces of the timed libraries or the Rust baselines.

## Protocol comparison with the preserved parent

[`protocol-review.json`](protocol-review.json) records a read-only Git-object/AST
comparison against `bdb8690317e96e1cd4a6f140e96376faa9dba522`.
The entire HIA unified qualifier, HIA performance qualifier, HIA benchmark source
and HIA native driver are byte-identical between that parent and tested `3a`.
The shared owned protocol, workload constants, oracle/checksum functions,
sample evaluator, historical schedule, execution helper and driver commands
are also unchanged. The entire shared source-owned qualifier file is not
claimed unchanged: source-observation additions elsewhere in it are distinct.
The expanded HIA v3 protocol is identical and matches its pinned canonical hash.

The offline bundle verifier checks the preserved comparison's source-file hashes
against the 920-file map and checks the actual report's canonical protocol pin.
It does not rerun a Git history comparison or execute the production evaluator.

## Archive completeness and verification

The archive contains **all extant regular files** from both requested output
directories and six external runner files, checked unchanged during capture:

| Namespace | Files | Bytes |
| --- | ---: | ---: |
| `attempt1/` | 2 | 7898 |
| `attempt2/` | 721 | 15123433 |
| `runner/` | 6 | 10841 |
| Total | **729** | **15142172** |

There are no symlinks or special files in the captured directories. Source and
native artifacts present within them are included. This is not a complete
copy of cleaned temporary build workspaces, installed toolchains, or the host
environment. Missing temporary files are not reconstructed. The full 920-file
source bundle remains in the sibling archive described above.

The regular-file USTAR container preserves member bytes and file modes; tar
user/group/time metadata is normalized to zero. One authorized compression
after HIA run 2 completion uses xz preset 6 with a 64 MiB dictionary. Its
15,656,960 tar bytes compress to 1,136,280 bytes. The single base64 file is
1,515,041 ASCII bytes including its newline, below the 3,500,000-byte part limit.
Part, compressed-stream, tar-container and individual-member hashes are all in
[`run-artifacts.manifest.json`](run-artifacts.manifest.json).

Run from the repository root with Python's standard library:

```sh
PYTHONDONTWRITEBYTECODE=1 python evidence/resource_composition_20261026/hia_candidate/verify_bundle.py
PYTHONDONTWRITEBYTECODE=1 python evidence/resource_composition_20261026/hia_candidate/test_verify_bundle.py
```

The verifier decodes the bounded archive in memory. It checks all 729 members,
rejects traversal, symlink/special members, duplicate keys/paths, changed bytes,
extra archive streams, oversized input/expansion and incomplete inventories.
It extracts no file and runs no archived source, compiler, native program,
emulator, production qualifier, or network request. Its `ok = true` means the
retained failed/interrupted evidence is consistent; it separately emits
`qualification_passed = false`.

The 19 small data tests include real retained-data recomputation and negative
controls for changed scheduling, removed samples, erased quality failures,
relaxed thresholds, forged paired statistics, missing/misbound observations,
changed native bytes, altered negative-control exit, an invented attempt-1 unit
count, changed terminal unit counts, substituted reports and unsafe containers.
The initial test execution is preserved in `verification-tests.log`.

`development/` preserves an initial archive-script failure before compression:
the initial inventory used `Path` component ordering while its recheck used
lexicographic relative strings. Both listed the same 721 unique attempt-2 files.
The correction canonicalizes both lists, then accepts earlier derived outputs
only if byte-identical. It does not rerun qualifications or replace results.
The original script/failure record, corrected script and successful capture log
are retained. There was exactly one compression of the complete run archive.

## Qualification scope

This evidence covers the finite HIA programs, migration cases, formal kernel,
target/emulator cases and workloads named in the original 15-gate plan. It does
not extend source-language local-view profiles, the new source task/I/O runtime,
or composed C++ source profiles to independent HIA or another versioned profile.
Passing unit tests does not itself extend HIA's admitted language or backend.

The original `full_six_deliverables_complete` and
`full_seven_deliverables_complete` remain false. The failed performance gate
prevents scoped HIA qualification. Neither source-byte integrity, formulas,
finite negative controls nor consistency of locally retained execution records
authenticates an arbitrary hostile producer or proves whole-language soundness,
universal Rust performance superiority, physical-device qualification, broad
C++ compatibility, agent productivity, or closure of every project blocker.
