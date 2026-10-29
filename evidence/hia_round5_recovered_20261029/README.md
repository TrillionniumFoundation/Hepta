# Recovered round5 CI evidence — 2026-10-29

This directory preserves surviving GitHub Actions evidence for Hepta source
`70179fcc54e2195f9966ca3f98428a6540d50a41`, tree
`13cc41cc64be27856119a942c166b8a9a690f32d`.
The evidence commit has that exact source commit as its sole parent and adds
only `evidence/hia_round5_recovered_20261029/`.

**The final source has 5 successful workflows and 17 successful jobs, including
14 actual C/C++ host jobs. This is recovered CI evidence, not a completed local
whole-repository qualification or closure of the six research goals.**

## Recovery boundary

Workspace maintenance cleared the previous round5 scratch evidence directories
on 2026-10-29. All old local-only component, full-qualification and supervisor
raw records in those directories were lost. They have **not** been restored.
The old local freeze receipts, collector snapshots and independent-review
files have not been reconstructed as originals from conversation summaries.
This package makes no claim that a complete local qualification passed.

The recovery fetched the original ZIP bytes still retained by GitHub, fresh
run/job/artifact API payloads, and connector-decoded job logs. Original ZIPs
match their GitHub artifact SHA256 digests. Generated recovery reviews are
new reviews, not restored copies of the old local reviews. See
`UNRECOVERED_LOCAL_EVIDENCE.json` and `CI_RECOVERY_HANDOFF.json` for this boundary.

No new workflow, rerun, project test, native execution, solver run or performance
experiment was launched by the recovery or packaging work. The original CI
executions retain their original timestamps, source identities and outcomes.

## Exact-source CI results and denominators

| Workflow | Original run | Jobs |
|---|---:|---:|
| Actual host ABI | [40792336767](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40792336767) | 7/7 success |
| Upstream C++ hosts | [40792336832](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40792336832) | 7/7 success |
| Migration push | [40792336898](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40792336898) | 1/1 success |
| Six outcomes | [40792343357](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40792343357) | 1/1 success |
| Verified optimization and native NDU | [40792343351](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40792343351) | 1/1 success |

`FINAL_STATUS.json` binds all 17 job IDs, source SHAs, conclusions, original
decoded-log hashes and API payload paths. Two old Windows failure logs are
retained separately, making 19 recovered job logs in total.

| Retained result | Denominator and observation |
|---|---|
| Verified regression | 595 test methods; 0 failures, 0 errors, 0 skips |
| Six-outcomes safety gate | 57 selected boundary tests; all passed |
| Six-outcomes regression | 52 test methods; 0 failures, 0 errors, 0 skips |
| Agent controls | 35 controls passed; **0 model requests** |
| Filecheck | `prepared_not_measured`; **0 performance samples** |
| Native NDU loop | 30 completed episodes; actual budgets and outputs passed |

The 595, 57 and 52 test denominators overlap and are **not added together**.
The 35 controls are not 35 model coding trials. Jobs, methods, controls, native
cases and optimization episodes are different denominators. These observations
do not establish Agent productivity, whole-language soundness, backend
refinement, general C/C++ migration, Rust performance superiority or a global
instruction optimum.

### Actual host and source bindings

The C/ABI and C++ matrices each cover seven actual profiles: Linux x86-64
GCC/Clang, Linux AArch64 GCC/Clang, macOS AArch64 Clang, and Windows x86-64
Clang/MSVC. These are two seven-job matrices, not fourteen architectures.

The recovery independently recomputed the compiler identity from the exact
141 Python Git blobs. It checked 894 distinct public source Git blobs across
the retained reports, including the verified regression's 357 bindings, the
NDU loop's 145 bindings, safety's 872 bindings and filecheck's 151 bindings.
Those sets overlap; their sizes are not added into a unique-source total.

For every C++ host, nlohmann/json versions 3.11.3 and 3.12.0 each retain 98
cases through the direct and compiled Hepta routes. The review checked every
retained-file hash, the actual executable bytes and ELF/PE/Mach-O architecture,
original stdout/stderr bytes against SHA256 and base64 receipts, parsed
observations, direct/Hepta result pairs, allocation deltas and exit status.
Wrong-code and incompatible-signature controls remain rejections. These are
finite library-reuse observations, not a proof of arbitrary foreign code.

Both Windows C++ reports contain seven ordinary, non-frozen example text files
whose reported bytes match a pure LF-to-CRLF conversion of the corresponding
Git blobs. Each difference is disclosed with both hashes. They are not counted
as exact Git-blob byte matches. All 141 compiler Python files and all six
frozen C++ upstream inputs match the original Git bytes; no original receipt
was normalized or rewritten.

The separate native ABI qualifier did not upload its temporary matrix
executables. Its original observations and executable digests remain available;
this recovery does not retroactively claim to retain those missing executable
bytes. Companion C-component and C++ archives retain their original artifacts.

### Original Windows failure and successful successor

Source `50521b1c9fe7fcbc6d895f95f891bf1ee371edc4` failed before actual upstream
C++ qualification in two Windows jobs. Both original ZIPs and logs remain
failure evidence:

| Compiler | Failed job | Original artifact |
|---|---:|---:|
| Clang | 123174950027 | 12860724231 |
| MSVC | 123174950232 | 12861327304 |

Step 7, **Check C++ host identity and evidence refusal contracts**, rejected
`E_CPP_UPGRADE_INPUT: upstream header content differs`. Both reports retain
`setup_failed` and `actual_reported_host_executed: false`; the actual execution
step was skipped. They are not relabelled as successful native executions.

The successor source commit 70179fcc adds the one-line Git attribute
`tests/fixtures/cpp_upgrade/** -text` to preserve the pinned upstream bytes on
Windows. It retains strict hash admission. Its successful Windows Clang/MSVC
reports bind the actual final-source executables and original process streams,
including both upstream versions. The old local checkout-reproduction raw
files are among the lost local evidence and are not represented as recovered.

### NDU outcome remains negative

The retained CI loop reports 30 completed episodes with correct outputs and
budgets. Both `ndu_descriptive_cost_lower_than_light` and
`ndu_descriptive_cost_lower_than_selected_fixed` remain **false**.
`statistical_superiority_established`, `global_optimality_claim` and
`safety_from_ndu_claim` also remain **false**. The original cost records and
their separate controller/build/evaluation accounting remain in the selected
`ndu-loop/RESULT.json` and episode reports.

This CI loop is not the historical preregistered exact-request reuse study.
No historical negative study was rerun or relabelled, and this recovery makes
no incremental NDU benefit or performance claim.

## Public archive and private exclusions

The package contains **368 unchanged payload files / 61,024,885 bytes**:
the 366-file public recovery allowlist plus its original manifest and freeze
record. It includes **17 original public CI ZIPs**, whose member inventories
describe **1,745 files**. Nested ZIP members are not additional test coverage.

The verified-optimization original ZIP, artifact `12862807176`, is excluded:
it contains four private NDU bridge executables. Its 4,693,108-byte original
archive has SHA256
`fec8587e21f27f3d658fa1d17ba54cf5b5dcd06701c1e0f231ec01e252cbeec3`.
Only 155 explicitly selected original reports and logs, the complete member
index, source/build identities and selection map are included publicly.
Private source code, private bridge binaries and the quarantined original ZIP
are absent from this package. Original report bytes and absolute process paths
remain unchanged as provenance.

The compressed outer archive is **37,142,188 bytes**, split into **6 parts**.
Its joined SHA256 is:

```text
3829e4df680ef2d5f58fcec6e01a1c84d385b64f772f0948276d81d6a4eb92c6
```

`RAW-INDEX.json` binds every payload and optional ZIP expansion member.
`ARCHIVE.json` binds that index, each part, the joined archive and source/count
identities. `SHA256SUMS` covers the directly published files and parts.

## Verify or restore without executing evidence

From this directory:

```sh
python3 RESTORE.py --verify-only
```

To restore into a new directory and optionally reconstruct the public CI ZIP
extraction trees:

```sh
python3 RESTORE.py --output /absolute/new/hepta-recovered-ci --expand-ci
```

The reader refuses an existing output, path traversal, symlinks, nonregular
tar members, duplicate/unexpected members, and hash, length, source or count
mismatches. It verifies the complete XZ checksum. It does not build, load or
execute any archived program. Optional CI expansion verifies each indexed ZIP
member before accepting its identity.

`VERIFY-ONLY.json` records the completed full outer-archive check. The packager
also read and hashed all 1,745 public ZIP members. The reader algorithm was
reused from source `3cfe761f0fa455679d0203f309c5adb5197a89a3`; only its docstring
and output schema identify this recovery. `RESTORE-PROVENANCE.json` binds both
reader versions. The older 315 MB evidence archive was not downloaded and is
not a substitute for the lost round5 local evidence.

The six research workstreams remain subject to their stated closure
conditions. This immutable evidence increment preserves what can actually be
checked after workspace loss, including failures and negative optimization
results, without claiming recovered local qualification that does not exist.
