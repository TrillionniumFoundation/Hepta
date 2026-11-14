# R8 post-reset R3: explicit input and runtime binding

## Current state

This directory is an authoring result. No binder, coherent input copy, oracle owner, project import, HIA generation, compilation, Native entry, or VM execution has run for this R3 package. The author used the host Python 3.12 only for JSON, AST, byte comparisons, and writing these new author files. It did not execute any restored R2 author script or the restored Python 3.14 interpreter.

The actual original R8 size/pack result is retained as an input. It is not semantic qualification. The original R5 six-case VM result remains five PASS and one cross-target-loans fuel FAIL. The two historical missing-original gaps in the original CAS manifest remain explicit.

## Fixed authorities and paths

| Authority | Exact path or identity |
|---|---|
| Complete original R2 author package | `/tmp/hia-r8-source-recovery-20261114-r1/frozen-author-r2` — 64 files, unchanged |
| Original R2 execution plan | Git `10b0e3c6b8cbdb877908c47a9302b2677fc361d0` |
| Restored source | `/tmp/hia-r8-source-recovery-20261114-r1/source` — 3,180 files, tree `4c62be4ed66ff107fa6f88c6131313a354868bd9` |
| Frozen content/mode source authority | `FROZEN-3180-SOURCE.json`, Git `1c4770702659539f148b0dc64610d4c34d6f04dc` |
| Root actual complete source readback | Git `9fd59fba1b84fd915964836ca9f634172bd1cba5` |
| Restored fixed input set | `/tmp/hia-r8-inputs-recovery-20261114-dda7` — 948 references, 944 distinct original paths |
| Root actual complete input readback | Git `62f30350fc0140d1347f28400ca8d8e887c0acae` |
| Restored runtime | `/tmp/hia-runtime-artifact-recovery-20261114-dda7/runtime-data` |
| Root actual stdlib-only startup result | Git `1e8bb057adf9f4cc72c656df3bc6a5d986973ae7` |
| New coherent input view, not created | `/dev/shm/hia-u32-r8-input-view-r3-dda7` |
| New original-oracle target, not created | `/dev/shm/hia-u32-r8-oracles-r3-dda7` |
| New oracle owner target, not created | `/dev/shm/hia-u32-r8-oracles-r3-dda7.owner` |
| New product evidence target, not created | `/dev/shm/hia-u32-r8-controls-r3-dda7` |

The restored executable and libpython have the original byte identities. Their paths and all current filesystem identities are new. The old virtual environment and site-packages were not recovered. The existing runtime startup observation is only stdlib readiness; it does not establish project imports, restored products, cold qualification, or whole Native execution. There is no new runtime probe in this package. The recorded unavailable `z3` and `pytest` modules must not be silently replaced, installed through an unreviewed route, or avoided by selecting a different interpreter. The separate static import review states its exact coverage.

## Three explicitly separate future stages

### 1. Metadata admission and 808-file input view

`prepare_input_view.py` consumes `PREPARATION-PLAN.json`. `PREPARATION-LAUNCH.json` is its exact future command descriptor; it is not an execution receipt.

The preparer does not import the project, run a subprocess, restore an oracle, or invoke a payload. It is itself a metadata Python process, launched only after Root authorization. Its `binary_executions: 0` counter denotes additional binaries or payloads launched by this preparer, not a claim that its own Python interpreter was never started. The authoring result remains zero restored-interpreter executions.

Admission fully checks:

- All declared author files and complete recovery/Root authority files, including their new seven-field stat records.
- All 3,180 current source files, complete pathset, original bytes/modes, new seven-field stats, and final stats.
- All 2,496 restored runtime files, complete pathset, bytes/modes, new seven-field stats, and final stats.
- All 948 original input references in the original order, with a fresh full read for each reference. Original role, phase, identity and duplicate-reference distinctions are preserved. Four duplicate references remain; they do not become four fabricated independent originals.

It then creates exactly 808 new regular files, totaling 132,337,387 logical bytes, under the new shm view. The 361 compact, 434 kernel, and 13 other non-oracle paths are mapped explicitly in the plan. The complete original-to-recovered-to-new-path relationship is recorded for every role. There are no hardlinks, symlinks, original-path writes, availability fallbacks, or source/runtime copies. Every new file has its required original input mode and a new independent inode. Before/after full input/source/runtime guards, copy journal, complete current view, and partial failure evidence are preserved.

The 136 already recovered observations are checked as immutable input authority during this stage but are not copied into the future oracle target. Their previous static restoration does not satisfy stage 2.

Before any copy, the preparer checks actual shm free space against the allocated size of both the 808-file view and the future 136-file restoration, plus the original 3 GiB product floor, 128 MiB reserve, and 8 MiB metadata allowance. The original oracle and product free-space guards remain intact and run again at their original boundaries.

### 2. Original 136-oracle restoration owner

`restore_oracles.py` is byte-identical to the frozen R2 file. `ORACLE-LAUNCH.json` specifies the new paths and still requires a real completed input-view preparation before authorization.

This stage is the original independent 180-second owner plus 3-second cleanup. It rereads the exact 27,221,867-byte compact archive, verifies the entire gzip/TAR stream, all 2,396 CAS objects totaling 1,658,896,740 bytes, and the original manifest. It writes only the original 136 selected observations, totaling 578,353,224 bytes, to the new oracle directory. The original absent-path checks are retained: `required[*].original_path` remains the historical missing original, not a new path or a fallback. The 360 other required files are explicitly rebound to the coherent view, with their original identities unchanged.

Original full source-before/source-after and binding guards, actual owner request/receipt/cleanup/ECHILD, and original `prepare_context` assertions are preserved. No static recovery report, author result, or fabricated owner result can replace this stage. `all_other_required_files_at_declared_rebound_paths: 360` replaces the obsolete metadata label saying those files remained at old paths; the complete original plan is recoverable by the recorded inverse.

### 3. Original retained controls

`run_controls.py`, `r8_common.py`, and `r8_private_reference.py` are byte-identical to frozen R2. `PRODUCT-LAUNCH.json` requires the actual original-oracle owner and a new Root product-slot authorization.

The original eight groups, their order, assertions, and expected counts remain:

| Group | Preserved work |
|---|---|
| public-R5-refusal | Original public component pin refuses the private R8 semantic component before its provider is called |
| native162 | Original ordered 162 full-frame comparisons, including original refusal cases |
| semantic-edge-vm | One actual Native entry and one same-input VM under original 10M fuel |
| semantic-remaining-vm | Five new VMs and reuse of this execution's actual same-image edge VM; six logical cases |
| kernel130 | Original 130 actual kernel executions and all original byte oracles |
| observer-build | Two original compile/pack calls for the test observer |
| pipeline7 | Original seven VMs and six actual kernel postreturn observations |
| tail2 | Original two last-byte fault VMs, two kernel observations, and four compile/pack calls |

No group, case, expected refusal, full buffer, canary, original error, or cleanup check is removed. Ordinary B3 remains the fixed 673,413-byte compiler. The private admission functions `_checked_components` and `execute_linux_file_roundtrip` remain complete exact original bytes. Public R5 component pins remain unchanged.

Every owner remains 180+3 seconds; each Native or compile deadline remains 20+3 seconds with 10 CPU seconds where originally specified. Original 1 MiB compilation/output/workspace capacities, 10M VM fuel, the 8,388,609-byte file extent, original VM heap limits and call-depth limits remain unchanged. The product entry still checks the actual output filesystem for at least 3 GiB free. There is no automatic retry, later-group continuation after a failed group, or inherited R8 semantic PASS.

## Exact source and plan differences

`R3-SOURCE-PROJECTION.json` and `review-diffs/` provide complete before/after pins and inverses.

- Four of the seven scripts have explicit old input-root constants rebound to the new coherent view. The other three scripts are byte-identical.
- The kernel130 script has one additional literal change: its full fixture REPORT SHA is updated because that fixture's sole changed field is `build.executable`, now under the new product output. No semantic image identity, ELF identity, expected result, or assertion structure changes. The whole script inversely reconstructs exact R2 bytes.
- All three support modules change only their top-level ROOT/SOURCE/compiler-path constants. Every function body is byte-identical.
- The common driver, original restoration helper, private wrapper and both private admission function bodies are complete byte-identical files/functions.
- `R3-PLAN-INVERSE.json` reconstructs the entire original R2 execution plan byte-for-byte. All 948 role identities/phases and all original group, order, budget, public pin and historical-result fields are exact.
- `R3-ORACLE-INVERSE.json` reconstructs the entire original oracle plan byte-for-byte. Its 496 identities, 136 restore order, all counts/limits/archive identities and original missing-history descriptions are exact.

Original R2 proof files retained in this directory are explicitly historical author records. They are not newly executed R3 qualification. `fixtures/REPORT.json` retains its historical `origin.stat`; that field is not claimed as a current filesystem identity. Current provenance is in `POST-RESET-PROVENANCE.json` and the new preparation records.

## Remaining gates

1. Complete Root review of this author package and the bounded static project-import analysis.
2. Explicit authorization and one actual 808-file preparation, with full new readback and all partial failures retained.
3. Explicit authorization and one actual original 136-oracle owner under 180+3.
4. Root readback of those real results, a fresh original 3 GiB gate, and separate authorization for the original eight product groups.

No future result or current qualification pin is filled in. A failed preparation or group must preserve its actual files and stop. It must not silently choose another directory, runtime, archive, source, or input set.
