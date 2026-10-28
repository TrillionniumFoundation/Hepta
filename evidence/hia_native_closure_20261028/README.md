# Native closure continuation evidence

Frozen source: `581c55cc2f14af38a7486e125d5c33496ca95f0a`. Frozen tree: `0a02e3f958b787faef6df5d4bc8860793db95f4f`.
Draft [PR #333](https://github.com/TrillionniumFoundation/Hepta/pull/333) is stacked on #326.
The later evidence-only delivery commit does not replace the tested source identity.

## Actual results

- 54 Rust tests and 310 targeted Python tests passed, with zero skips. Python groups: 149 Core/NDU/lifecycle, 68 independent Rust, 93 migration.
- Repository discovery found 2,643 tests. This was not a full repository run or the full 35-gate qualification.
- Independent Rust/Python execution compared 1,460 complete resource ledgers: 124 + 105 + 1,231. The last count already includes 168 fill-loop observations. Sixty bulk native controls reuse inputs from that corpus; do not count them as 60 additional disjoint Rust/Python observations.
- Nine native dispatcher methods are included in the 149-test group. PID-FD pause/resume observes in-flight native children and artifact lifetime, without an internal active-loan handshake.
- Actual pinned upstream Ring-Buffer execution completed 16,384 state transitions, 65,544 paired comparisons, and 131,088 native entry invocations.
- Its one captured configuration converted all 9 function bodies, accounted for all 22 active declarations, and retained 9 separately counted C ABI wrappers. This route uses the Hepta checked core/Rust backend and caller-authored record-view obligations; it does not establish arbitrary standalone-HIA C translation or inferred foreign ownership.
- All three fixed NDU searches completed with actual evaluator `abstain` and host `no_change`. All native baseline/candidate pairs were byte-identical. No performance gain was admitted.
- Source and selected tool identities remained unchanged during each frozen invocation. The host was the shared Linux x86-64 container, without physical dot-host attestation.

## Fixed native experiment

Exactly 31 paired samples per search, 10,000 complete-corpus repeats per side/sample, 16 fill cases or 20 swap cases; **32,240,000 timed native calls** total. Thresholds remained MAD <=5%, relative gain >=2%, three paired-saving MADs, 60s search admission ceiling and 2s decision reserve, with a 100,000,000-call assumed horizon.

The medians below are descriptive observations. Artifact equality alone refuses eligibility; noise and unrecovered cost provide additional rejection reasons.

| Run | Baseline median ns/call | Candidate median ns/call | Relative MAD B / C | Paid internal / complete CLI seconds | Decision |
| --- | ---: | ---: | ---: | ---: | --- |
| fill-loop-1 | 69.128687 | 61.008000 | 20.940% / 20.095% | 5.021830 / 5.170952 | no_change |
| fill-loop-2 | 105.395206 | 102.279769 | 10.972% / 9.278% | 2.806605 / 2.949834 | no_change |
| swap-control | 23.153400 | 23.990410 | 13.667% / 17.221% | 2.036050 / 2.205122 | no_change |

Different fill Core and LLVM IR documents produced the same 15,480-byte native library under the selected Clang: `9060fcb2df0d51a45c12ff426bc02bcbf0553c6ac3cf3c5f8d77c6534b9f8b73`. Swap produced the same 15,432-byte library on both sides: `527992d971d479b12a0a8ef033745527f36764df081bc78ba4ac3d0ee94421d1`. No particular compiler pass is attributed without further evidence. Total internal paid search time was 9.864484806s; complete CLI time was 10.325908494s. Neither includes engineering, evaluator build, tool installation, model, energy or maintenance costs.

The temporary native .so files were removed by the instrument after execution. Artifact equality is supported by the instrument's actual before/after hashing and compiled/executed receipts; the later read-only audit did not reopen those deleted files. Core and LLVM IR texts are retained. Selected tool identity is not an independent attestation of every host library or the complete operating environment.

Ring-Buffer's three descriptive Hepta/C median ratios were 0.740983, 0.625515 and 1.589138. Relative MADs across those samples ranged from 24.007% to 49.971%; these seven-sample, different-backend controls do not qualify a speedup. Both favorable and regressive results remain retained. Automatic module qualification cost 19.441098545s internally and 20.440977547s for the enclosing CLI. Manual contract authoring, review and maintenance hours remain null.

## Evidence and reproduction

`results.json` provides the derived summary. `raw-evidence.zip` contains all retained development logs including failures, frozen command plans, source/tool snapshots, raw timing reports, the real module's generated sources/contracts/bridge, and independent read-only audits. `raw-evidence-manifest.json` lists every member and its verified SHA-256. Original paths inside reports describe the historical invocation; archive-relative member paths are portable.

The committed experiment is `experiments/hia_ndu_native_20261027/run_frozen.py`; its protocol was committed before timing. The source-bound functional runner and its exact environment helper are retained in `reproduction/`. Adapt tool paths for a new host, use a new output directory, preserve the same protocol and retain failures. The NDU bridge was built from upstream `f8c9419df6ddeb36ff8b522a50219981fb8d9345`; the retained build receipt binds its executable and inputs. No private upstream production source is vendored here.

## Acceptance status

The finite implementation and evidence improve P0/P1/P2/P3/P5/P6. P4 remains open: these candidates delivered no new native bytes or accepted net gain. P7 remains open: no full 35-gate run, new physical/multi-OS execution, long-lived workload or independent Agent productivity experiment was performed here. Whole-language soundness, full backend refinement, global optimality, universal Rust superiority, automatic C/C++ contract recovery, representative migration/human cost, and external-borrow/callback/shared-state native migration are not claimed. No candidate was activated or merged.

See [the Chinese report](REPORT.zh-CN.md) and the exact [machine-readable results](results.json).
