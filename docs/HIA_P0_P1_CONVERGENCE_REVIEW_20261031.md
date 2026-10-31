# HIA P0/P1 exact-source convergence review (2026-10-31)

Status: **DRAFT / NO-GO**. This adds bounded P0 semantic/wire corrections to the P1 receipt-checking branch; it does **not** certify P0–P7 production completion, complete language soundness, or performance/NDU gain.

## Exact provenance and non-loss contract

- Target parent: Hepta Draft PR #443, exact `de8d73c9a04ead94848ec69c9c99f8f172ee8f5a` (itself stacked on #441, #440 and #434).
- P0 donor: Draft PR #439, exact `2580856718e1eaef66eacf6343065224975be282` (preserves #437, #436 and #438 work).
- This is **not** a wholesale merge of #437 and #434. It transplants only the reviewed P0 Unicode-token admission and `int.cast` catalog trap corrections onto #443. Both parents remain untouched.
- Source-exact donor blobs: `hepta/hia_agent_assembly.py` `7047efbd34f1f950c71267da05a133a98ce06a72`; `tests/test_hia_agent_assembly.py` `23f295035744ae3ec4869a9789653ed2ab3a778b`; `docs/HIA_AGENT_ASSEMBLY.md` `dd94fa9c02f12413a107a0e6edd28dd40d8d43ca`; `docs/hia-opcode-catalog.v8.json` `9f4dbac7bd5a420652d3752543d63cd6968127db`.
- Two overlapping P1 files must **not** be replaced by the #439 versions. Instead, preserve #443 `validate_execution_observation`, chain-node allocation/free invariants, exact integer steps and the execution-contract regressions; change only the original `int.cast` trap metadata in `hepta/hia_opcodes.py` and add the independently checked cast regression to `tests/test_hia_opcode_catalog.py`.

## Reproduced incompatibility and repair

In #443 the Agent input accepted non-ASCII Unicode separators/format controls that the P0 donor explicitly refuses. The exact #443 metadata advertised `int.cast` trap `overflow_when_checked` although the executable checked cast traps with code `overflow`. This contaminates the machine-readable opcode catalog used by Agent clients and independent checking.

The exact donor v8 catalog differs from the original #443 v8 catalog **only** in the checked-cast possible trap code and the resulting catalog hash. All visible type groups, opcode list, result rules and other metadata compare equal. The merged `hepta.hia_opcodes` retains the full P1 execution observation validator while correcting the one possible trap-code token.

These are bounded metadata and input-admission fixes, not a proof of source-to-machine refinement. Generated catalogs and model-facing contract text are not authorization.

## Required exact-head verification

```sh
python -B -m unittest tests.test_hia_opcode_catalog tests.test_hia_agent_assembly tests.test_hia_execution_contract -v
python tools/generate_hia_catalog.py --check
```

Also require the existing HIA closure workflow, safety-selector matrix, Rust/LLVM/native negative controls and independent source-bound review against the **final exact head**. No queued workflow, skipped test or older-branch result qualifies this branch. A passing small test set does not close any global soundness, C/C++ migration, P5 net-benefit, P6 NDU economic, or P7 production claim.
