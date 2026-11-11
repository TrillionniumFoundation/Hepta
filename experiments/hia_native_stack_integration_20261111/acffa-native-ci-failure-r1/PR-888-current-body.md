## Purpose

Continue the complete HIA migration with source-bound native owners, ordinary caller coverage, installed resources, and strict process ownership. The requested final cutover still requires complete matching-source qualification and closure of the remaining hosted owners.

## Current result: blocked on the original ELF caller gate

Current head is [acffa9262f31d073f8f0a6f0201eae201039f619](https://github.com/TrillionniumFoundation/Hepta/commit/acffa9262f31d073f8f0a6f0201eae201039f619), tree `22a095436c94efc87b1a89aca912c8caab2eed80`, with 4,023 source leaves. The PR checkout is the real merge commit `9796578f490cb9ed2720fd6b0fb6d1a42cc25987`, with the identical source tree.

Both current HIA CI runs completed with the same failed step: **Original 51 ELF callers with retained writer forbidden**. The frozen gate reported `HOLD`; its detailed original report is being recovered from the artifacts. The job logs do not expose the inner cause, so this update does not classify it as an individual test failure or a timeout.

The source jobs passed all 401 tests each. Both native jobs passed through the complete state, instruction, Core lowering, and ELF component/boundary gates before the final ELF caller gate failed. Complete retained regression has not been dispatched for this known failing candidate.

## Changes in this candidate

- Integrate the native Store authority, artifact/page, machine state, instruction, ELF, and 32-image Core lowering owners with ordinary caller paths and source-bound installed resource admission.
- Preserve the complete 30-gate qualification surface and the actual process-owner receipts, including their raw hashes, natural termination, bounded cleanup, and source/image identity checks.
- Repair four integration source controls: the exact 33 Core resources, the complete bootstrap/source contract union, the full workflow command sequence, and the original 55 commands plus four new gates. The original test method populations and failure behavior remain intact.
- Regenerate the support contract from the complete source. The regenerated language inventory is byte-identical to the preceding candidate.

## Actual validation

| Observation | Actual result | Scope |
| --- | --- | --- |
| [Source authoring 43116276591](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43116276591) | PASS | 59 generators, 53 parsed Python files, 68 zero-return commands; 11 accounting + 18 compiler-gate + 24 original integration methods. Original 180-second owner closed naturally in 90.260128181 seconds. |
| [Push 43117621509](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43117621509) source | PASS | 401 tests, 584.453 seconds. Complete original log independently read. |
| [PR 43117632066](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43117632066) source | PASS | 401 tests, 429.017 seconds. Complete original log independently read. |
| Both current native jobs | **FAIL** | Sole failed job step 38: original ELF callers, `HOLD`. Steps 34–37 recorded PASS; complete original logs and provider artifact seals retained. Detailed native artifact reports remain pending readback. |
| Separate Core development observations | PASS in three separate runs | Exact 12 + 51 + 50 IDs and zero anomalies; 28 modes and 3,799,403 actual native steps. The three owners' times are not a single 180-second qualification. |
| [Exact-source supplier 43119431463](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43119431463) | PASS | Unchanged exporter preserved the real commit/tree/object closure, reconstructed it, and reproduced an independent clone. Source supply only; no product qualification. |
| Complete retained regression | NOT RUN | Requires repair of the current failure and a newly bound final source. |

The push cold summary recorded 11/11 checks and language coverage recorded 1,242/1,242 checks. The original artifact receipts, phase inventories, and new native gate details still require independent recovery; job summaries do not replace those originals.

All original constraints remain: cold 180 seconds, two workers, all 38 phases; original 3/5-second callers; unchanged compiler capacities; complete retained discovery at 5,400 seconds under the 10,800-second guardian. No skips, reduced denominators, or development-group totals can substitute for a complete gate.

## Remaining work before cutover

1. Recover both current original ELF gate reports and lifecycle records, identify and fix the concrete failure, then regenerate and qualify the corrected source.
2. Complete matching-source cold, all 30 gates, full retained discovery, installed-package, recovery, and default-path observations for the final candidate.
3. Finish the Emitter control expansion, complete foreign ELF sorting behavior, remaining Agent business/persistence/process owners, CLI/build/install paths, and the separate runtime implementation.
4. Remove the supported old implementation only after those replacements and the final cutover are qualified.

The Emitter v2 source is ungenerated/uncompiled WIP and inherits no v1 native results. The TimSort source preparation r2 stopped on an incorrectly wired historical receipt before any source generation; that actual HOLD is preserved and its controller correction remains separate from sorting correctness.

## Durable evidence and retained failures

- [Current two native CI failures, original logs, external artifact seals, and previous complete PR narrative](https://github.com/TrillionniumFoundation/Hepta/tree/d52a9b005dfa91d9d2500cf5b3b4f0fdd0243e6d/experiments/hia_native_stack_integration_20261111/acffa-native-ci-failure-r1).
- [Both complete 401-test source logs and exact-source supplier evidence](https://github.com/TrillionniumFoundation/Hepta/commit/358bac4bdbdd681bf4dc5b80675745fafc6a2172).
- [Independent source authoring acceptance](https://github.com/TrillionniumFoundation/Hepta/commit/47dc8d0bf492444ad6825e3ab5f98f157852851a): all 166 original files, 278 recovery pieces, 6,898,354 bytes, and complete source identities verified.
- [Original Core development results](https://github.com/TrillionniumFoundation/Hepta/commit/fe10a8262182cc4068e7e1a444708a62f7f1bdee) and [separate timing-boundary correction](https://github.com/TrillionniumFoundation/Hepta/commit/799109a5d2bd3e504cc75b573fe4fef168c1bdb2).
- [Original e8 CI failures and integration findings](https://github.com/TrillionniumFoundation/Hepta/commit/2d372b91d2691166cdc7464e8e0690f40e0a565d). These remain failures after the source repairs.
- [Actual TimSort preparation HOLD](https://github.com/TrillionniumFoundation/Hepta/commit/32ef14694624f5544d9599a2d2670ec4f14130ec).

Existing FAIL/HOLD/UNKNOWN evidence, including the earlier desktop cold deadline failure, remains authoritative for its original run. This draft has not merged, activated a new default, changed the deployed runtime/configuration, or deleted supported old owners.
