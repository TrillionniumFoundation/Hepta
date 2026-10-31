# HIA seven-track reconciliation on the current P0/P7 source

Date: 2026-10-31

## Exact source ancestry

This research source preserves two independent histories:

- Current security / ABI chain: Draft #504, parent `4e303ab3c0fcb7051de1ec4321526529b9d69659`.
- Seven-track returned-loan / NDU / C++ / Agent research: Draft #497, exact head `cf979410742481caa4948e877723cc7440171741`.
- Common ancestor: `3201298a9828927452d42bcac146e610e1348a7f`.
- The integration commit has two parents, with #504 as first parent and #497 as second. The final source SHA and Git tree are recorded by CI artifacts; branch history is not a production release.

The Git-tree reconciliation compared full recursive tree objects, not only changed filenames. It retained 47 byte-identical overlapping objects, adopted 28 feature-only paths, and manually reconciled five different overlapping objects. There were no deletions in the feature delta.

## Five explicit reconciliations

1. `hepta/cpp_gsl_final_action.py`: retain the AST-derived const-lvalue factory profile v3, adding only the source-observed GSL 3.1 / 4.0 const-reference factory path to the existing callback profile.
2. `tools/qualify_hia_verified_increment.py`: keep the current exact planned/started/finished test identity gate, explicit expected-failure and unexpected-success rejection, source/worktree immutability checks and DENY_ALL receipt. Add the eight seven-track test modules; do not replace the strict runner with the older #497 runner.
3. `benchmarks/hia_native_ndu/PROTOCOL.json`: record that all Pareto paths are retained and only a unanimous first prepared-set action can be selected; conflict or abstention retains the incumbent.
4. `tests/test_hia_native_ndu.py`: add explicit positive and negative controls for unanimous first actions, ambiguous actions, later preparation work, and authority refusal.
5. `tools/qualify_hia_native_ndu.py`: retain failure-preserving timeout/spawn receipts, explicit instrumented and optimized-release profiles, and first-action selection checked against the independent finite DP.

The P0 policy predecode, source/target ABI preflight, owned-entry arity preflight, P7 image/generation/queue checks and native-driver digest admission remain inherited from the first parent.

## Scientific and engineering evidence boundaries

The original #497 branch reported 1,226/1,226 registered integration tests and five successful workflows on its own exact source. Those results are not transferred to this new two-parent source; exact-head workflows are re-run here.

The negative results remain binding:

- Rust release parity: 0/10 registered CI size thresholds.
- Native NDU service economics: 0/9 positive against fixed, exact-DP and greedy controls. Whole-lifecycle cost and positive net benefit are not established.
- Agent coding productivity: 0/4 correct tasks per arm across HIA JSON, Hepta assembly and Rust. No Agent productivity advantage is established.
- The out-of-profile `realloc(NULL,n)` allocator observer accounting issue remains disclosed.

The #502/#504 host, P0 and P7 scoped results are also source-specific historical evidence. This branch must run its own exact-head broad, native, C/C++, ABI and P0/P7 workflows. A workflow queued or a test module green is not an independent release approval.

## Authority

`authority=DENY_ALL`; `safety_certificate=false`; `production_activation_allowed=false`. All P0–P7 production checkboxes in Issue #471 remain OPEN until the same final integrated source has the required independent proofs, host evidence, held-out economics, Agent results and crash/recovery qualification. This document is a provenance note, not a safety certificate or release grant.
