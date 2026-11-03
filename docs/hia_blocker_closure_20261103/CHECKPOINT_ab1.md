# HIA blocker closure evidence — 2026-11-03

This is a research evidence checkpoint for PR #564. Each observation retains
its actual source commit. These files grant no production authority.

## Verified checkpoint

Source `ab1c1a50b77a0d9f2da14a86b418f60985fbfe28`, tree
`4134b41a604e8ccb86bde62f5d492135590afe99`, passed all 21 composition
qualification entries: 291 regression tests, zero errors/failures/skips;
404 Lean theorem dependency checks and 11 designated rejecting controls.
There are 22 command receipts including the native NDU build. Source/tool
identities were stable. The 404 includes older and concrete-instance theorems;
22 new generic lifecycle theorems were added.

GitHub's prospective merge tree for PR #564 into the stacked research base
matches this source tree. This is not a main-branch release qualification.
The two larger workflows were still running when the initial host review was
recorded; their later completion must be recorded separately.

The original `composition-ab1.zip` and earlier `composition-68c04.zip` were
verified against GitHub artifact digests. Readout JSON files retain their run,
artifact, source and tree identities. Earlier negative results remain intact.

## Implemented repairs

The source now includes logical-line transport bounds, typed frozen performance
registrations, package directory-alias rejection, strict startup ACK handling,
provider quota/cleanup stops that survive malformed output, bounded detached
NDU snapshots, and selected capability lifecycle proofs. The expanded composition
gate executes the new controls and proofs with the original native experiments.

## Actual native scope

All 17 reviewed host jobs passed on ab1. `HOST_ARTIFACTS_ab1.json` records all
artifact metadata; `hosts/` preserves seven inspected ZIPs. Each local ZIP was
independently checked against the original GitHub digest. Full decoded job logs
are retained in `HOST_LOGS_ab1.tar.xz`; conditional skips remain explicit.

| Route | Observed scope |
| --- | --- |
| Captured C to HIA to LLVM | Linux x86-64/AArch64; each has 48 functional cases/144 native calls, 16 resource cases/32 calls, 12 control tests, 12 translated bodies including 11 upstream bodies. No Rust codegen. |
| Standalone HIA AArch64 | Direct ELF execution: 17 scalar returns, one NULL refusal, one bounds exit 134, two wrong-Core controls, four allocations/frees and zero outstanding. Runtime bound: 4096 bytes and one live allocation. |
| Broad ABI, seven combinations | Linux x86-64/AArch64 GCC and Clang; Windows x86-64 MSVC and Clang; macOS AArch64 Clang. Hepta uses its Rust 1.90.0 backend. |
| C++ reuse, seven combinations | Unchanged nlohmann JSON 3.11.3/3.12.0, C++ bridge and Rust-backend Hepta consumer. This is not translation of the entire library. |

The results do not qualify every target ABI, general foreign ownership,
physical MMIO/IRQ/DMA, arbitrary C++ migration or whole-language safety.

## Performance remains a blocker

The production-path reduction gate passed 143/180 comparisons on 68c04 and
152/180 on ab1. Neither establishes broad Rust parity. The separate thin-wrapper
study, retained under `experiments/hia_empty_wrapper_20261103` on the source
branch, passed 232/276 comparisons and 10/12 complete empty-input gates; it also
has four nonempty median regressions above 10%. It remains experimental.

The paired 256-model snapshot study retained all 66 timing samples: median
Python validation, exact-control and request-building times fell 90.96%,
81.45% and 61.98%. That isolated experiment made zero native NDU calls.

The ab1 integrated NDU experiment completed all nine workload calls and matched
the exact model, but won 0/3 scenarios. Its conservative campaign costs were
8.125962415 s fixed, 8.131817693 s exact DP, 8.134412014 s lightweight and
35.792549967 s native NDU. Native includes 27.616697285 s of outer bridge build.
These are declared allocations of observed costs, not four independent solo
campaigns. Full acquisition/human/maintenance costs remain unknown. The current
controller computes exact DP before constructing the native candidate bank;
agreement does not demonstrate additional solution quality. Cross-host and
toolchain timing differences are not paired estimates of snapshot causality.

## Open proof and production obligations

`REFINEMENT_INDEX_ab1.json` verifies the scalar manifest and binds four actual
LLVM/native reduction chains. It keeps different Core artifacts separate.
The selected scalar proof does not prove a native-machine-code endpoint.
The CI archive retains native identities and execution records, but not the
reduction object/library bytes; the separate wrapper archive retains its binaries.

Issue #471 remains open. Outstanding requirements include complete declared
schema/opcode consumer coverage; borrow permissions, calls/returns and
capability-to-heap correspondence; outcome/FFI/resource-budget composition;
broader native targets and physical devices; migration and maintenance cost;
positive Rust/NDU performance; completed real-model productivity studies; and
long-lived deployment, power-loss and external-effect recovery evidence.

Further borrow-permission work is evaluated separately when its actual proofs,
rejecting controls and integrated-source results are available. The status stays
`authority=DENY_ALL`, `safety_certificate=false`,
`production_activation_allowed=false`, `all_blockers_closed=false`.
