# HIA product follow-through: exact-source corrections, 2026-11-07

This follow-through starts from metadata commit
`d0635e7e4c5ebb3493fc135f0b98afc49f75a17d`, whose installed source lock named
Hepta `3151bdd0b3bc7fa2911f1e7e7f3fe1b0fe9bd092` and runtime
`c81a938150d2e533843a42af77739cb888812338`. It preserves the earlier records
and corrects two acceptance/reporting defects. The source pair in the current
`releases/hia-current.json` is the installation authority for this candidate;
an earlier live receipt does not qualify its changed worker.

## Original production tasks and current service

The original cutover `1a1b54d0050-fc05-8be3` on `main` was read again under
the same launch nonce. Its terminal remains `failed`, exit 1, with all 6,305
stdout bytes durable and complete. Config, plist and link restoration passed;
service rollback did not complete. The original evaluation
`1a1b59f7d31-12894-7d` on `x230` remains `succeeded`, exit 0, with all 1,775
stdout bytes durable and complete. Its domain outcome is `unchanged` and
`adopted=false`. Neither task was relaunched.

A fresh read-only observation found the current Mac controller in the
`gui/501` launchd domain, PID 75924, running. Its config SHA256 remained
`902a77c095bb5e6e5b0ac6d6fa8f13f5ee87330273b239df2f2bc732ed1fa090`
and plist SHA256 remained
`3498a4b0b69a0a2e77227739c1e649c3487e74af79b826c2b303cbfb51948ccc`.
The generic service API's system-domain-only miss is retained separately; it
does not prove that this user-domain service is absent.

An authenticated, read-only `initialize`/`tools/list` observation returned
113 tools including all eleven HIA tools. The complete sorted catalog SHA256
remained `954670433d118607f1ad55fb330a139e6d8fd998b740a9f62a41a212cc722b0e`.
The configured worker remained
`b75a689c159beab75d3af985badede167c247f482dd7dc86dfe99973a5aab079`, belonging
to Hepta `894d2dfce54ff25271b8de2c18c902394484d5cc` and runtime c81.
There were zero domain calls in this discovery observation and no production
configuration change. The current conversation still exposes zero HIA tools;
an HTTP catalog and actual registration in this Agent remain distinct gates.

The controller inventory again refused a changed membership, then exceeded its
original source-scan budget. These errors are retained. No new live cancellation
trial was submitted after incomplete inventory. Runtime inventory optimization
is a separate patch and is not silently included in the c81 source lock.

## Safe Core: a real counterexample and the corrected chain

The old x86 symbolic executor treated an external `abort` call as immediately
terminal. It omitted the calling instruction's implicit eight-byte return-address
store. A deliberately wrong backend inserted `mov rsp, 0` immediately before
the call. The old independent model accepted the final linked image, although
real x86-64 `CALL` must first write to an invalid stack address. The harmful
image was not executed.

The exact final-image SHA256 was
`78e423c2edf4285e7a214e1598566b31a5c91e71b504499895cc7ee40f0d9066`.
The fixed model applies the stack decrement and checked return-address store
for every call before deciding whether the target returns. Rechecking the
same image produces a SAT counterexample to `machine_memory_access_bounds`.
The retained scalar example uses arguments 2608092046 and 3261911607, whose
checked-u32 addition reaches the abort path.

The correction is in source commit
`097b0d831ace40f7b7c9b30ac66479961fa92a22`; the accompanying evidence commit
is `1df4890940c68c421f9f93e0c3aefa949517d5b7`. Qualification passed 27 tests
without skips, three positive final images, five semantic SAT mutants and 29
query replays. All seven before/after same-image queries were separately
replayed. The [retained evidence](../review-evidence/hia-safe-core-call-stack-20261107/README.md)
contains both the incorrect old acceptance and the fixed refusal.

These are results for the independent Python Core/x86/ELF models and the
declared Safe Core profile. Kernel-checked hardware-ISA refinement, checker
soundness and whole-language soundness remain unproved. Caller allocation,
exclusive borrowing, loader/libc, available stack and hardware assumptions
remain explicit in the [profile contract](HIA_SAFE_CORE_MACHINE_VALIDATION.md).

## NDU: complete tasks must precede a completed-control saving

A later provider/native campaign exists and must not be reduced to the older
READY-only probe. All 32 provider processes have retained terminal usage and
cleanup observations. They produced 27 completed proposals, 22 correct native
task arms, seven native NDU evaluations and 42 failed or rejected attempts.
Its original byte verifier passed; the campaign itself exited 2. No provider
request or native workload was rerun for this follow-through.

| Policy | Registered tasks | Completed proposals | Correct native task arms | All-attempt wall ns |
| --- | ---: | ---: | ---: | ---: |
| Fixed | 8 | 7 | 2 | 130466301676 |
| Greedy | 8 | 7 | 7 | 134985846220 |
| Ordinary | 8 | 6 | 6 | 151383646332 |
| NDU | 8 | 7 | 7 | 113450243024 |

The old headline saving of 17,016,058,652 ns compared NDU with the cheapest
raw attempted arm, Fixed, even though Fixed completed only two tasks. No arm
completed its eight registered tasks. The new `completed_comparison` reports
each arm's eligibility, requires the entire registered control set to finish
correctly within the original budget with complete observed costs and actual
use, and returns `ndu_saving_ns=null` here. A failed Ordinary arm cannot be
silently removed in favor of a weaker control. Raw arithmetic and all failed
attempts remain available as explicitly labelled diagnostic fields.

The relevant 77 tests passed. The [NDU record](HIA_NDU_STRONG_CONTROL_20261107.md)
retains original inputs and a read-only reassessment. This synthetic wrapping-u8
cohort is not a representative real-user task cohort. The single-model proposals,
unknown monetary costs and unauthenticated provenance do not establish NDU
economic superiority or a fresh-Agent product qualification.

## Release and remaining boundaries

The release entry now includes `README.md` and this follow-through document in
its required exact-byte inventory. Removing either from a lock is rejected.
The integrated source passed 114 release, reconciliation, selfhost-contract and
NDU tests, plus the Safe Core qualification's 27 tests. Its 222-file seed
inventory was regenerated, and its own cold Selfhost-Core replay passed all
10 outer checks and 154 inner checks. B1=B2=B3 remains
`76446640911c583bc70b7f5a0c59973383b01dacb007d6f1f5b5239e70b25ad6`;
modified M2=M3 remains
`71f31e85003cb28ba081426106576322464ae2c15dcb97b7ab6c3ac344d59d55`.
The original source manifests, queries and generated bytes are retained in
[the integrated evidence](../review-evidence/hia-followthrough-current-20261107/).
Source and metadata commits remain separate.

The previous 8,192-instruction Selfhost-Core v5 capacity, 1 MiB source/output/
workspace budgets and refusal at 8,193 instructions are retained. This change
does not add general ownership, arbitrary checker coverage, returned borrows,
recursion, external-symbol linking or a general native backend. Those need
their own language semantics, negative controls and cold modified fixed points.

The live c81 inventory/cancellation gate, ordinary Agent tool registration,
representative equal-budget Agent/NDU trial, whole-language self-hosting and
default-branch/live-service promotion remain open. GitHub's current connection
refused repository reads with an account-suspension 403, so this session cannot
claim current remote CI, merge or publication. Local commits, raw observations
and exact source checks are delivered without substituting for those gates.
