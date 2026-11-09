# HIA six-track blocker review — 2026-11-09

**Overall acceptance remains HOLD.** The selected v9 public installation and its timestamped formal manifest readback agree. Final v16 source B has completed its original qualification cohort and has been integrated into both source baselines. This publication adds its separately named public installation entry and preserves the original evidence. Complete Core coverage, general machine correctness, original Agent-delta adoption and stable NDU economic benefit are not established.

The [previous review at main 74063163](https://github.com/TrillionniumFoundation/Hepta/blob/74063163ad19d096a4ff9a66a6f25728e6ce0d8f/docs/HIA_BLOCKER_REVIEW_20261109.md) and all older evidence remain available. Later results bind their own subjects; no ancestor result is transferred to a new commit.

## Public entries and observed online identity

| Role | Exact source | Selection |
| --- | --- | --- |
| Default public release and timestamped online HIA manifest | `2598f4309791d3a023cd5df585ad26810b20c744`, tree `4c073a29839eff1e75fbcc6dd28db4108c04160c`, bounded v9 profile | Unchanged `tools/hia_release.py` and `releases/hia-current.json` |
| Separately named v16 source release | `6ecd8023615a6e0b2dc269379fb059c656b38b6f`, tree `4c51962e030e9ea39c6498224c99eb40fbdd2f35`, bounded v16 profile | `tools/hia_release_v16_6ecd802.py`, explicit `releases/hia-v16-6ecd802.json` and SHA256 |
| Runtime in both original locks | `4cd85c99c5f5a480832c48fbde8561bb365f67a9`, tree `6b78d53b53d51a6c070bb37e8e9f6a15ad26d0e8` | No live transition performed |

The default lock is the original 37,527-byte source-CI member, SHA256 `9000d6eaa089f6bed92ea07a6561d91381a6f913263f0b1016d4f99e8789c1d3`.
The named v16 lock is the original 47,762-byte member, SHA256 `b3c3725e183d98bec2819155f2d4cd525c3f45305d04ec8fa686e13f454e50e0`.
Neither lock was regenerated or had its source-only flags rewritten.

The v16 entry is a byte-identical copy of B's original helper under a versioned filename. The old v9 helper cannot validate the new inventory under the existing executing-source identity gate. The shared preflight already has identical bytes. The [release guide](HIA_RELEASE_ENTRY.md#named-v16-source-release--2026-11-09) contains complete commands; the [five-path static review](../review-evidence/hia-v16-public-entry-static-20261109-e5ee/README.md) retains exact identities and checks.

The public workflow independently checks current and v16, retaining every original gate and the 35-minute limit per row. Current exercises the true default without a lock override and retains its original artifact name. Source qualification, static review, the metadata head's two installation jobs and actual-main post-merge installation are distinct evidence.

### Retained actual-main installation and formal readback

[PR823](https://github.com/TrillionniumFoundation/Hepta/pull/823) merged as `74063163ad19d096a4ff9a66a6f25728e6ce0d8f`. Its own [public installation run 42570014483](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42570014483) passed all 11 steps. The original native result contains 173 matching planned/executed IDs and no failure, error, skip, expected failure or unexpected success. Source/tree/cleanliness, describe/materialize/check, locked task inputs and the complete installation manifest agree. The lock fetched from that exact main commit is byte-identical to the original source-CI member. The [original artifact and independent readback](../review-evidence/hia-main740-public-installation-20261109-e5ee/README.md) retain these observations.

The formal online read at **03:01:50–03:03:18 UTC** returned the complete 7,048-byte manifest with `next_cursor=null`. The unchanged checker returned `PASS_CURRENT_INSTALLATION_READBACK`; worker, backend and catalog matched v9. Manifest SHA256: `d05cf5c78bed8da1cb9486f307097e4a2303780dd76da1c7ee44bafbee08969c`. The earlier 16,384-byte timeout and historical-operation recovery remain in the [formal readback record](../review-evidence/hia-online-release-2598-20261108-e5ee/postmerge-REPORT.md).

This is a timestamped installation-manifest observation. It does not prove continuous uptime, a newly executed native worker, loaded runtime-binary provenance or future states. Later metadata CI is not a new online observation.

## Final v16 source qualification and integration

B has ordered parents `20eace37747fde9aa0fc9c14cdb0159db30f5161` and `50262236d9d1807ca8df0eccfb9f5f7ee9f6206c`. The intermediate commit combines e0 and ff. Both prior source histories and the independent PR816 integration remain. Relative to qualified 6a, 64 paths change with no base deletion; all 380 prior evidence blobs remain, with 25 added evidence paths.

The [frozen original CI cohort](../review-evidence/hia-b6ecd-ci-final-20261109-e5ee/final-readback.md) completed **19/19 successful workflows**: 17 on attempt 1, Shared on attempt 2 and Guarded on attempt 3. Its latest 115 job records comprise **114 successes plus one conditional skip** for an optional workflow-dispatch native job. Initialization completed 80/80 jobs. This is not a claim that every job ran without a skip.

Shared attempt 1 and Guarded attempts 1 and 2 exhausted the original four pinned-Lean download attempts with HTTP 504; affected proof steps did not run. Those failures and the older ff456 assembly failure remain. Successful later attempts actually obtained the same pinned dependency and ran the original gates. No dependency hash, proof gate or acquisition retry limit was weakened. The gateway's underlying cause remains unknown.

At **06:21:19 and 06:21:21 UTC**, expected-SHA, non-force fast-forwards advanced both source baselines to B. GitHub independently reports [PR817](https://github.com/TrillionniumFoundation/Hepta/pull/817) and [PR808](https://github.com/TrillionniumFoundation/Hepta/pull/808) merged at that exact commit. Actual refs, preconditions and tree/parent records are in the [integration packet](../review-evidence/hia-b6ecd-source-integration-20261109-e5ee/README.md). Integration created no different source tree and did not merge full source into metadata-only main.

Those updates triggered a **separate 22-run cohort**. Its immutable [06:45:36–39 UTC phase snapshot](../review-evidence/hia-b6ecd-postintegration-phase-20261109-e5ee/README.md) records 20 successful and two running workflows; 118 latest job records comprise 115 successes, two running and one conditional skip. Post-integration Guarded attempt 1 again failed on four HTTP 504 responses; one evidence-based failed-job rerun passed on attempt 2. Both original outcomes remain. Running workflows are not counted as successes in that snapshot, and this cohort is not merged into the original 19-run denominator.

The separate [06:55:07 UTC terminal snapshot](../review-evidence/hia-b6ecd-postintegration-final-20261109-e5ee/README.md) subsequently records **22/22 successful workflows**: 21 on attempt 1 and Guarded on attempt 2. Its 118 latest job records comprise **117 successes and one conditional skip**. The earlier phase snapshot and original 19-run package were rehashed unchanged. This terminal packet retains the new full-NDU log/metadata; its additional ZIP and numerical samples are not substituted for the independently reconciled original full-NDU artifact discussed below.

## Independent source and machine-report review

The [exact-source audit](../review-evidence/hia-b6ecd-source-independent-20261109-e5ee/exact-source/README.md) binds artifact `13652892138`: 36,367,360 bytes, official SHA256 `819cdb66f6fd7cb1de3c02f52bdabfbb27f009f30f849778d132df29f83ea8cc`. Release, runtime, cold, language, fragment, leaf, Safe Core and strict-support inventories were independently matched to exact Git blobs. Overlapping Hepta groups cover **688 distinct paths**; group counts are not added as unique files.

Original reports retain 11 cold outer checks, 1,447 nested checks and 1,196 language checks. Fixed-point identities and the intentional wrapper transition retain their own meaning. Finite language cases and traps do not prove arbitrary-input compiler correctness.

The audit checks **29 successful proof/recheck reports and 145 retained query/result records**, including six scope fields and checker identities. Replays of the same obligations are not new theorems. The frozen C1 select fragment has five typed cases, four distinct whole images and two distinct copied 35-byte fragments. Original and independent rechecks concern the same 25 obligations; 200 projection and 64 whole-program calls are finite observations. Initialized, disjoint, normalized slots and the compiler-refinement premise remain assumptions. Arbitrary-context composition is not proved.

The [default-checkout audit](../review-evidence/hia-b6ecd-source-independent-20261109-e5ee/default-checkout/README.md) binds actual merge checkout `16add3df22d58fd5486541837cdaf73a21317c49`, parents 20 and B, with B's tree. Those jobs did not use B's commit identity itself. Linux reports 83 matching planned/started/finished successes. Safe Core v1 retains 45 tests, three positive cases, three supplied-byte rechecks and five rejected controls. Safe Core v2 retains 26 programs, 130 original obligations and a replay of those same 130, plus three independent artifact rechecks. Intentional producer/consumer profile and canonical/raw Core-hash distinctions remain.

All **28,122 original source-CI member streams** are [preserved and independently checked](../review-evidence/hia-b6ecd-source-originals-20261109-e5ee/README.md): 1,885,015,870 bytes, 16,121 distinct objects, a 7,366,924-byte archive. Every object, CRC, member mapping and aggregate count was checked. This container is not the original ZIP byte stream and cannot recompute GitHub's ZIP digest.

The reviewer used standard-library byte/JSON/AST/hash readers. No new project compiler, solver, generated native image or dynamic loader experiment was executed in this independent source review.

## Buffer lifecycle and original unfamiliar-Agent task

Frozen C1 and current B compiler-buffer continuations have separate subjects and exact source hashes. Each retains 25 worker requests, six reopened consumer processes and three original consumer receipts. Each uses the same Core against itself, satisfies its required Core/canonical-behavior/encoding claims and reaches a scoped **nonproduction, unchanged** lifecycle result. General compiler lowering remains unsupported. This closes the reviewed finite buffer-continuation engineering range.

The original semantic-change task retains its four-claim result:

| Required claim | Original outcome |
| --- | --- |
| Core | proved |
| Behavior equivalence | unknown |
| Encoding | proved |
| Compiler lowering | unsupported |

It remains `HOLD_REAL_DELTA_STRICT_GATE`; evaluation returns `E_HIA_CLAIM_REQUIRED`, with no adoption. The original counterexample and refusals remain. C0 rejects the extension while C1 accepts it, so unconditional all-input equivalence is unsuitable as a new extension property. A versioned extension property is a different subject and cannot retroactively satisfy the frozen contract.

Full original provider interactions, tokens and billing remain unavailable. A no-model campaign or dispatch counter is not a provider ledger; unknown cost is not zero.

## NDU performance and economic boundaries

The [scalar/controller review](../review-evidence/hia-b6ecd-ndu-independent-20261109-e5ee/README.md) binds B's own artifacts. Scalar integration records 180 successes and three Rust framing controls. Each prepared/persistent campaign completes 72 cells with zero failed/unstarted/retried cells, 1,020 original native responses and 510 ordinary calls. Independent standard-library replays return exit 0 and reproduce the original summaries byte for byte.

**Ordinary is faster in all 24 matched pairs in each campaign.** Prepared beats one-shot in 24/24 pairs. Persistent beats prepared in all 18 pairs at horizons 4/16/64, but only one of six pairs at horizon 1. Median total times from the persistent campaign are:

| Horizon | Ordinary ms | Prepared ms | Persistent ms |
| --- | ---: | ---: | ---: |
| 1 | 0.171533 | 8.495233 | 8.928076 |
| 4 | 0.671987 | 16.302890 | 13.777557 |
| 16 | 2.606314 | 45.502950 | 31.907931 |
| 64 | 10.051395 | 164.252748 | 104.974643 |

The frozen controller completes 64 pairs/128 calls with the same winner in each pair. **NDU is faster in 0/64 pairs**. Median NDU is 9.2602645 ms versus 0.044612 ms for Ordinary; median paired Ordinary-minus-NDU is -9.2165545 ms. Original outer wall time includes capture/export/audit costs. Independent verify-only execution checks 307 objects/128 cells without running prepare or native modes.

The full native NDU artifact has a separate [independent review](../review-evidence/hia-b6ecd-full-ndu-independent-20261109-e5ee/README.md) and [complete member preservation](../review-evidence/hia-b6ecd-full-ndu-originals-20261109-e5ee/README.md). It comes from [run 42565815059](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815059), artifact `13653895483`; original ZIP SHA256 `d8ad94fe9ab18679c1475de2e490c03620081e58bad52654031c73253e2d1dff`.

The bounded narrowed-reduction result passes **9/9 training and 21/21 holdout** compiler-performance comparisons. Two other retained parity groups report 0/9 plus 3/21, and 9/9 plus 18/21. The independent audit recalculates all 360 requests, 72 original JSONL files and 7,560 batches across the three groups. Thus the bounded narrowed kernel has a full-sample performance result; it is not evidence of general compiler superiority.

All 21 narrowed holdout median ratios are below 1, from 0.3750794211 to 0.9325095057 (recorded medians 6.75%–62.49% lower than the corresponding controls). These finite batch measurements are not confidence intervals or production-tail guarantees. The older guarded/narrowed receipts retain their own schemas: the guarded proof binds `hia.o`, and the retained trusted-linker step produces a separately hashed `hia.so`. This review does not relabel those receipts as six-field machine proofs or collapse object and loaded-library identity.

The pre-registered distinct-code guarded opportunity retains 84 samples and reports `no-economic-opportunity`. Both module gates remain unmet. Three original native-policy cohorts each have 12 complete rows and **zero NDU policy invocations**; incremental/gated/whole-lifecycle net-benefit flags remain false. A successful compiled-kernel comparison is distinct from extra value supplied by NDU policy.

The scalar/controller campaigns use finite synthetic workloads on a shared host. The controller campaign has no model calls or real tasks. Independent readers verify byte identity, arithmetic and internal consistency, not independently authenticated timings. Complete global/model/provider and monetary costs remain unknown. Transport improvements and a faster compiled program do not by themselves establish stable incremental NDU value or economic benefit.

## Runtime source candidates

### Mac helper PR111

[Runtime draft PR111](https://github.com/TrillionniumFoundation/hepta-runtime/pull/111) is `82de085a0223a6a3a3bf9573902bf252c4a0c8bf`, tree `bfc93c575fd30131f0ce3462009ebb00b247495d`, based solely on fixed runtime 4cd. The unrelated runtime default branch is unchanged.

The helper reserves journal capacity for 26 control-event types under the operation lock before effects. Unrecordable observations cannot authorize effects. The 37 original fake-test method bodies remain with five additions; the actual local suite passes 42 methods. The finite 15-event refusal and 16-event activation/rollback/finish fixtures establish the reviewed capacity boundary, not arbitrary I/O success or indefinite convergence.

Both original existing Linux CI runs pass on attempt 1. Each of three executed jobs records 2,389 passing/40 skipped all-feature tests and 2,360 passing/28 skipped no-default-feature tests. Actual head or same-tree merge checkouts are retained in the [original CI packet](../review-evidence/runtime-pr111-ci-20261109-e5ee/README.md). These repeated Rust configurations are separate from the 42 Python fake tests, which that workflow does not invoke.

Real Mac activation, trusted loaded-build/configuration identity, state/lease compatibility and operational admission remain unestablished. Linux CI did not deploy the helper.

### Private startup-receipt PR112

[Runtime draft PR112](https://github.com/TrillionniumFoundation/hepta-runtime/pull/112) is separate and based on fixed 4cd. At this preparation snapshot, head `246696b049273ec67eda7874e3b78777e53dffe9`, tree `3f5bc4d4ac895212b9cd10095bd9a7ef30d3aaf1`, contains seven changed files with 14 Unix library and three CLI focused tests.

The design binds provenance to the same buffer used for parsing, carries an immutable loaded-config wrapper and publishes an opt-in private receipt only after both runtime initialization sets succeed. Original RuntimeConfig serialization, old loader and policy-digest method bodies remain unchanged. It adds no hidden configuration digest to public MCP output.

The first head's three jobs failed at formatting before these tests ran; originals remain. A reviewed whitespace/optional-comma correction passes all three new format gates. Compilation, test execution and final qualification must come from [this head's PR run](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/42574689582) and [push run](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/42574683513). This preparation record does not claim that the 17 tests passed.

Even a successful producer candidate needs Mac build/load qualification, a trusted private adapter binding OS process-start, loaded image, service target and held locks, and a new unified runtime lock. `configuration_initialized` does not prove listener readiness, native-worker execution or persistent-state compatibility. Existing active slots, leases and artifacts cannot be assumed compatible because SQLite layout or directory is unchanged. Post-link I/O uncertainty remains explicit. Neither release lock selects this candidate; it was not inserted into PR111 or activated online.

## Six-track disposition

| Track | Established result | Remaining requirement |
| --- | --- | --- |
| P0 release consistency | Selected v9 public lock, actual-main installation and timestamped formal worker/backend/catalog readback agree. B is independently qualified/integrated and has an original named lock/helper. | The named entry needs its own metadata-head and actual-main installation results. A future online selection change needs its own observed transition. |
| P0 proof semantics | Reviewed six-field proof/recheck records retain subject, property, profile, assumptions, checker identity and unproved obligations; legacy optimization receipts keep their explicitly limited schemas. | Scoped PASS does not establish global safety or discharge broader P1 correctness. |
| P1 complete Core selfhosting | Six bounded scalar types, checked unsigned casts, bool equality/effect propagation; 50 ELF operation names and 40 flat-output names. | Signed i8/i16/i32/i64/isize and unit remain outside the scalar support matrix. General returned owners/loans, multiple-result calls, module graphs, arbitrary identifiers, full effect/resource combinations and general linking remain outside the implementation. Names are not full language coverage. |
| P1 machine correctness | Exact Core/machine/checker-bound Safe Core v1/v2, leaf and copied-fragment reports with independent rechecks. | Whole-compiler refinement, general ABI/resources/FFI/ISA/loader behavior and arbitrary-context composition remain unproved. |
| P1 unfamiliar Agent task | Both actual compiler-buffer continuations complete separate nonproduction unchanged lifecycles. Frozen patch, consumers, counterexample and strict refusals remain. | The original task still lacks two required claims, evaluation rejects it and adoption is absent. Full provider interactions/tokens/billing remain unavailable. |
| P2 stable NDU/economic value | Measured transport improvements and a full-sample bounded narrowed-kernel performance result; all registered comparisons and negative samples retained. | Ordinary wins all scalar pairs and 64 controller pairs. Distinct-code opportunity finds no economic opportunity. Stable incremental policy benefit and complete economic return are not established. |

These are substantive implementation, proof, original-task and empirical/data obligations. They cannot be closed by renaming HOLD, substituting a same-program lifecycle for the original change, counting an unexecuted proof, transferring ancestor CI or treating missing cost as zero.

## Publication boundary

This publication adds a separately named source release, checks both public entries and preserves original evidence. The default lock/helper, selected runtime and live service are unchanged. Runtime candidates retain their own identities and scopes. Overall six-track acceptance remains HOLD until the remaining requirements are established for their actual subjects.

