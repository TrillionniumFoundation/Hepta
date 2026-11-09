# HIA six-track blocker review — 2026-11-09

**Overall acceptance remains HOLD.** The selected public v9 installation has a
verified post-merge manifest readback. The combined v14 source is published for
its own CI; it has not been promoted to the public default or activated by this
review. Existing proof requirements and original failed observations remain intact.

## Public selection and observed identity

The default remains source `2598f4309791d3a023cd5df585ad26810b20c744`, tree
`4c073a29839eff1e75fbcc6dd28db4108c04160c`, runtime source
`4cd85c99c5f5a480832c48fbde8561bb365f67a9`, profile
`selfhost-core-linux-x86_64-v9`. The original 37,527-byte source-CI lock has SHA256
`9000d6eaa089f6bed92ea07a6561d91381a6f913263f0b1016d4f99e8789c1d3`.

[PR #818](https://github.com/TrillionniumFoundation/Hepta/pull/818) aligned that
public selection with the observed worker. Its actual main merge `bd4b8463`
passed [public installation CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42552762057).
A subsequent formal connector read returned the complete 7,048-byte manifest;
the unchanged checker matched worker/backend/catalog identity to the actual lock.
The earlier timeout, historical-operation recovery and successful independent
read are retained in the [post-merge report](../review-evidence/hia-online-release-2598-20261108-e5ee/postmerge-REPORT.md).

[PR #820](https://github.com/TrillionniumFoundation/Hepta/pull/820) published that
record. Its main merge `de31c4840c2b900a309f4c06ea3fc204c8630df1` passed its own
[public installation](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42556868174),
[online evidence replay](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42556868190)
and CodeQL. The original lock bytes remain unchanged.

This is a timestamped installation-manifest observation. Reobserving an immutable
operation does not prove a newly executed worker, loaded runtime build provenance,
continuous uptime or future installation states. The original lock's source-only
and deployment flags were not rewritten. Later operational changes require their
own observations and cannot be attributed to this review without evidence.

## Qualified parents and combined source

| Role | Commit | Result |
| --- | --- | --- |
| Loader, lease, cohort and first deadline integration | `2aa206882c7d6298d74ddc1ddf3a4ccb052e41a6` | 19/19 associated workflows succeeded, all attempt 1 |
| Bounded u16/v14 and copied-fragment qualification | `635c57bd7fd0b9f37480b4da091af4dddfd53a36` | 19/19 associated workflows succeeded, all attempt 1 |
| Combined [PR #817](https://github.com/TrillionniumFoundation/Hepta/pull/817) | `6a8c297b3f8f21506d11c2cb093c1c58d84ffe55` | Own applicable CI pending; parent results do not transfer |

The combined tree is `635d02f8f2b8151ae4697365e1962b070e4015a3`. Both parent
histories, their full file union, original failures and the 723 distinct control
inventory are retained. Three fixtures combine PID/starttime identity with all
prior cleanup assertions and both timeout premises. The production collector and
two readers retain their exact bytes, 60-second process and two-second cleanup
limits, and leader/streams scope.

The focused integration run passed eight methods, including both preoutput
subtests. Four separately injected observations comprise one positive case and
three required refusals, not four additional unique methods. The two distinct
historical 108-method failures remain unchanged. See the
[exact integration report](https://github.com/TrillionniumFoundation/Hepta/blob/6a8c297b3f8f21506d11c2cb093c1c58d84ffe55/docs/HIA_V14_FIXTURE_INTEGRATION_20261109.md).

During review, [PR #816](https://github.com/TrillionniumFoundation/Hepta/pull/816)
was independently merged into the source baseline as
`20eace37747fde9aa0fc9c14cdb0159db30f5161`. Later integration must retain this
new ancestor. Prospective merge metadata is not a substitute for actual job
checkout logs and artifact source fields.

The two default-checkout jobs actually used the initial PR merge
`d8dbec3de419ae45f719774dccbdfecb8bfa4493`, with the same `635d02f8` tree as
`6a8c297b`. They did not use either the head commit itself or the later prospective
merge. Their [independent identity review](../review-evidence/hia-6a-default-checkout-20261109-e5ee/README.md)
retains actual checkout logs, metadata and original artifacts. Linux reports
83/83 tests; Safe Core reports 45 tests, three positive cases, three supplied-byte
rechecks and five rejected controls. Producer and consumer profiles intentionally
differ; their subjects, properties, assumptions and checker identities agree.

## Independent v14 artifact review

The [parent read-only audit](../review-evidence/hia-635c-independent-20261109-e5ee/README.md)
qualifies identity and scope consistency only for original `635c57bd` artifact
`13646795635`, from [source run 42552813567](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42552813567).
The 32,398,297-byte ZIP matches its official SHA256
`577e5ab4311d6bd6f66a106eb676806277e809225f408b83851c5e2e5b1a5cee`.

All 252 exported source identities match their cold/language/lock hashes and
exact public Git blobs. Original reports retain 11/11 cold, 1,215/1,215 nested
and 1,026/1,026 language checks; these overlap and cannot be added as unique tests.
All 555 fragment evidence files were hash-checked. Five proofs and five independent
rechecks concern the same 25 obligations. Five typed outputs contain four distinct
whole images and two distinct copied 35-byte fragments. The 200 projection calls
and 64 whole-program calls remain separate finite observations.

The reviewer did not execute a new project compiler, solver, generated native
image or dynamic project test. These scoped reports assume initialized, disjoint,
normalized input slots and the stated compiler refinement premise. The fragment
lemma does not prove its preconditions or reachability in arbitrary surroundings.

The combined `6a8c297b` source now has a separate
[independent exact-source audit](../review-evidence/hia-6a-source-independent-20261109-e5ee/README.md),
using its own successful [source run 42558245653](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558245653)
and original artifact `13649338156`. The 32,401,939-byte ZIP matches official
SHA256 `0de6b5217abcb1568b06f4e9f5c95eb30d9c487678d51007c57f9ddc6e3c7169`.
Its original 46,609-byte release lock has SHA256
`57c6d240add46c3ee27884d24193bb607ec7983674e58b135072ac281d60345d`.

This review independently binds 365 Hepta release-file hashes, 13 runtime hashes,
252 cold exports and the separate qualifier source inventories. The overlapping
groups cover 679 distinct Hepta paths and are not added as unique files. It
checks 29 successful proof/recheck reports and 145 retained query/result records,
and connects actual frozen C1 output slices to copied projection object and final
ELF text. These counts describe original reports and internal byte/hash/result
consistency, not 145 different theorems or a new local solver run. Cold, language,
fragment and original strict Agent boundaries remain as above. The included
standard-library audit script ran with exit code 0 without importing project code
or executing a compiler, solver or native image.

## Six-track disposition

| Track | Established evidence | Remaining blocker |
| --- | --- | --- |
| P0 release consistency | Selected public v9 lock, actual-main installation CI and timestamped formal worker/backend/catalog readback agree. | v14 needs its own completed CI, source integration, the merged source's original lock, public installation qualification and a verified operational transition/readback before promotion. |
| P0 proof semantics | Reviewed proofs/rechecks retain subject, property, profile, assumptions, checker identity and unproved obligations. | Scoped records do not establish global safety or discharge the broader P1 correctness obligations. |
| P1 complete Core selfhosting | Qualified v14 has six bounded scalar types; ELF declares 50 operation names and flat output 40. | Signed scalars i8/i16/i32/i64/isize and unit remain unsupported; Core declares twelve scalar types in total. General returned owners/loans, multiple-result calls, module graphs, arbitrary identifiers, full effect/resource combinations and general object linking also remain outside the implementation. Operation names are not complete language coverage. |
| P1 machine correctness | Safe Core artifact validation and actual copied-output-fragment checks bind their exact subjects and assumptions. | Whole compiler refinement, general ABI/resources/FFI/ISA/loader behavior and arbitrary-context composition remain unproved. |
| P1 unfamiliar Agent task | Real frozen patch, independent consumers and original strict refusals are retained. A separate finite buffer continuation passes a nonproduction lifecycle with outcome unchanged. | For the original task, behavior equivalence remains unknown and lowering unsupported; evaluation rejects the missing required claim, with no adoption. The separate lifecycle does not qualify that task. C0 rejection/C1 acceptance also makes unconditional all-input equality unsuitable for the extension. Full original provider interactions/tokens/billing remain unavailable. |
| P2 stable NDU/economic value | The combined 6a source's own original CI reports 172 integration tests and three Rust controls; both registered 72-cell campaigns independently replay byte for byte. | Ordinary is faster in all 24 pairs in each new 6a campaign. Persistent beats prepared at horizons 4/16/64 but only one of six pairs at horizon 1. These transport improvements do not establish incremental value against Ordinary. Complete provider/model and economic cost remain unknown. |

The original Agent report stays `HOLD_REAL_DELTA_STRICT_GATE`. The fragment
reports retain `evaluation_performed=false`, `adoption_authorized=false` and
`agent_proof_receipt_issued=false`. A future versioned extension property is a
different subject and cannot retroactively change the frozen task's four-claim
contract. Its remaining obligations are listed in the
[extension proof plan](https://github.com/TrillionniumFoundation/Hepta/blob/6a8c297b3f8f21506d11c2cb093c1c58d84ffe55/docs/HIA_AGENT_EXTENSION_PROOF_PLAN_20261108.md).

The [new 6a NDU review](../review-evidence/hia-6a-ndu-independent-20261109-e5ee/README.md)
binds run 42558245656 and artifact 13648987153. Its 8,085,898-byte ZIP matches
official SHA256 `b115dda0b04c35f9fb60a6d26eacd4aa74cb479af27c7179c165e5a2d93057b0`.
All 475 original file members are retained, together with the registration,
source identities, raw responses, timing records and independent replay results.
Each campaign checks 1,020 original native responses and 510 ordinary calls;
these are original observations, not new native evaluations by the reviewer.
The standard-library replayers check identity and arithmetic and do not
independently authenticate the original timings.

The earlier NDU evidence remains in the
[ffa audit](../review-evidence/hia-ffa64-independent-20261108-e5ee/README.md).
The new campaigns also use synthetic finite cost tables on a shared host with
no real task or model call. Missing cost is not zero; failed samples remain;
transport improvements are not relabeled economic gains.

## Publication boundary

This record adds evidence only. It does not change the default lock, release
helper, source installation, runtime configuration or service process. Source
integration and metadata-only main remain separate. Overall acceptance stays
HOLD until each outstanding requirement is established for its actual subject.
