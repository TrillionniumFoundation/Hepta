# V9 independent review before generation

## Decision and exact source

**Allow the single registered fresh V9 qualification** at
`ef9fbafabe9db52a5e59220f1738d5842ac164cc`, tree
`7ad53d1f8763d7688877f3e8df7c458500fa65de`.
This decision followed source/preregistration review and a new, complete
19-row capacity/reference receipt. It does not declare qualification successful
or unconditionally authorize main. Main still requires fresh V9 **3/3** through
the unchanged gates and result verification. If this qualification fails, the
registered stopping rule retains the failure and costs, leaves main unstarted,
and rules out another round of task-specific prompt tuning in this study.

The review was explicitly staged. The first receipt allowed only zero-generation
capacity controls and held generation. The final receipt permitted qualification
only after those fresh controls had completed and been checked. The final audit
file was retained before the new qualification's plan was started; the plan itself
records zero preceding model requests. These are ordinary execution/file records,
not hardware attestation or a new runtime authorization mechanism.

The reviewer ran no tests, tokenizer, compiler, production editor/parser, VM,
native candidate, or model. Source inspection, standard-library JSON processing,
Git comparisons, and hashing of retained artifacts were the review operations.
Producer controls are identified as producer results throughout.

## The change is limited to the registered contract disclosure

Relative to frozen V8 `33c46cdef12c60faf0c1dbef02ea20caa3ad7d56`, V9 adds seven
files and modifies none of the existing files. Its prompt implementation is a
copy with exactly two generic string changes:

1. Both node interfaces say each node ID appears at most once per batch.
2. Rust says type nodes receive allowed type expressions, expression nodes
   receive expressions, and same-file selected spans must be disjoint: select
   a parent or descendants, never both.

No task answer, selected repair node, extra task example, source rewrite, implicit
cast, overlap deletion, or automatic answer repair is added. The new study CLI
differs only in its explicit prompt/support imports. The new capacity CLI adds
the corresponding imports and a distinct V9 capacity schema. Both keep the
original control flow. The actual generation transport, decoder, history-budget
implementation, validation, reference construction, ownership checks and native
evaluation remain shared with V8. Transport generation records retain that
adapter's V8 format; the enclosing study and capacity records are explicitly V9.

The final retained control inputs were also compared directly with V8, without
running either prompt implementation:

- All **19 queries and human reference responses are unchanged**.
- All **8 full-file initial prompts are byte-identical**.
- The **4 HIA-node prompts** contain only the common unique-ID amendment.
- The **7 Rust-node prompts**, including qualification, contain only the two
  registered amendments.
- Actual model and tool identity records, including the companion inference
  libraries, are identical across the V8 and V9 capacity runs.

The protocol loader additionally rejects changes to the model, runtime, arm/task
sets, generation/history budgets, native/resource budgets, primitive-conversion
profile, hidden seed/case count and fixed qualification task list. V8 capacity or
qualification records are rejected by the new schema/source/prompt bindings.
The threshold remains three correct tasks, not a majority or a reference-control
result.

## Fresh checks and their scope

The producer ran **41/41 static controls** on the frozen V9 source: seven new
amendment controls, thirteen original study controls, and twenty-one structured
interface controls. The original log SHA-256 is
`bcf06618242373bf35ab1eb9dd761d47d7f53f007c41bd718417b2155f4010ba`.
The reviewer checked its receipt and log, rather than rerunning the suite.

The producer then ran **19/19 actual reference controls**, with successful public,
terminal hidden, native, resource and applicable VM observations. The owned
inference process supplied template/tokenizer services only, made **zero
generation requests**, and exited. Complete reference token IDs agreed between
the owned server and the separate pinned tokenizer. Source/model/tool boundaries
remained stable. The receipt SHA-256 is
`9e12ee31034f9f188ce9a79c6eb6f24189938c536471468792192838d7c75afb`.

The independent audit matched **172 source dependencies** against Git, the
working source and the retained snapshot. It checked complete query/reference
digests, actual template renderings, stored token-ID lengths, the two complete
repair positions and reference-history capacity, all public/terminal hidden
gate records, and the retained bytes of all **19 native artifacts**. These checks
establish attribution and internal consistency of the producer observations;
they are not independent re-execution or a proof of all possible program runs.

| Capacity item | Actual maximum | Registered limit |
| --- | ---: | ---: |
| Initial request | 2804 tokens | 8192-token total context |
| Complete reference response | 1059 tokens | 1536 output tokens |
| Checked complete repair plus output reserve | 5044 tokens | 8192 context tokens |
| Registered additive repair allocation plus output reserve | 7284 tokens | 8192 context tokens |

The three qualification initial requests use 1413, 1783 and 2263 tokens; their
complete reference responses use 55, 109 and 65 tokens. The capacity/reference
run took 76.953562987 seconds of producer-recorded wall time. This is preparation
cost, not a performance comparison or model success.

The model remains the pinned Qwen2.5-Coder-7B Q4_K_M; every arm has the same
8192-token context, 1536-token output limit, at most three submissions, a
900-second request deadline, four threads, greedy seed-zero decoding and no
prompt cache. The previous-response and feedback caps remain 1664 and 1024.

The additive allocation is not a theorem about arbitrary tokenized text. Every
actual rendered request is checked again, and a history/context overflow can
end the cell as a retained budget failure. Three submissions is a maximum, not a
guarantee under every possible response or timeout. Previous source code is not
truncated or auto-merged, and public resource/case flags are not removed.

## V8 remains a separate, failed qualification with retained cost

V9 is explicitly registered as an adaptive follow-up after observations and an
independent contract-disclosure audit. It does not assert that the omission
caused the earlier failures or that the two added rules will make the model pass.

The complete V8 result is **1/3 qualification tasks correct**, with **8/8** complete
requests/responses and no unknown residual usage:

| V8 task | Submissions | Actual outcome |
| --- | ---: | --- |
| Scalar | 2 | First failed real Rust type checking; second passed public and terminal hidden gates. |
| API migration | 3 | The same 2072-byte, 790-token answer was repeated three times; complete functions were placed into type nodes and rejected before overlap checking. |
| Ownership repair | 3 | The same 794-byte, 280-token answer was repeated three times; trailing tokens outside expression fragments were rejected before overlap checking. |

V8 consumed **19014 input + 3398 output = 22412 tokens**, including failed
submissions. Only the scalar task reached one public and one terminal hidden
native execution. No main cell or HIA model cell started.

The separate independent raw-accounting review at
`103218400fa2ce6e6fa4196b1be924be0d819147` checked all eight actual request token
lists, retained SSE texts/token IDs, final evaluated/predicted counts, usage
records and per-cell costs. Its receipt SHA-256 is
`4f641c0c8121599ac413be901b8955696ff9ceb7702976e72329df3b91c3a8a4`.

Recorded V8 phase costs are 64.003405956 seconds for capacity/reference controls,
2059.597590950 seconds for qualification, and 5.690141661 seconds for the refused
main invocation. Their sum is **2129.291138567 seconds**. This is a sum of the
three measured phases, not all historical development labor, model acquisition,
or total project cost.

Those outcomes measure this model's behavior with these interfaces and budgets.
They do not establish general Rust weakness or HIA efficiency. They are not
reclassified, omitted from costs, repaired offline, or inherited as V9 eligibility.

## Separate unified-source CI selector review

The independent reference-only CI wrapper at
`d7f39c21820237defa285aa54dd8c0e30fc05b7d` was reviewed separately. Its finite
`study_version` parameter selects one support module for a run and passes it
explicitly through source binding, registry, session, snapshot and every identity
boundary. It does not rebind a module global, and the default remains V8.
The receipt records the selected version and the actual selected protocol
schema/hash. Both versions keep the same reference builder and evaluator.

No blocking selector issue was identified. This is static review only; it does
not assert that this particular frozen CI commit has completed native tests.
CI reference success cannot satisfy tokenizer capacity or model qualification.
The CI source and the frozen V9 model-study source retain their distinct commit
identities.

## Retained evidence

`experiments/hia_next_safety/toolstudy_v9_review_20261029/` contains the staged
preflight decision, final independent capacity audit, unmodified producer
capacity/test receipts and log, independent V8 accounting receipt, CI-selector
static review, executable standard-library audit, and digest index.

This review allows one fresh qualification. It contains no V9 model outcome and
does not establish a language, general productivity, long-term maintenance,
whole-language safety, physical-machine or production-optimization claim.
