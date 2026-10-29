# V9: complete negative qualification, exact costs, and enforced main refusal

## Actual outcome

The one prospectively registered V9 qualification at original source
`ef9fbafabe9db52a5e59220f1738d5842ac164cc` passed **0/3 tasks**. All **nine**
requests completed and their exact usage was retained: **21,803 input + 3,479
output = 25,282 tokens**. Whole qualification wall time was
**2,261.307883468 seconds** on the shared development host. There were no unknown
usage requests, timeouts, code truncations, clipped diagnostics, omitted public
cases, human answer repairs or automatic host answer repairs.

Source, model, compiler/runtime tools and companion-library identities stayed
unchanged. The owned server exited, and a subsequent read-only check found its
recorded PID absent from `/proc`. The actual main command then rejected the result
with `E_TOOLSTUDY_NO_QUALIFIED_MODEL` before constructing an inference engine or
creating the main output directory: **zero main cells and zero main requests**.
No HIA-vs-Rust or full-vs-node model comparison was performed.

| Qualification task | Submissions | Passed | Input tokens | Output tokens | Actual earliest rejection |
| --- | ---: | ---: | ---: | ---: | --- |
| json_scalar_reasoning | 3 | 0 | 6,091 | 272 | Actual rustc rejected incompatible u32/u64 arithmetic; the three model edits did not resolve the caller's type error. |
| two_file_signature_repair | 3 | 0 | 8,017 | 2,931 | Complete function definitions were supplied to type nodes; the finite type-fragment parser rejected them before compilation. |
| owner_flow_repair | 3 | 0 | 7,695 | 276 | The complete edit set included `api.rs/touch/n21`, which is absent from the captured source catalogue; the duplicate/unknown/unauthorized-node gate rejected it before compilation. |
| Total | 9 | 0/3 | 21,803 | 3,479 | Fresh 3/3 qualification is false; main is forbidden. |

Each API reply was byte-identical across all three attempts: 2,401 bytes and
977 output tokens, text SHA256
`10b4dfba8e675eab4c1e387335d90a309ab1f5b0c4df02eb75aaaf0971a92684`.
Each ownership reply was also identical: 256 bytes and 92 output tokens, text
SHA256 `8e08e629d8d1eb6b84196816b4532225c7afc70d256c4b06292832f417a10ee9`.
The scalar replies differed but all failed actual compilation. No qualification
candidate reached public native execution or terminal hidden execution. These
are the observed tool/compilation outcomes; later functional or resource behavior
was not measured and is not inferred from the rejected source.

The actual maximum request input was 3,117 tokens and maximum output was 977.
The largest retokenized complete previous response was 976 tokens; maximum public
feedback was 821. The observed failures therefore did not come from context
truncation or exhaustion of these registered token caps. The host did not change
node targets, extract functions into fragments, delete overlaps, repair source,
install rejected candidates or use hidden observations as feedback.

## What the prospective amendment changed

V9 added exactly two independently reviewed generic contract disclosures to V8:
unique node IDs in a batch, and Rust's type/expression fragment categories plus
pairwise-disjoint spans (choose a parent or its descendants). The eight full
prompts stayed unchanged; all nineteen source queries and human reference answers
remained identical. Model, decoder, budgets, tool authority, native/resource gates,
qualification tasks and the 3/3 requirement stayed unchanged.

The amendment was explicitly registered as an adaptive follow-up after observed
V8 failures. The original V8 result at `33c46cd` remains **1/3, eight requests,
22,412 tokens and 2,059.597590950 seconds**, without rescoring or discarded costs.
V8's API failures preceded the overlap gate; V9's API failures likewise occurred
at the earlier type-fragment gate. The ownership rejection differs across studies:
V8 reached a trailing-fragment check, while V9 failed the source-node scope gate.
The two generic disclosure strings do not justify attributing these observations
to a hidden overlap check or making language-efficiency claims.

## Capacity and reference validation were independently established

Before generation, all **19** complete human reference responses passed actual
compiler/public/native/resource and terminal hidden controls. The owned server
made **zero generation requests** in these preparation controls. Actual template
renderings and exact token IDs are retained; independent pinned CLI/server IDs
matched for every complete reference response. This preparation took
**76.953562987 seconds** and is not a model qualification success.

The longest initial prompt was 2,804 tokens; the longest complete correct response
was 1,059. The largest actual control repair input plus the full 1,536-token output
reserve was 5,044. The registered allocation was at most 7,284 of 8,192 tokens.
That allocation is not a theorem for arbitrary BPE concatenations: each actual
complete request is checked again, with the whole output reserve, and a cell ends
without code truncation if it cannot fit. Three submissions remain a maximum,
not an unconditional promise after any possible response.

Forty-one post-commit static/mock controls passed: seven V9 controls, thirteen
unchanged V8 study controls and twenty-one structured-editor controls. Independent
pre-generation review `34cafc7eb0efe9e016ed7f0070414c01576bd642` checked 172 source
bindings against Git/current/snapshot bytes, the original static receipt, all
nineteen actual reference/native artifacts and retained template/token-ID data,
and the exact two-string changes relative to V8. Its initial capacity-only hold
and later explicit qualification allowance are retained separately. The reviewer
ran no model, tokenizer, native program or tests.


Independent completed-run review `757bbf37ca9b5ab70e0782579b8cd73adac9d80d`
then recomputed all nine request/SSE/token/usage histories, actual public-to-hidden
boundaries, 172 source snapshots and exact Git blobs, runtime identity records,
captured query digests, and the main refusal. It independently associated the
subsequent PID-absence receipt with the recorded engine identity. The raw ledger
passed its first complete audit; the review's own optional-field development
error and correction remain separately retained and did not alter the experiment.
The reviewer did not execute any model, tokenizer, native program, compiler or
tests. The main review receipt SHA256 is
`6e4499bd58a9bef8829e7cb60cac75d84ed71ade823bf8857c9b2d20de951ddb`.

## Complete cost and retention accounting

Transport wall time was **2,199.867711180 seconds**; the generation wrapper total
was **2,200.104980079 seconds**. Whole qualification time includes preparation,
validation, identity checks and owned startup/shutdown. The real rejected main
entry separately took **12.242381912 seconds**, with no engine construction or
model request. Capacity + qualification + rejected main entry total
**2,350.503828367 seconds**. That is a registered-study cost subtotal, not total
project development effort.

All retained V5/V6/V8/V9 model runs together now comprise **53 requests, 83,912
exactly known tokens and 6,729.857035842 seconds** of recorded experiment wall
time. Earlier V5 development/environment results retain their original validity
and source labels. This total excludes V4 incomplete/unknown residual usage,
reference controls, acquisition, human tool/protocol work and other unmeasured
costs. It is not presented as an end-to-end cost of the language project.

`SUMMARY.json` gives denominators, exact per-task costs, complete response hashes,
context maxima and the refusal binding. The raw manifests bind every original
file, including source snapshots and native images retained in the full raw
archive. Compact evidence copies preserve original text bytes and SSE records;
large images and repeated source snapshots are hash-bound instead of copied into
this compact package. Original measured commits are preserved independently of
later integration/publication commits.

## Registered stop and remaining empirical requirement

The V9 stop rule has been taken: no same-task prompt tuning or repeated old7B
experiment follows this failure. An independently capable model remains required
for a valid main comparison with these real tools. V10 is a separate, prospectively
registered single-model candidate with unchanged V9 task messages and acceptance
requirements, its own model/template provenance and fresh capacity/qualification;
none of its results can replace, rescore or erase this V9 record.

This evidence does not establish general Rust or HIA ability, relative Agent
productivity, real long-term maintenance costs, compiler/language soundness,
whole-program safety, or performance on a verified `dot` host. The observation is
bounded to the registered finite tool study on the shared development host;
`LOCAL_RUNTIME_NOT_OBSERVABLE` remains the location scope.
