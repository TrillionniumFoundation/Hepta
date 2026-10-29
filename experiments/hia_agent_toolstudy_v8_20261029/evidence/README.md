# V8 real-node Agent qualification and capacity evidence

## Outcome

The fresh pinned 7B model passed **1/3 qualification tasks** under original source
`33c46cdef12c60faf0c1dbef02ea20caa3ad7d56`. All eight requests completed with exact
usage: **19,014 input + 3,398 output = 22,412 tokens**. The complete experiment
wall time was **2,059.597590950 seconds** on the shared development host. There
were no unknown-usage requests, timeouts, code truncations or human answer repairs.
Source, compiler/runtime tools and model identities stayed unchanged; the owned
server exited. The actual main command rejected this qualification before creating
its output directory or constructing an engine: **zero main cells and zero main
model requests**. No HIA model comparison was performed.

| Qualification task | Submissions | Correct through hidden/resource gate | Input tokens | Output tokens | Actual outcome |
| --- | ---: | ---: | ---: | ---: | --- |
| json_scalar_reasoning | 2 | 1 | 3,574 | 188 | Actual rustc rejected u64 + u32, then the model's node edits added a cast and passed public/hidden/resource gates. |
| two_file_signature_repair | 3 | 0 | 7,505 | 2,370 | Whole function definitions were submitted as type fragments; the finite parser rejected them before compilation. |
| owner_flow_repair | 3 | 0 | 7,935 | 840 | Assignment/let/drop statements were submitted as expression fragments; the parser rejected trailing tokens before compilation. |
| Total | 8 | 1/3 tasks | 19,014 | 3,398 | Fresh qualification is false; main is forbidden. |

Each API response was byte-for-byte identical across its three submissions, with
text SHA256 `03c92c5e2fce541959e3dd66c3493e9f7349d264e48a73e5615527ba04252ecb`.
Each ownership response was also identical across its three submissions, with
text SHA256 `bed9d4b42dd651c4bbd0a6c874cdafd875e6e8d6d8598f7a577d65617fb95313`.
The full retained responses, not partial-generation impressions, establish this.
Neither failed task reached hidden execution. These are failures to use the
registered structured tool correctly; they are not observations that the complete
Rust language or memory-safety guarantees failed. No host changed a node target,
converted a whole function into edits, removed overlaps or repaired the source.

## Capacity and engineering are separately established

Before generation, all **19 human reference responses** passed actual compiler,
public, resource and terminal hidden controls and fit the output/context limits.
The owned server performed zero generations in those controls. Exact server and
independent pinned CLI token IDs matched for every complete reference response.
The complete initial/repair renderings and token IDs are retained. The reference
control run took 64.003405956 seconds and cannot qualify the model.

The longest initial prompt was 2,758 tokens; the longest complete correct
reference response was 1,059 tokens. The maximum actually observed control repair
input plus the full 1,536-token output reserve was 5,001. The registered allocation
envelope was at most 7,238 of 8,192 context tokens. This allocation is not a theorem
for arbitrary BPE concatenations: the runner checks every actual complete rendered
request and reserves the entire output budget, ending a cell without code
truncation if it cannot fit. Three submissions are a maximum, not an unconditional
entitlement to three repair opportunities after any possible model output.

During the actual qualification, the maximum request input was 2,884 tokens, the
maximum output was 790, the maximum retokenized complete previous response was
789, and the maximum public feedback was 645. No diagnostic was clipped. Thus the
observed format failures did not result from context truncation or these token
caps. The prospective limits were the same in qualification and all planned arms.

Thirty-four post-commit static tests passed, including the original 21 structured
editor controls and 13 new study controls. The V7 engineering results at original
commit `677a15928c1dd3b236c7bee8cf4b3e6041177f6c` remain separately attributed:
51 tests and nine real transaction controls (five accepted, four expected refusals)
with zero model requests. Those controls are not Agent successes either.

## Independent review and the prospective disclosure issue

Original independent method review
`f52d45996917b281140967d11c7cf4871a0f2412` checked 166 source dependencies against
Git/current/snapshot bytes, static receipts, all 19 actual native artifacts and
reference/public/hidden/resource receipts, and the retained template/token IDs.
It did not rerun the model, tokenizer, native programs or tests. A review finding
about inference companion libraries was repaired before these formal controls:
`33c46cd` binds the sorted actual server/tokenizer companion library inventory
across capacity, qualification and main; `5bba97e` remains pre-review and unmeasured.

Later independent addendum `0201a6e56f334106c56134f350a3689f74c7ab7a` identified a
presentation omission: the node prompt did not explicitly state unique node IDs
and pairwise-disjoint Rust spans (choose a parent expression or its descendants,
not both). The catalogue's raw spans do not by themselves describe that API rule.
The minimal two-string candidate under `prospective-unapplied/` is **not applied**
to this source or this result. It adds only general tool-contract information,
without examples, target nodes, answers, accepted-language changes or automatic
answer repair. Any future main comparison requires prospective registration and
fresh qualification under its final disclosed contract.

The API replies in this run actually failed the earlier type-fragment check, and
the ownership replies failed fragment parsing; no reply was rejected at the
span-overlap gate. The omission therefore does not retroactively explain away or
reclassify these observed failures. All costs and old results remain retained.

## Cost and provenance limits

The complete V5/V6/V8 retained model runs total 44 requests, 58,630 exactly known
tokens and 4,468.549152374 seconds of recorded experiment wall time. Earlier
V5 development runs retain their separate validity/source labels. This sum
excludes V4 unknown residual usage, reference controls, acquisition, human/tool
engineering and other unmeasured costs; it is not an end-to-end project cost.
The actual rejected main-entry check separately took 5.690141661 seconds and
started no model or main cell. Source/model hashing, process startup/shutdown,
validation and feedback preparation inside the qualification are included in its
whole-run time and retained separately in raw records.

`SUMMARY.json` contains denominators, exact costs and response hashes.
`CAPACITY_TABLE.md` lists every reference/arm token count. The raw manifests bind
all original files, including full source snapshots and native images that are
kept in the complete raw archive instead of duplicated in compact evidence.
The original source commits are retained in the source bundle with public
`2f49151ab9d8812eeb02ac2056f224f140099d76` as prerequisite. Later integration or
publication commits do not relabel these measurements.

The remaining empirical blocker is a model that can pass the complete registered
qualification with the real tools. These finite tasks do not establish general
Agent productivity, whole-language superiority, long-term maintenance costs,
compiler correctness, arbitrary resource safety, or performance on a verified
`dot` host. `LOCAL_RUNTIME_NOT_OBSERVABLE` remains the execution-location scope.
