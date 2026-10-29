# Fresh v6 qualification: 1/3, main forbidden

The fresh pinned 7B run used reviewed source
`f695384324d2de784f727d349bd67891f7f45bd3`. It completed all three original
baseline tasks and all eight requests. One task passed the complete finite
native/resource/hidden gate. The required three out of three gate remains false;
no main cell or main model request started. The actual main selection function
also refused the completed receipt with
`E_FACTORIAL_BASELINE_CAPABILITY_UNQUALIFIED`.

| Baseline task | Submissions | Recorded result |
| --- | --- | --- |
| Scalar reasoning | 2 | Correct; complete terminal hidden gate passed |
| Full-width API upgrade | 3 | First real compiler rejection, then two primitive-conversion profile refusals |
| Owner flow | 3 | Three entrypoint interface refusals |

The run consumed **7,151 input tokens and 1,458 output tokens, 8,609 total**, with
**796.357656461 seconds** of recorded experiment wall time. All eight responses
have validated complete token usage and retained SSE bytes. Unknown usage,
human answer repairs and first-submission successes are zero. Source, model and
tool identities stayed stable; every owned model process exited. A short disk
pressure incident during a separate worktree checkout was resolved by sparsely
checking out that new worktree. No model/raw evidence was removed, no transport
was incomplete and the final observation remains valid. Timings are descriptive
on the shared available host, not verified dot or a language-performance result.

## What the failures mean

The scalar task is a new observed success under the prospective v6 profile; it
does not rescore the old v5 reply. The API task's first source multiplies two
`u32` values with `wrapping_mul` while declaring a `u64` return, and the real
compiler reports E0308. Its next two replies put `into` on an arithmetic result
and a provider call. Those receivers are outside the already registered narrow
bare-scalar-parameter profile, so the replies are refused without source edits.
They also retain the source-level full-width multiplication issue. The recorded
outcome is a profile refusal; no unrun hidden failure is invented or counted.

Each owner-flow reply changes the required entrypoint parameter `b:u32` to
`b:u8`. The unchanged interface gate refuses all three. The replies use the
returned owner but still omit the requested increment. No automatic or human
repair was applied. These are the actual outputs of this model/interface
combination, not a general statement that the model cannot write Rust.

## Independent review and controls

Source `13bc60891943781ef3d36f334d3bfcb68c607c06` and its 29-test log are retained
as pre-review development evidence. Before any v6 model inference, independent
review found a macro-expansion hole: a literal `$x.into()` could resemble a
scalar parameter while substitution supplied a container; another variant hid
the method name in a metavariable. The final opt-in profile rejects macro
definitions and dollar-sign metavariables in every Rust file before looking for
literal conversion sites. Both complete negative examples are tested. Default
historical v4/v5 profiles were not changed.

Final source `f695384` passed 30 post-commit static controls and independent
review `a1adf74`. Three actual native/profile controls then passed on that same
source: a legal scalar conversion compiled and executed correctly, the default
old profile still refused it, and an unsupported `u32` to `u8` conversion reached
real rustc and received E0277. Their full receipts, source bindings, generated
sources and compiler diagnostics are included. Those controls made zero model
requests and are never counted as Agent successes.

`SUMMARY.json` reports the formal totals; `RAW_MANIFEST.json` hashes the original
run and control files. The compact evidence contains exact prompts/responses,
streamed token records, native validation and generated text sources. Full raw
implementation snapshots and native images remain in the named original
directories for archival; their hashes remain in the manifest.

## Next interface remains a separate study

V6 jointly changed primitive conversion admission and the layout of already
public counterexample feedback. Its difference from v5 does not isolate either
change, model competence or a language effect. The whole-function query context
is still not a node editing interface, so a main run under it would not answer
the user's requested full-program versus real structured-edit question.

A separate engineering branch now implements actual revision-bound HIA node
batches and finite Rust expression/type edits. It must first pass static/native
controls and actual pinned-tokenizer capacity checks. Any future qualification
must run under those real tools and freshly pass three out of three complete
baseline gates. Eligibility is not inherited from v6, and reference controls
cannot substitute for model output. No new main cohort is counted here.
