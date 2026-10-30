# V12: public node contracts after the retained V11 failure

V11's exact Qwen3.5-4B candidate passed no Rust qualification task (0/3).
Six responses exceeded the selected node's fields; other responses also had
functional errors. Those observations and costs stay unchanged. This adaptive
follow-up fixes a generic editing interface deficiency, not a reference answer.

The new decoder enumerates **all** editable IDs from each captured public query
and the fields/types each accepts. It does not choose nodes, replacement values,
operations or an answer. Read-only nodes and extra fields cannot be requested
through the new node grammar. Rejection diagnostics identify public allowed and
received field names without echoing replacement code. Full-file response syntax
is unchanged. Rust and HIA use the same catalogue-derived construction rule.

The decoder is not an admission authority: duplicate/overlapping Rust edits,
whole-function fragments, type errors, ownership violations, stale revisions,
wrong public results and failed native/resource gates still reject. Capacity
controls additionally check every complete reference response against the public
schema. That check is not native grammar execution or a model success.

V12 reuses the V11 runtime/template pin, exact input tokenization, stream usage,
finalization, public feedback clipping, source/identity checks and native gates.
Initial task messages, examples, model, seed, three-submission limit, 1536-token
output reserve and 8192-token context are unchanged. No model answer is repaired
or merged by the host. The source and protocol must be committed before any
generation, with fresh 19-row capacity, 95 CLI tokenizer comparisons and 3/3
qualification. Main remains unstarted on failure. All new costs belong to V12.

This is an adaptive same-task engineering experiment. Even a positive small
main study would be descriptive, not independent replication or evidence of
general AI developer productivity or long-term maintenance superiority.
