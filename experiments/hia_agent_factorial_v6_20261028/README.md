# Primitive conversion and structured public feedback, v6

V5 remains a completed failed eligibility experiment. Both pinned models passed
one of three baseline tasks; no main cell was started. Its larger model's scalar
repair used `c.into()` exactly as the real Rust compiler suggested, and the
experiment's old method whitelist rejected it. Independent metadata compilation
of the **unchanged complete Rust source and harness** succeeded. That diagnostic
does not retroactively admit a v5 answer or add a model success. The separate
owner task's omitted increment was a real semantic error, not that interface
restriction.

This prospective protocol changes two tool-interface details before new model
responses. It selects the already pinned 7B model for fresh three-task
calibration; it does not repeat 1.5B solely to reproduce its completed failure.
All v4/v5 observations and costs remain separate. Selection is adaptive and
differences between protocol versions do not identify a language or model
effect.

## Closed primitive conversion profile

The existing evaluator gains an explicit opt-in profile. A bare identifier may
receive `.into()` only if the actual function header declares that parameter as
`u8`, `u16`, `u32`, `u64`, `usize` or `bool`. The parameter cannot be shadowed.
Files using this extension cannot contain closures/bar operators or complex
`let` patterns. Container, field and expression receivers, arguments to `into`,
custom traits and arbitrary new methods remain excluded. The actual target
conversion is decided by real `rustc`; unsupported conversions receive its
ordinary diagnostic. The host never rewrites a model's source into a repair.

Every Rust file under the opt-in profile also excludes macro definitions and
dollar-sign metavariables, including files without a literal `into` call. This
closes the independent pre-inference review's macro-expansion counterexample:
`$x.into()` could otherwise resemble a scalar header parameter while expansion
substitutes a container. The earlier review source and its test log remain
development evidence; no model inference used that source.

V4 and v5 use the default old profile and continue rejecting `into`. HIA uses
the unchanged independent Core and its existing cast operations. Each language's
full/query arms retain identical edit authority, compiler tools and task gates.

## Public counterexamples

Repair feedback pairs each already public input with its already observed and
expected entrypoint/provider-probe values. Aggregate resource/VM verdicts and
real compiler/admission diagnostics remain the same. No hidden input, new
example, correct code, edit menu or task-specific solution hint is supplied.
Hidden checks run once after the first public pass and are never fed back.

The four main tasks and their hidden cases are unchanged and are not used for
tuning. The same three-submission, 2048-output-token, 8192-context-token and
300-second-per-request limits apply to calibration and all language/interface
cells. Main still requires all three complete baseline gates. The syntax-only
check/files output envelope and retained SSE transport are reused from v5.

Run `tools/qualify_hia_agent_primitive_repair.py`. Commit source and protocol
before inference. The imported fixture protocol and v5 transport implementation
are bound inputs. Models, interpreters, registered tools and source bytes are
checked at boundaries. Current-host costs are descriptive; dot runtime remains
unobservable. This small four-file corpus is not production or long-term
maintenance evidence, and query remains a context slice rather than node edits.

## Narrow profile controls

The `profile-controls` subcommand runs three no-model controls after source is
committed: a scalar parameter conversion must compile and pass actual native
functional/resource checks; the same source remains refused by the default old
profile; and a `u32` to `u8` implicit conversion must reach real rustc and receive
its unsupported-conversion diagnostic. Controls are labelled `model_answer:
false` and cannot qualify a model. The preexisting `controls` subcommand remains
available for the full reference/partial-repair matrix. Unit checks cover
parameter shadowing, closure/pattern/field/container receivers, forbidden custom
traits/methods and public-only paired feedback.
