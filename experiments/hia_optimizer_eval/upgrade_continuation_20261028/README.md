# Supplemental execution of previously unstarted upgrade cells

The original Qwen upgrade driver stopped its entire phase when its first HIA
request reached the registered 180-second completion timeout. That request is
retained as an unsuccessful registered cell. It is not a semantic wrong-answer
classification, and it is never submitted again. Its original `PLAN.json`,
`RESULT.json`, request, server log, and all measured costs remain immutable.

This supplemental driver was added **after the original registration and that
failure**. It does not retroactively make the original driver complete or pass
its scientific gate. Its only purpose is to execute the remaining registered
language/task comparisons that the outer-loop exception handler left unstarted.

## Fixed execution policy

The driver reads the original scheduled order and requires the retained request
artifacts to agree with the attempted prefix. It skips every attempted cell,
including the timed-out first cell, and executes only the remaining suffix.
Only the unique sibling `upgrade-continuation` directory is accepted; an existing
directory or an alternative output destination is rejected.

Prompts, fixtures, inputs, checker, compiler tools, model bytes, JSON grammar,
context of 8192, four threads, greedy seed 0, limit of 1536 output tokens, at most
two submissions, and completion timeout of 180 seconds are unchanged. The driver
imports the frozen compilation, execution, and public-feedback functions. Hidden
tests run once after a public-pass candidate and never become model feedback.

Each transport timeout remains an unsuccessful cell with unknown complete output
usage. The driver closes that owned server before moving to the next registered
cell; it does not use the second-submission allowance to retry the timed-out cell.
An ordinary returned response that fails public validation may use the same
already-registered second submission and public feedback. Both model families
use this identical continuation policy if their original driver leaves cells
unstarted.

The runtime amendment `LLAMA_ARG_REPACK=0` applies to every server. The actual
owned PID's allowlisted environment value, executable, model identity, and whole
runtime-file inventory are checked before its first request. Final source, tool,
model, runtime, original-record, and supplemental-driver identities are retained.
Any identity or shutdown failure invalidates the execution record and returns a
nonzero exit status. Completion of the planned coverage is separate from model
correctness and complete token accounting.

## Costs and retained failures

The original Qwen upgrade phase lasted 202,381,293,593 ns. Its timed-out request
contains 867 actual input token IDs. It has no completion response, so validated
output-token usage and measured per-request inference duration remain unknown.
The server log's last partial generation counter of 354 is retained separately;
it is not substituted for complete response usage. Missing counters in the old
summary are not treated as measured zero cost.

The supplemental `experiment_wall_ns` measures from entry into `run()` through
the final identity checks, before writing the final result. It includes model
hashing, startup, attempts, validation, shutdown, and identity verification. A
separate Bash outer `time` record includes Python startup/imports and final result
writing. The sum of original and supplemental measured phase intervals is also
reported. Neither measurement includes unquantified human labor or the time spent
designing and repairing these tools; those costs remain unmeasured. This is not a
claim of total economic cost.

All prior failures stay in the complete registered task denominator. Supplemental
results are indexed separately from the original phases and do not replace them.
Unknown token counts remain null, preventing a missing response from creating an
artificial token-efficiency advantage.

## Controls and review

`CONTROLS.json` retains the initial two focused mock controls. After independent
review, `CONTROLS-after-review.json` retains all three passing controls, including
rejection of alternative or reused continuation destinations. These are tests of
orchestration and failure handling, not model-generated successful upgrades.

The initial script is preserved under `review/`. The reviewed executable script
is bound by SHA-256 in each supplemental plan. The original frozen evaluator and
registration were not edited.
