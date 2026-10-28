# Supplemental primary-task coverage

Granite's original primary driver completed its two format probes and started
four scored cells. The first three returned unsuccessful responses; the fourth
(`capacity_roundup_hia_full_context`) reached the registered completion timeout.
The original outer-loop exception handler then left twelve cells unstarted.

The original phase measured 339,721,728,133 ns and retained six completion requests
and five responses, including the two probes. Its timeout remains an unsuccessful
registered cell, with unknown complete output usage and unknown measured
per-request inference duration. Missing summary counters are not zero-cost
measurements. All original plans, reports, transports, logs and timing records
remain immutable.

This independent continuation was added **after the original registration and
partial model execution** to complete the coverage of the unstarted suffix. It
does not make the original experiment complete or change the failed scientific
gate. The four attempted cells, including the timeout, are never requested again.
The actual four cell request artifacts and all six transport request artifacts
must agree with the original fixed prefix; the driver does not select remaining
cells by looking only for complete responses.

The twelve pending cells retain their original order, prompts, parser, native
evaluator, model bytes, compiler and runtime identities, 77 native test inputs per
task, one attempt, 512-token output limit, 180-second completion timeout, greedy
seed 0, four threads and 8192-token context. No compiler or hidden-test feedback
is sent to the model. The original Granite upgrade phase runs to completion or
its recorded failure before this supplemental phase starts; model execution is
serial throughout.

Only the unique sibling `primary-continuation` directory is permitted. Alternative
output paths and a previously created continuation directory are rejected. Each
timed-out server is closed before the next pending cell starts. Counts of actual
requests and responses are saved before shutdown and final identity checks, so
those costs remain visible even if cleanup or hashing fails. A false final model
or runtime identity immediately stops further requests and invalidates the
execution record. Actual owned-server PIDs are checked for the allowlisted
`LLAMA_ARG_REPACK=0` condition and the complete original runtime inventory.

`experiment_wall_ns` measures from entry into `run()` through final identity
checks, before writing the last result JSON. A separate Bash outer `time` record
includes Python startup/imports and final result writing. Original and supplemental
phase wall times are reported separately and as an explicitly scoped sum. Human
labor and tool-construction time are unmeasured. Unknown output tokens remain
null; a partial server generation counter is not substituted for validated usage.

Four focused mock controls cover attempted-prefix/transport binding, unique
destination enforcement, timeout followed by a positive cell with unchanged
budgets and no feedback, and request-count preservation across shutdown or identity
failures. They are orchestration controls, not model-generated successful tasks.
Their raw output is in `CONTROLS-after-review.json`; the earlier source and controls
are also retained. The reviewed script is SHA-bound in each execution plan.
