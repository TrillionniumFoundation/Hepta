# Paid observation before another NDU comparison

`tools/qualify_hia_paid_observation.py` is a separate, standard-library-only
mechanism study. It leaves the existing scalar and multistep protocols intact.
The [registered protocol](../benchmarks/hia_paid_observation/PROTOCOL.json)
defines ten heldout SQLite repair tasks and three matched controls. This is
synthetic task plumbing; no trained or native NDU paid-information policy is
assembled, and the result always retains NDU `NOT_RUN`.

Each task has one actual `counter_a` or `counter_b` database column. The terminal
goal is to increment every existing value by seven exactly once. Policies
initially receive the public schema prior, action fees, reward and original
budget. They receive neither a database handle nor the realized schema. A paid
`READ` launches a real Python subprocess that observes `PRAGMA table_info`.
`REPAIR_A` and `REPAIR_B` launch actual SQLite transaction subprocesses. A
separate post-terminal readback compares all rows with the arithmetic goal.
The evaluator never supplies labels to an online decision. This is trusted
same-host separation, not adversarial capability isolation.
The frozen heldout partition is withheld from policy inputs; it is not an
independently author-blinded task set. Tests may execute the same deterministic
partition, so no confirmatory generalization claim is made.

| Control | Decision rule |
| --- | --- |
| Fixed | Freeze a read-fee threshold and default repair using the shared calibration observations; use a paid schema observation when available. |
| VOI | Compare the best feasible no-read action with exact expected value after one optional paid READ. |
| MPC | Independently enumerate the complete finite action and observation tree with the same public model and budget. |

VOI and MPC can match exactly in this known finite model. The fixed family is
an explicit limited static baseline; it is not claimed to be the strongest
possible learned policy. All three controls receive the same calibration
dataset and rights. No controller receives additional model training, labels,
tool calls or hidden future outcomes. Shared calibration uses eight actual
READ subprocesses; fixed-policy fitting replays their observed schema outcomes
under the known effect model and is identified as replay, not extra execution.
The fitted strategy freezes before any heldout cell executes.

Every control gets a fresh, paired database, identical original tariff and wall
budgets, and at most one READ and one repair. Task order is fixed and arm order
rotates prospectively. Action fees are charged before dispatch, including
failed or timed-out calls. An unavailable or unknown READ stops without a
repair or retry. The registered invalid-schema control stays in all three
denominators. Wrong repair failures and successful but over-budget effects also
remain in the result. No database effect is labelled rolled back.

Synthetic tariff and reward units are distinct from measured elapsed time and
money. The report preserves actual controller, child-process, setup, evaluation
and outer cell wall times. Outer intervals include their nested operations;
nested subtotals are not added again. All shared calibration and fit costs are
recorded once. The observation-to-dispatch clock check is an admission bound,
not a hard real-time guarantee. Complete billed cost remains unknown.

Run from a source checkout into a new evidence directory:

```sh
python -B -m unittest discover -s tests -p test_hia_paid_observation.py -v
python -B tools/qualify_hia_paid_observation.py --output /absolute/new-evidence
```

The output retains exact runner/protocol bytes, all original child stdout and
stderr, process exits, public decision states, synthetic charges, terminal
evaluations, actual input/final database hashes and final SQLite databases.
Source or protocol drift during the run withdraws mechanism acceptance.
Existing output directories are refused to preserve earlier attempts.

`PASS_MECHANISM` requires the complete 10 × 3 matrix, paired inputs, charged
actions, observed compliance with every original budget, and at least one delivered cell where paid information changed the
later repair relative to its prior no-read action. It is not an NDU comparison,
production hotspot win, statistical superiority result or economic return.
An independent trained/native NDU policy, matched training and tuning, real
task provenance, heldout task outcomes and complete costs remain required for
P5 acceptance.

## Failure custody and read-only inspection

The retention-enabled runner creates databases directly inside the new output
directory. It records a campaign owner bound to the copied runner and protocol,
and gives each calibration or heldout cell a stable owner and operation ID.
Append-and-fsync journals retain the decision, charged intent, worker result and
evaluation stages. An intent is recorded before dispatch; completed calibration
observations and heldout rows receive atomic result checkpoints. Exceptions keep
the original databases, journals, completed rows and active owner available.
An unavailable effect acknowledgement remains `UNKNOWN`; a later row readback
does not authorize an automatic retry or relabel the earlier acknowledgement.

Persisting an intent consumes the same original two-second cell budget. The
runner checks the remaining time again after that durability boundary. If the
budget has expired, it raises `E_PAID_DISPATCH_DEADLINE` without starting the
worker. The campaign records `FAILED_EXECUTION`, and the durable intent,
synthetic charge and original owner remain visible. This conservative failure
path neither refunds a charged intent nor replays an uncertain operation. The
registered protocol and its two-second acceptance limit are unchanged.

Inspect an output created by this retention-enabled runner with:

```sh
python -B tools/qualify_hia_paid_observation.py --inspect /absolute/original-evidence
```

Inspection checks the retained owner/source/protocol bindings, journal owners
and sequences, recorded charges and missing/unknown acknowledgements. It reads
the existing database bytes without dispatching a worker. Existing campaign
directories and existing cell journals are refused by execution entry points;
inspection does not grant permission to resume them. Legacy evidence without
an owner capsule does not acquire one through this inspection command.

The campaign's outer wall interval includes the added journal and intermediate
checkpoint work. The cell interval retains the registered setup-through-
evaluation scope; the terminal cell receipt and enclosing campaign checkpoints
remain outside that cell interval. Final campaign result encoding/write and
outer interpreter startup/imports are still explicitly excluded. No nested
duration is added to the enclosing interval again, and complete billed cost
remains unknown. Host filesystem durability, historical execution and observed
timing are trusted; these records are not adversarial isolation or independent
execution attestation.

The focused regression command is:

```sh
python -B -m unittest -v tests.test_hia_paid_observation tests.test_hia_paid_observation_retention
```

The custody controls cover interruption after a completed effect, a missing
post-commit acknowledgement, an interrupted calibration, changed retained
source identity, and a deterministic deadline-expiration counterexample. The
two post-effect controls explicitly require their real effect preconditions to
be reached before injecting the interruption. The deadline counterexample uses
a controlled clock and a forbidden worker-dispatch mock; its result is not a
native timing or performance observation.

The earlier development suite's three failures remain recorded in
`review-evidence/hia-paid-retention-20261109/PRIOR_FAILURES.json`. That file is a
labelled transcription of the retained session outcome; the original per-case
temporary fixtures were not retained. A subsequent fresh attempt ran the same
three test bodies on the unchanged recovered source and original two-second
protocol, preserved all fixtures, and passed. This does not establish why the
earlier attempt failed. The independently found post-fsync deadline defect is
kept separate from those unresolved historical failures.
