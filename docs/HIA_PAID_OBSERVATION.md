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
