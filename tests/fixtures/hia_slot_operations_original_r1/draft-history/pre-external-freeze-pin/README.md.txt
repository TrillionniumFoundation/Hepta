# ROOT execution handoff: original-only Slot SQL reconstruction

This is a new, unexecuted revision. The old post-K 270-case oracle was lost and
is not reconstructed verbatim. The actual new input list has **248 cases**.
All original 15 Store methods, all 15 SQL sites and the entire original 15-test
module are preserved in source snapshots. See DESIGN.md for scope and limits.

Only ROOT may execute the following originals-twice plan after the static
handoff is admitted. It launches fake-provider originals, not product tests,
real SQLite, native code, a VM, a compiler or a candidate.

## Inputs and outputs

- cases.json: all fixed inputs, no expected observations.
- originals/: exact source snapshots and extracted original class/helpers.
- observe_originals.py: exact AST-node execution with declared fake providers.
- run_originals_twice.py: fresh-process supervisor; 180 seconds per new
  diagnostic child, 5 seconds owned group cleanup.
- source-freeze.json: exact complete deliverable source pins; checked before
  and after every original run.
- caller-plan.json: complete existing scopes and current source identities,
  statically inventoried; no TestLoader or old test body executed.
- resource-controls.json / port-map.json: future implementation/control plans,
  explicitly unimplemented and unqualified.

The primary raw output is observations.jsonl, in all 248 declared ordered IDs.
raw-exceptions.jsonl preserves interpreter traceback diagnostics. Each
consumer snapshot is immutable before later cases/GC. post-seal-gc.json keeps
later destructor events in a separate diagnostic and never overwrites a case.
Complete command/result/stdout/stderr, runtime, source before/after, planned/
started/stopped identities and group cleanup are mandatory.

The supervisor compares all 248 original records, raw traceback records and
the separately retained final GC diagnostic **within each runtime**. It never
copies a previous runtime's expectation or edits AttributeError metadata.
All old test budgets remain unchanged; this diagnostic adds no new product
input domain limits.

## Actual known host executables

The desktop /usr/bin/python3 was observed as CPython 3.12.3 in the earlier
stdlib-only AST check, not the old cloud 3.12.14. The restored verified runtime
is /home/qian-qi/hia-recovery-20261115-0232/verification-env-py314/bin/python3.14.
Each run records its actual sys.version/executable; no version label overrides
that evidence. This handoff has not executed either interpreter's oracle.

ROOT may run separately (commands are prepared, **not executed**):

    slot_oracle_root=/home/qian-qi/hia-recovery-20261115-0232/next-slot-sql-original-oracle-reconstructed-r1
    /usr/bin/python3 -I -B "$slot_oracle_root/run_originals_twice.py" \
      --oracle-root "$slot_oracle_root" \
      --runtime desktop312=/usr/bin/python3 \
      --output /home/qian-qi/hia-recovery-20261115-0232/slot-sql-originals-py312-r1

    /usr/bin/python3 -I -B "$slot_oracle_root/run_originals_twice.py" \
      --oracle-root "$slot_oracle_root" \
      --runtime verified314=/home/qian-qi/hia-recovery-20261115-0232/verification-env-py314/bin/python3.14 \
      --ld-library-path /home/qian-qi/hia-recovery-20261115-0232/verification-env-py314/lib \
      --output /home/qian-qi/hia-recovery-20261115-0232/slot-sql-originals-py314-r1

Output directories must not exist. Any partial case list, missing raw record,
source change, fault that did not fire exactly once, unraisable callback error,
deadline expiry or residual group is HOLD. Both original attempts remain
retained even when one fails. A later observer correction requires a distinct
revision and preserved prior failure, never refreshed expected results.

These commands remove every HEPTA_HIA* and PYTHON* environment variable from
each child and use -I -B. The original fake package modules are deliberately
installed in memory; product imports/native/SQLite/process-provider calls
are rejected by the child audit guard. Only the supervisor spawns fresh Python
children.

## Work to do after original observations

First inspect the complete same-runtime originals and all weakref/deletion/
exception phases. Then implement the full 15-mode HIA graph and explicit
multi-statement series custody, preserving original dynamic callbacks and
literal SQL expressions. The existing transition-only R2 and read weak-R3
single-occurrence tap are not whole multi-SQL qualification.

Run the 14 independent real resource controls and every applicable complete
original scope in caller-plan.json. Slot 15, integration 13 (nested original
10 retained), ordinary 112, separate 128, transaction 61 (1800 seconds),
shared-component 152 and Store 130 are distinct overlapping scopes. Do not
sum them, filter old methods, weaken timeouts or expand old admin bundles.

The current selected/default release and eventual retained-body deletion
remain separate delivery work. No generated HIA, metadata, new source
contract, default bundle or production patch is supplied by this directory.
