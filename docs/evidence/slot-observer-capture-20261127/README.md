# Explicit Slot snapshot observation revision

The `deferred-json-snapshots-v3` component run completed all 248 original and
7,574 derived inputs on CPython 3.14.4. Both fresh original repetitions ran
before the native candidate. Every canonical observation byte agreed: zero
different cases and zero different leaves. The actual run took 182.265647
seconds, all owned children exited naturally, and source custody checks passed.

This is an explicit development component result. Its compiler SHA-256 is
`acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9`.
It is not a matching-source cold qualification, an installed whole-stack result,
or authorization to remove the previous production implementation.

## Why the observer changed

The frozen original observer implements `copy_json(value)` as
`json.loads(canonical(value))`. Encoding and decoding the consumer snapshot
creates a retained graph of dictionaries and lists between consumer release
and retained-traceback release. Automatic cyclic collection can therefore run
as a consequence of the observer's own allocation. The original final snapshot
also sets its seal count before constructing the snapshot, allowing later
finalizer events to appear both in the primary record and the late suffix.

The immutable 36-file original fixture and both finite input files remain
unchanged. The explicit v3 AST revision admits the exact original expressions,
including field values and order. It changes two snapshot expressions and moves
the two final seal bookkeeping statements into the final snapshot section.
It does not alter product operations, providers, cases, fault injection,
consumer release, retained traceback clearing, or the original explicit
`gc.collect()` statement.

The consumer capture now keeps its exact canonical JSON bytes. Decoding those
bytes occurs inside the final capture section, after all original product
release operations. The final record retains every original field and type.
Automatic GC is deferred only while taking the snapshots; prior GC state is
restored on success and on encoding or decoding failure. No collector threshold
changes or extra collections are introduced. The original-v1 CLI default remains
available for historical reproduction. The current v5 Native4 method explicitly
selects v3, and the source workflow adds seven separate regression controls.

## Evidence and retained negative results

- `v3-capture-contract.json` records seven actual regression tests, including
  exact AST changes, original GC-state restoration, encoding/decoding errors,
  immutable consumer values after subsequent world mutation, actual cyclic
  finalizers on both sides of the seal, and mixed-version/source-pin refusal.
  It also records successful exact recovery of the original terminal sources.
- `v3-independent-report.json`, `v3-component-result.json`, and
  `v3-component-driver.py` preserve the complete comparison report and the exact
  external invocation. The comparison uses the original 180-second original
  child, 1,800-second candidate/supervisor and five-second cleanup limits.
- `attempt1-independent-report.json` and `attempt1-native-diffs.jsonl` retain the
  earlier atomic-snapshots-v2 HOLD: original248 agreed, but derived7574 had 13
  different cases and 65 different leaves. `attempt1-sources.tar.gz` preserves
  the six exact changed sources needed to reconstruct that attempt from base
  `2f4ff983a41212ba8bc6a89aa9dda001610a9d89`.
- The earlier original-v1 result remains in
  `docs/evidence/branch-consolidation/slot-full-7822-v1-independent-report.json`;
  its 15 derived-case differences have not been reclassified as passing.

The successful component source pins precede the final Native4 test selector and
CI registration change in this commit. Those two changes select the same tested
v3 CLI and add its seven controls. A complete committed-source Native4 run,
including public84, handled12, admission25 and installed-worker checks, remains
required before that larger scope is claimed.

## Exact source history

The installed-distribution source relation adds only the reviewed helper-input
line and the two Native4 selector/report lines. Its original source bytes remain
fixed. Every existing source relation is retained, and reverse splices recover
the full historical files before the earlier terminal authority validates them.
The reader binds each original and candidate to the same explicit capture
version, helper SHA-256, complete product freeze, and actual command arguments.
It continues to compare every observation field without normalization.
