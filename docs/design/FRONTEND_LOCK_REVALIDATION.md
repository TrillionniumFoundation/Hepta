# Isolated sequential frontend lock revalidation

This additive experiment is based on PR #637, commit
`523ecbd51574d9b224c13d0c4b665c1c9872925f`, tree
`8a05248a8513933e86846dd2cd27eec07213c620`. Every inherited source,
experiment, document and workflow remains unchanged. It does not change either
the default Hepta CLI or `experiments.frontend_cli`.

## Explicit invocation and meaning

```
python -B -m experiments.frontend_lock_revalidation check --frontend-only \
  --policy loader-experimental-v1 SOURCE [--locked]
```

The schema is `hepta.experimental.frontend-lock-cli.v1`. Existing report content
and classification remain unchanged; the envelope adds:

- `lock_revalidation`: `not_requested` for a real unlocked request;
  `not_completed` for a locked request whose observation did not complete;
  `post_analysis_observed` after the fresh lock equality, final inherited graph
  validation and non-callback finish guards all succeed.
- `atomic_snapshot`: always `false`.
- `frontend_only`: always `true`; `native_qualified`: always `false`.

**This is a sequence of observations, not an atomic snapshot or a promise that
Hepta.lock is still valid at return.** The lock is read before the final graph
validation. A checkpoint during that later graph work can replace the lock, and
the request can still return success with `post_analysis_observed`. An independent
regression deliberately demonstrates this residual race. Changes made and
restored between observations may also escape. No caller callback is added after
final owned validation. No native, overlay, default-route or sandbox authority is
introduced. Checking, emission and hashing remain synchronous and unmetered.

The observation describes lock/graph validation only. A stable locked graph with
checker diagnostics can have `post_analysis_observed` and still be rejected.
Success requires `report.ok`, no first failure, and completed observation when
locked was requested. Unknown, non-exact-string or inconsistent qualifiers fail
closed. Usage/help, constructor failure and serializer fallback conservatively
use `not_completed`; output delivery errors return 74.

## Implementation and ordering

`owner.Owner` subclasses the existing policy owner and adds `revalidate(handle)`.
Inherited `unchanged` is not modified. The operation uses one `_enter` / busy /
finally lifecycle and exact handle identity lookup. It retains the detached
private authority captured by the original load. Public `locked`, `package`,
`package_state`, source maps and bindings never choose the comparison basis.
It runs the inherited public revalidation-hook guard, then:

1. For locked authority, test `authority.package.root / 'Hepta.lock'` through
   original Ops.path. A missing/non-file lock raises original E_LOCK_MISSING.
2. Read using original Ops.read with role `lock`, then bounded Ops.json using the
   pinned JSON parser. The same context, reader, counters and policy are used.
   No second Owner, replacement ledger, full graph reload or additional package
   snapshot is constructed. JSON semantic equality with captured package_state
   is required; whitespace/key ordering changes alone are accepted.
3. Unrecorded ValueError/UnicodeError from decoding/parsing becomes original
   E_LOCK_INVALID. If a callback already recorded failure, bare rethrow preserves
   exact callback exception identity. Unequal semantic content raises original
   E_LOCK_STALE. Budget, I/O, cancellation and arbitrary checkpoint errors are
   never normalized to invalid lock. First failure remains sticky.
4. After equality, or immediately when unlocked, run the original
   modules._revalidate with the same Ops and frozen authority. This catches graph
   mutations made during the lock read and retains False/E_MODULE_RACE and I/O
   provenance semantics. Late lock errors intentionally precede graph drift.
5. Adapter finish guards run without a new caller checkpoint. Every return sets
   authoritative observation; exceptional exits reset it conservatively.

The lock helper intentionally lives outside modules._unchanged, whose inherited
catch would turn original lock diagnostics into an ordinary graph-race result.
A valid newly regenerated lock for changed source is stale against captured state.
An old valid lock plus changed source reaches the graph check and reports a race.
Missing lock wins before read admission even when read quota is exhausted.
Existing lexical binding tracking rejects lock symlink retargets, even for equal
bytes, and retains the strictest admitted role cap for aliases.

## Narrow copied boundaries

`adapter.py` copies the frozen frontend_adapter adapter, changing only the Owner
import, request observation initialization/reset/final assignment, and the final
call from handle.unchanged to owner.revalidate. Lifecycle, raw entry handoff,
exact-bool config, guards, analysis call and no-native behavior remain inherited.

`cli.py` copies frontend_cli cli, changing its adapter import, invocation/schema,
envelope observation fields, result validation and conservative fallback. The
new result validation checks exact closed-enum observation and requested-lock /
report / sticky-failure consistency. Parsing, failure serialization,
classification, primitive-only serialization and output transport stay inherited.
These local copies avoid mutating imported globals or production routing.

## Regression evidence and gate

The baseline real-pipeline reproducer accepts late malformed, deleted and stale
locks with success/0 although an independent fresh locked load rejects each with
E_LOCK_INVALID, E_LOCK_MISSING and E_LOCK_STALE. The new route rejects those same
three transitions with diagnostic/1, original diagnostic and sticky diagnostic
first failure, never a qualified success:

```
python -B experiments/frontend_lock_revalidation/reproduce.py --checkout BASELINE --baseline
python -B experiments/frontend_lock_revalidation/reproduce.py --checkout .
python -B -m experiments.frontend_lock_revalidation.gate
python -B -m experiments.frontend_lock_revalidation.gate --include-consumers
```

The exact gate enumerates unique identities and rejects skipped tests, expected
failures, unexpected successes and count drift. It retains all 811 inherited
controls and adds 70 controls (46 implementation and 24 independent review):
**881 hosted / 749 local without consumers**. Both hosted Python 3.11 and 3.12 run
all 881 twice. The dedicated workflow pins the exact baseline commit and tree,
uses its object directory as Git alternates for a full frozen-tree diff excluding
only this experiment/doc/workflow, and runs the existing 99 parser, 80 normal
loader and 813 prior-profile differential outcomes. Rust 1.90.0 and GCC are bound
for consumers. Local consumer execution is unavailable because rustc is not installed;
no local consumer pass is claimed and the no-consumer gate skips no planned test.

New controls exercise late malformed/deleted/stale/directory/wrong-schema/UTF-8
locks; initial diagnostic parity; semantic reserialization; unlocked behavior;
private authority; source/manifest/dependency/inventory/binding drift; mutations
during lock reads; sequential-observation residual race; quotas including fresh
metadata/package/path/inventory accounting and lock growth overflow sentinel;
foreign/reused/reentrant/wrong-thread/overlay refusals; cancellation and config
substitution; callback identity, read/close I/O precedence, no fallback; checker
rejection, conservative serialization and output failure. Existing controls
remain frozen rather than being rewritten to expect the stronger route.

No merge, deployment, production rollout, atomicity or total-resource bound is
claimed by this experiment.
