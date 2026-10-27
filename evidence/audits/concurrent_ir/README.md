# Independent concurrent resource IR review

Reviewed source commit: `b31c3cc` (the complete SHA is recorded in the reports).
The audit is scoped to normal-exit Task/TaskGroup join obligations, Buffer
transfer and the source lowering that exposes those operations. It does not
prove runtime scheduling, budget enforcement, data-race freedom or compiler
refinement.

## Reproduced defect and repair

The original lowerer checked a group before evaluating later call operands,
and checked an indexed Buffer before evaluating the index. A later expression
could join/drop that same owner. The graph then omitted the actual subsequent
use. Six source counterexamples passed the frontend and old concurrent IR;
the existing Rust native gate rejected every one, so these cases did not
produce accepted native artifacts.

The repair evaluates scalar/output operands before emitting the group or
sender operation. Indexing rechecks its Buffer base after index evaluation.
Ordinary assignment continues to evaluate its right side before the target;
this follows the generated Rust assignment's evaluation order, as specified
in the [Rust Reference](https://doc.rust-lang.org/reference/expressions/operator-expr.html#assignment-expressions).
Function calls already validate resource arguments after all arguments are
evaluated; an explicit regression retains that rejection.

| Check | Reviewed source | Repaired source |
| --- | ---: | ---: |
| Invalid operand-order sources unexpectedly accepted by concurrent IR | 6 / 8 | 0 / 8 |
| Invalid sources rejected by actual Rust checking | 8 / 8 | 8 / 8 |
| Valid neighboring sources accepted by both checks | 5 / 5 | 5 / 5 |

The eight invalid sources include timeout, both selected groups, budget
configuration, Buffer indexing, assignment-index effects, assignment-RHS
effects and a later call argument consuming an earlier borrowed argument.
Five valid controls retain independent resources, completed reads and a
nonconsuming loop condition. The tests additionally retain the full existing
15 graph mutations and add 20 malformed/scope controls. Both new selection
and shared-budget examples lower and verify successfully. A fresh process
confirms that the standalone verifier imports neither parser nor checker.

## Evidence and replay

- `cases.json` contains every exact reviewed source.
- `before-b31c3cc.json` and its `.graphs/` directory record the clean reviewed
  checkout, compiler SHA-256, four implementation file hashes, graph hashes,
  native toolchain identity and actual native diagnostics.
- `after.json` and its `.graphs/` directory record the fixed files with their
  exact hashes. The Git commit field remains the common base because this
  report was generated before committing the repair; the implementation
  hashes distinguish the reviewed and fixed sources. No report was relabeled.
- `tests/test_concurrent_ir_audit.py` carries executable source and graph
  regressions. `replay.py` can target either checkout explicitly:

```sh
python evidence/audits/concurrent_ir/replay.py \
  --checkout /absolute/path/to/checkout \
  --output /absolute/path/to/new-audit.json
python -m unittest tests.test_concurrent_ir tests.test_concurrent_ir_audit
```

The replay refuses to overwrite evidence. Its output reports the number of
counterexamples; a completed replay is not itself a whole-language safety
qualification. Source-to-IR refinement remains unproved. The concurrent IR
checks owner presence at the operation, not full expression-scoped alias or
borrow exclusivity; the sequential resource IR and native Rust gate retain
their respective additional checks.
