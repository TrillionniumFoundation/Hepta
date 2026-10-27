# HIA P5: transitive SSA consumer slices for Agent edit queries

## Exact scope / source

Base: PR #296 exact HEAD `5db24bfdd074e71871bd61d4e30285f04acbce0a`.
Existing owners: `hepta.hia_edit_query.prepare_edit`,
`hepta.hia_edit_batch.prepare_batch` and canonical
`hepta.hia_program.verify_program`.
No alternative parser, compiler, SSA checker, native emitter or patch authority.

## Problem

The previous compact query displayed a selected value-producing instruction
and **only direct** same-block users of its outputs. If `a` feeds `b` and
`b` feeds `c` which is returned, the query displayed `b` and the
terminator `ret c` but silently omitted `c`'s defining operation.
This was a presentation/dataflow gap, even though whole-module patch
verification already prevented invalid SSA/ownership transitions.

## Implementation

- One forward pass over verified same-block SSA, starting from **all** outputs
  of the selected operation, computes the transitive dataflow consumer set.
  Consumers with no output are retained; they do not propagate new values.
- Existing backward producer closure is applied to the entire displayed set.
  No interblock, hidden-effect or alias safety proof is claimed.
- Each query must fit `MAX_VISIBLE_OPERATIONS=256` displayed operations.
  Overflow refuses: no silent truncation, no fabricated dependency closure.
  Agents may request full-module context instead.
- The existing batch renderer naturally deduplicates shared transitive
  consumers. `apply_edit`/`apply_batch` continue to reconstruct the
  snapshot-bound query and invoke the existing full-module patch verifier.
  Earlier query snapshots whose presentation changed reject as stale.
  The wire envelope and allowed patch fields are unchanged.

## Acceptance regressions

```sh
python -m unittest tests.test_hia_edit_transitive_context \
  tests.test_hia_edit_query tests.test_hia_edit_batch -v
python -m unittest tests.test_hia_program tests.test_hia_program_tools -v
```

Four committed native-Hepta test methods cover: two-hop consumer completeness
and irrelevant-op exclusion with actual VM result; multi-output branches;
atomic two-site batch with one deduplicated context and actual VM result; and
a verified 260-step chain rejecting presentation truncation.

An independent Python 3.13 standalone copy of the forward closure passed 4/4
synthetic graph cases (deep chain, multi-output, leaf, no consumer). These are
**not** the actual new full-checkout Hepta tests. GitHub DNS and Cargo/rustc
remain unavailable in the local container. No claim of AI productivity
improvement is inferred: held-out model A/B, total tokens and wrong-but-valid
edits remain mandatory P5 gates.

**OPEN:** complete P0–P7 qualification, canonical Memory SSA/Provenance,
source→machine refinement, C/C++ L2/L3, actual model Agent A/B, GPU/DMA/real
hardware and production p95/p99. `whole_project_blockers_closed=false`.
