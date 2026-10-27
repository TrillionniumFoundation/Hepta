# HIA P5: exact-CFG block-argument SSA query visibility

**Based on:** PR #308 exact `8dec804bcaa747c8fba90e80043541e5a91d9869`.
**Authority:** unchanged `hepta.hia_program.verify_program` and existing
`hepta.hia_edit_query.prepare_edit` / `hia_edit_batch` editor. This is a
read-only presentation/Agent context feature, NOT a new HIA IR or checker.

## The actual context gap

The existing compact Agent query closed value uses *inside the selected basic
block* and displayed its terminator. After `jump middle(%value)`, the model
could not see that `middle(%arg)` multiplied the value and subsequently
forwarded it through another basic block into a return. A textually small
edit could be statically valid but behaviorally wrong, and a model relying
on this incomplete view could not reason about the downstream expression.

## Implemented delta

- Follow **only the verified SSA block-argument edges** of jump/branch.
  For each affected target block input, traverse all later instructions
  transitively by explicit SSA operands and propagate their outputs.
  Joins and downstream cycles use monotone unions: a downstream loop with
  unchanged affected inputs reaches a finite fixpoint and is displayed once.
  Affected SSA cycles returning to the *selected block* refuse the compact
  view instead of falsely claiming it is complete.
- Include displayed consumers, the producer closure for their other inputs,
  block parameter identities, and full successor terminators. Retain the
  already-existing 256 visible-op bound **across all blocks**, and enforce
  the 1 MiB query cap at prepare time, not only when applying/rendering.
- Carry the same context through the existing batch presenter with stable
  deduplication of instruction indices and conflict refusal.
- Keep `apply_edit` and `apply_batch` on the same captured Core and normal
  full-module re-verification before any candidate publication.

## Limits are explicit

This is an **explicit-value dataflow** slice. It does not prove control
dependence, external call behavior, hidden-memory aliases, concurrency,
functional equivalence, performance or cross-module impact. Affected branch
conditions are identified, not automatically expanded into a guessed
transitive control-dependence closure. Users needing those semantics should
select the full-module edit path. The Rust/LLVM backends and HIA ISA are
untouched; no new proof claims are granted.

## Verification plan / results

```sh
python -m unittest tests.test_hia_edit_cfg_context \
  tests.test_hia_edit_transitive_context tests.test_hia_edit_query \
  tests.test_hia_edit_batch tests.test_hia_context_render_input -v
python -m unittest tests.test_hia_program tests.test_hia_program_tools -v
```

Independent CPython 3.13 executable pure-helper controls exercised a
two-hop linear edge chain, branch join and returning selected-block backedge.
They passed, but are **not** actual complete-checkout verifier/VM/native runs.
The new in-repository regression file is committed as acceptance input and
has not executed on this exact Git HEAD in this environment (GitHub DNS
and full checkout unavailable). No CI queue status is used as a development
stop; no green status is inferred.

**OPEN:** whole compiler soundness/Memory SSA/Provenance, general C/C++ L2–L3,
cross-toolchain ABI, production p99, true held-out Agent A/B, physical DMA/
GPU/IRQ and signed Final-use eligibility. `whole_project_blockers_closed=false`.
