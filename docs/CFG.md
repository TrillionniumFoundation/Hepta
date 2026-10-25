# Structural CFG extraction (`hepta.cfg.v0`) — P1 incremental qualification

This stage is a **typed, deterministic, inspection-only** control-flow graph
built from `hepta.hsir.v0` after the existing checker accepts the source.
The `hepta cfg` command also requires the regular pinned Rust native reference
gate before returning a checked snapshot. This is **not** SSA, a new backend,
an independent borrow checker, a formal soundness proof, or a proven semantic
correspondence with machine code.

## Semantics represented

- Stable per-function basic-block IDs, terminators and successor edges.
- Conditional branches with typed conditions; exhaustive match arm patterns.
- While-loop backedges and half-open for-range edges, with explicitly one-time,
  left-to-right bound evaluation (abstract `range_init`).
- Explicit returns, fallthrough, and retained unreachable source statements.
- Typed expression trees from HSIR; source spans, lexical unsafe depth, effects,
  resource contracts, ABI/direction and external assumptions.
- Deterministic JSON and SHA-256 identities tied to the HSIR source snapshot.
- Bounded block count/nesting and fail-closed rejection of unknown statements,
  missing typed expressions, malformed nodes and invalid edges.

`range_next` is abstract: it is not a numeric SSA induction variable or
executable code. `unsafe_depth` records lexical unsafe regions; it is not a
proof that operations inside them are valid. Source expressions remain typed
trees, rather than being lowered to sequenced three-address instructions.
No value numbering, dominator/phi analysis, pointer provenance, loan identities,
effect inference or independent memory safety check is claimed. Source hashes
detect changes, not a malicious compiler. Foreign contracts remain assumptions.

## Reproduce

~~~sh
python -m unittest discover -s tests -p test_cfg.py -v
python -m hepta cfg examples/parser.hepta > /tmp/parser-cfg.json
python -m hepta cfg examples/results.hepta > /tmp/results-cfg.json
~~~

The CLI refuses frontend-only/native-skipped success. The snapshot's
`reference_validation` reports the exact native validation status, compiler,
checks and backend identity. Re-run the complete 13-gate release qualification
on the **final** commit; the Hepta 0.2 reference report does not qualify it.

## Next acceptance gates for HSIR v1 / HMIR

1. Formalized branch semantics and effectful expression sequencing, including
   abort paths and defined overflow behavior.
2. Dominators, SSA construction with join/loop phi nodes and critical edges.
3. Ownership/move/drop, region/lifetime, pointer provenance and capability
   tracking on all CFG paths, plus adversarial negative examples.
4. Differential interpreter and Rust/C backend refinement tests, and
   independently checked proofs for a qualified core.
5. Native object/ABI checks and host/target execution; hardware and independent
   backend safety qualification remain separate.

**Blocker state:** P1 PARTIAL; P2–P7 and P01–P12 remain OPEN/PARTIAL.
Whole-project blockers are not closed.

## Deterministic dominance analysis (`hepta.cfg.analysis.v0`)

`hepta.cfg_analysis.analyze_cfg` validates structural CFG successor edges,
canonical block IDs, complete entry reachability, and computes dominator sets,
immediate dominators, dominance frontiers and natural loops/backedges. It
fail-closes on malformed edges/terminators and bounds the analysis to 512 blocks
per function. `python -m hepta cfg-analyze examples/parser.hepta` runs after
the same pinned Rust native reference gate. No executable SSA, phi nodes,
independent ownership, Drop or provenance checking is claimed.

Run `python -m unittest discover -s tests -p test_cfg_analysis.py -v`.
