# Hepta CFG v0 — typed structured control-flow export

The opt-in `hepta cfg` command exports a source-bound, checked structured
control-flow graph for AI agents. It is a descriptive graph, **not** a verified
MIR, SSA optimizer, independent borrow checker or machine-code translation proof.

```sh
python -m hepta cfg examples/results.hepta --frontend-only
python -m hepta cfg examples/ownership.hepta
```

## Contract

- Schema `hepta.cfg.v0` inside `hepta.cfg.export.v0`, with canonical hash
  including source bytes and project identity.
- Blocks are `bb0`, `bb1`, ... with typed expressions, source spans and
  unsafe depth. Terminators: return, goto, branch, structured_for_range,
  structured_match. For/match remain high-level, not fully desugared.
- Dangling edges, unterminated or unreachable blocks, untyped expressions,
  unknown statement kinds and post-return statements fail closed.
- Exporter limits: 4096 blocks and 16384 operations per function.
- Foreign declarations are graph-null with effects; their implementations
  remain outside the Hepta safety proof. Unsafe markers are descriptive.
- Frontend-only qualification stays frontend-only, even with a valid graph.

## Next engineering gates

1. A precise evaluation-order and drop/unwind model that represents all
   effects, including calls and foreign/unsafe contracts.
2. Typed SSA and explicit move/borrow/provenance facts, with sound verifier.
3. Differential execution semantics against the existing Rust native path.
4. Mechanized refinement proofs on a small core before optimizing codegen.
5. Independent cross-target validation and representative workload tests.

See [implementation status](IMPLEMENTATION_P0_P7.md) and
[production blockers](BLOCKERS.md). This incremental exporter alone closes
none of the whole-language safety, performance or hardware blockers.
