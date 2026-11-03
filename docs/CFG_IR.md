# Hepta descriptive CFG v1 — typed structured control-flow export

The opt-in `hepta cfg` command exports a source-bound, checked structured
control-flow graph for AI agents. It is a descriptive graph, **not** a verified
MIR, SSA optimizer, independent borrow checker or machine-code translation proof.

```sh
python -m hepta cfg examples/results.hepta --frontend-only
python -m hepta cfg examples/ownership.hepta
```

## Contract

- Schema `hepta.cfg.descriptive.v1` inside `hepta.cfg.export.v0`, with canonical hash
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

## Version boundary and explicit legacy import

The descriptive export previously shared `hepta.cfg.v0` with the incompatible
scalar structural CFG. Only the structural format keeps that spelling; it
requires `status: structural_cfg_only_not_proved`, uses the existing scalar
HSIR/CFG/SSA pipeline and is not accepted by the descriptive adapter. New
descriptive exports use the distinct schema above and retain
`profile: typed_structured_cfg_not_ssa_or_verified_mir`. The outer CLI envelope
stays `hepta.cfg.export.v0`; the nested schema and its digest change. Consumers
must explicitly select the format instead of dispatching on the old name alone.

Historical descriptive exports require the explicit Python API:

```python
from hepta.flow_ir import import_legacy_descriptive_cfg

current, report = import_legacy_descriptive_cfg(
    legacy_json_bytes, source=source_text, path=original_path,
    project_sha256=original_project_identity,
)
```

The adapter reuses bounded JSON intake (8 MiB, 128 levels, 262144 nodes), rejects
duplicate keys, requires the exact old descriptive envelope/profile and false
claims, and verifies its checksum. Source text is at most 8 MiB; path and optional
project metadata are each at most 4096 UTF-8 bytes. It freshly parses, checks and
lowers the supplied closed source through the same producer, requiring canonical
byte equality of the complete payload except schema and digest. Unknown fields,
resealed semantic changes, wrong profiles and mixed structural/descriptive
envelopes reject. No format guessing or automatic import occurs.

Imports are not loaded by this API. Project-expanded exports that cannot replay
from the supplied closed source must be regenerated through the project pipeline.
The project identity remains caller-supplied metadata; its string is compared but
is not project authentication. The returned report grants no execution or
refinement authority. Both descriptive versions and the report remain rejected
by scalar CFG analysis, scalar SSA and standalone HIA admission. Historical
evidence and artifact source copies retain their original formats and identities.

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
