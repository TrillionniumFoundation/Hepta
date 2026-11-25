# Ordered native BackgroundOptimizer admission stages

This pure component preserves the constructor, submit binding and lifecycle flag checks used by the enclosing BackgroundOptimizer owner. It consumes freshly captured values and actual runtime snapshot payloads. It does not supply runtime, proof, path, evaluator or publication authority, and it does not itself start a worker.

## Private wire

The six-word HIA entry consumes disjoint views. Input starts with a 256-byte HIABAD01 header:

| Offset | Value |
| --- | --- |
| 8 | Stage 0 through 9 |
| 16 / 24 | Options raw / owned arena lengths |
| 32 / 40 | Admitted Core raw / owned arena lengths |
| 48 / 56 | Job generation / epoch decimal lengths |
| 64 | Actual HIAMVBS1 snapshot length |
| 72 | Zero |
| 80 / 112 | Captured original baseline Core / input SHA256 |
| 144 / 176 | Captured last published Core / input SHA256 |
| 208 through 255 | Zero |

The tail contains options raw, options arena, Core raw, Core arena, job generation, job epoch and the snapshot, in that order. The complete views and every length sum are validated before output. Arenas use the owned 72-byte record format and must match their raw views. Snapshot counters are full canonical decimal byte strings; they are not truncated to machine words.

Output requires at least 512 bytes. Workspace requires at least max(131072, largest arena node count) bytes. There is no additional aggregate raw-byte or fixed arena-node cap. Original Core and submit budgets remain with their existing owners.

Return zero produces HIABAR01 followed by status at offset 8, error identifier at 16, complete error JSON length at 24, and stage results:

| Offset | Result |
| --- | --- |
| 32 / 40 | max_pending / timeout_ms, or shutdown wait / cancel flags |
| 48 / 56 | Exact binary64 bridge timeout bits / original exact-int flag |
| 64 / 72 | First and second bridge value node IDs, retaining insertion order |
| 80 | Current source is original baseline (0) or last source (1) |
| 88 | Actual snapshot generation and epoch match the job |
| 96 | Function node |
| 104 through 127 | Zero |

Errors contain the original BackgroundOptimizationRejected class and full E_HIA_BACKGROUND message at byte 128. Private malformed input returns FFFFFFFD; short output returns FFFFFFFE. These framing refusals leave output unchanged.

## Required ordering

| Stage | Owner position and checks |
| --- | --- |
| 0 | After actual runtime capability type admission: max_pending, translation timeout, bridge timeout, exact two-key bridge shape. Returns bridge insertion order for real Path.resolve calls. |
| 1 | After fresh original baseline verification: exact string function and public scalar-entrypoint membership. Explicit exports, including an empty list, take precedence over inferred scalar signatures. |
| 2 | After actual runtime snapshot: original baseline binding, then tracked current source. |
| 3 | After original submit structure checks and checked freezing: objective target. |
| 4 | Fresh current-source tracking against original baseline and last published source. |
| 5 | After current-source selection: incumbent observation binding. |
| 6 | Actual open snapshot generation and epoch equality against the accepted job. |
| 7 | Shutdown flags with original exact-bool rules and defaults. |
| 8 | Original single-shutdown-owner copy refusal. |
| 9 | Original invalid-runtime-type diagnostic selected by the actual capability owner. |

The enclosing owner must perform the omitted effects between these stages. In particular, stage 0 does not resolve paths, stage 1 does not replace Core verification, stages 2/4/6 do not manufacture a runtime snapshot, and stage 5 does not attest host measurements. Runtime and last-source hashes come from the enclosing captured owner, not caller assertion fields.

Stage 6 receives the provider's actual snapshot representation: a missing selected generation has no generation byte string. It does not reinterpret an inconsistent development fixture containing a current generation ID with no corresponding selected generation record.

## Qualification

Both native compilations produced the same 380584-byte flat with SHA256 7f0bac9de47c969d637c7d0f792235fba4b247a874259303191afe1b08cfac9c.

There are 915 actual native/original method stage comparisons and 16 framing/atomic-output controls. They cover exact types and error priority; binary64 bridge endpoints, subnormals and nonfinite rejection; bridge key insertion order; all original scalar types; explicit and empty exports; exclusion of borrowed-buffer signatures; baseline/current hash combinations; original target and incumbent checks; counter equality; shutdown and copy refusal.

The wider cases use an actually verified Core with more than 131072 nodes and actual 100001-digit generation/epoch comparisons. The temporary decimal conversion override in that development harness is only for encoding the internal unbounded counter wire. It does not change the original method or a product JSON/string conversion policy.

For these pure-stage comparisons, the unchanged original BackgroundOptimizer methods are stopped or supplied controlled results only at explicit Path/Core/runtime/thread effect boundaries. That scope is recorded in the report. These gates do not constitute live whole-runtime or whole-BackgroundOptimizer qualification.

Earlier author and compiler refusals are retained. The first large label function exceeded the original per-function SSA limit and the repeated diagnostic literals exceeded the original total operation limit. Label helpers were split and identical diagnostic fragments were shared. No compiler budget or admitted business domain was enlarged.
