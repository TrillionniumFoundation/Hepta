# Capability projection and finite edge traces

The sequential capability model now includes the selection performed before a
CFG edge renames its arguments. The earlier theorem started from the already
selected closed graph. It therefore did not establish that an omitted input
was external, or that every local owner and local loan survived selection.

`formal/HiaCapabilityRenaming.lean` defines selection as a list filter. An
admitted projection must retain every nonexternal capability and keep the
selected root/parent graph closed. The subsequent name map must be injective.
These are the existing production helper's rules; this change does not change
which programs the production checker accepts.

## Properties and quantifiers

| Property | Coverage |
| --- | --- |
| Only external capabilities can be forgotten | Every admitted projection of every finite capability list |
| Local capability inventory is preserved | The complete ordered list of local `(kind, parameter-origin)` pairs, including multiplicity, through projection and renaming |
| Root/parent closure is preserved | Every admitted transfer, including transfers that discard external inputs |
| No positive parent cycle is introduced | Every admitted transfer whose initial graph has a strict natural-number parent-rank witness |
| Composition | Every finite trace made only of these admitted transfers, without a fixed trace-length bound |
| Production evidence | Every independently inventoried CFG edge in the selected artifact, exported from its actual full input, name map and observed output |

The generic rank transport uses the injective name map to transfer the previous
rank witness. A parent step strictly lowers its rank; induction on a positive
parent path excludes a cycle. Projection removes nodes but cannot manufacture a
parent relation. A separate induction over edge traces preserves the local
inventory, closure and existence of parent ranks.

The local inventory theorem is stronger than a count equality: changing a local
capability's kind or formal parameter origin also changes the observed inventory.
The existing relational renaming theorems still preserve individual names,
roots and parent relationships. The theorem does not assert that two different
resources with the same kind/origin pair have the same identity.

## Actual production witnesses

`tools/verify_hia_capabilities.py` now encodes **all** capabilities supplied to the
production helper, including external values that are later forgotten. The
full input, selected name predicate and observed output use separate before
and after SSA namespaces. The name map is derived from the observed remap and
is never reconstructed from output fields.

For each edge the Lean kernel independently checks the literal full-input
selection, local retention, selected graph closure, exact observed output,
and a strict parent rank for the full input. Generic theorems then establish
the edge's local inventory equality and output acyclicity. The full-input rank
profile rejects missing parents and cycles even in discarded external nodes;
such artifacts remain outside this proof profile instead of receiving a
partial whole-input claim.

The generic report is version `hepta.hia.capability-renaming.proof.v2`; the
production witness is `hepta.hia.production-capability-witness.v3`. Older
reports retain their original, narrower scope. Generic negative controls now
also remove the local-retention premise and weaken strict parent descent.
Lean must reject both modified models at their intended theorem. Existing
root, parent, kind and origin controls remain mandatory, as do all actual
output-field mutations and independent Python/Rust whole-Core refusal cases.
Two additional controls change only an exported selector or rank certificate:
the selector discards a local capability, or every parent rank becomes zero.
Observed input/output lists remain identical. The kernel must reject these at
the projection or initial-rank theorem, so the new premises cannot be accepted
solely because the Python exporter supplied them.

## Boundaries

`EdgeTrace` contains transfers only. Allocation, loan creation, loan ending,
release, calls and other instructions inside a CFG block are not steps in this
relation. A whole-program execution can change its live local inventory at
those instructions. Consequently the generic trace theorem cannot be reported
as a proof that every production instruction or every legal Core program is
type- and ownership-safe. Nor does observing every static edge prove that the
production interpreter refines the model for all inputs.

The Python-to-Lean exporter, production verifier, individual instruction rules,
native lowering, FFI, concurrency, device permissions and recovery remain
separate obligations. Capability ranks are mathematical witnesses, not machine
addresses, reference counts or runtime budgets. No execution permission or
release certificate is created by these results.

## Reproduce

Use the repository's SHA-pinned Lean 4.19.0 and a fresh output outside the source:

```sh
python -B -m unittest tests.test_hia_production_capability_witness tests.test_hia_capability_flow tests.test_hia_capability_identity
python -B tools/verify_hia_capabilities.py --lean /absolute/lean --output /outside/source/capability-model.json
python -B tools/verify_hia_capabilities.py --lean /absolute/lean \
  --production-output-directory /outside/source/capability-production \
  --rust-shadow /absolute/hia-core-shadow --rust-shadow-sha256 ACTUAL_SHA256
```

Production qualification additionally requires a clean committed source and
the independently checked Rust verifier/VM built from that combination. The
receipt retains exact inputs, generated Lean, all kernel output, actual VM
observations and rejected changes. A failed proof or incomplete dependency
inventory does not produce a passed qualification.
