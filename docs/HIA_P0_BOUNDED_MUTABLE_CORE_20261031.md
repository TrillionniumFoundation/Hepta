# HIA P0 — bounded caller-owned Core snapshot before validation/encoding

## Source-exact defect

The existing `hepta.hia_program._decode` for a directly supplied Python
`dict` or `list` used:

```python
_structure(value)              # checks 262,144-node / 8 MiB limits
raw = json.dumps(value, ...)  # reads the same mutable tree again
```

A different thread could mutate the caller-owned tree after the preflight
but before encoding. This creates a **check/use mismatch**: an originally
small list can grow past `MAX_NODES`, or a scalar/string can change after
the structural guard, causing a different document to be encoded from the
one checked. A subsequent full Core semantic check does not restore a prior
structural-budget guarantee for that earlier `json.dumps` allocation.

## Bounded repair

For directly supplied built-in `dict` or `list` inputs only,
`_bounded_detached_snapshot` now creates a separate, plain JSON-container
tree **before** `_structure` and `json.dumps`.

- Iterative traversal: maximum existing `MAX_DEPTH` and `MAX_NODES`.
- Bounded fanout: each original dictionary or list is captured into an
  at-most-budget child reference list; growth during enumeration is refused
  once the remaining node budget is exhausted.
- Dictionary concurrent mutation raising `RuntimeError` is explicitly
  converted into a checked `E_HIA_FORMAT` refusal.
- Only exact built-in JSON-compatible scalar/container types are accepted.
  Non-string keys and caller cycles are rejected. Repeated, noncyclic shared
  input subtrees are expanded into detached copies.
- The **same detached tree** then passes the original `_structure` byte
  and node checks and is serialized; the full existing HIA typed SSA,
  ownership and effect verifier remains the execution admission authority.
- Immutable bytes/text input still has the existing bounded syntax preflight,
  duplicate-key refusal and canonical decoder. It does not need to capture
  another caller-owned mutable Python tree.

The repaired input domain is not claimed to be an **atomic transaction** over
arbitrarily concurrently mutated nested caller objects. It only guarantees
that once child references have been captured, the later budget scan and
canonical encoding operate on a detached tree, with no second read of
caller-owned containers. The original source can still be modified by its
producer; source-identity or external authorization needs a separate digest
bound to the submitted immutable wire.

## Reproduce and falsification cases

```sh
python -B -m unittest tests.test_hia_bounded_mutable_snapshot -v
python -B -m unittest tests.test_hia_program tests.test_hia_json_preflight \
  tests.test_hia_program_composite -v
```

The new suite deterministically mutates the **original** source inside a
patched post-structure-check boundary, before encoding. This ensures tests
do not depend on thread scheduling. Controls demonstrate:
1. A checked small dictionary whose original string later grows beyond 8 MiB
   must still encode the *captured* small document.
2. A checked small list whose original later grows beyond 262,144 nodes
   cannot bypass the snapshot node budget or change the emitted Core.
3. Caller cycles, excessive original fanout/depth, invalid scalars/keys
   fail closed.
4. Shared DAG input, bytes/text/direct-object canonical identity, actual
   scalar and resource Core programs preserve their former meaning.

This is a **P0 input-intake safety increment** only. It is not a complete
proof of the HIA checker, source-to-Core translation, LLVM refinement,
C/C++ ABI, arbitrary asynchronous cancellation, native RSS, or whole-language
resource safety. It does not close P0–P7 as a group or change native execution
authority. All original production and rollout gates remain open.
