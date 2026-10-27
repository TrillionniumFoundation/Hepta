# Atomic multi-site HIA edits

`hepta.hia.edit-batch-query.v2` selects up to 16 nonoverlapping value-producing
instructions by function, block and SSA output. A selection grants only a
nonempty subset of `op`, `args` and `attrs`; output identities and interfaces
remain fixed. Multi-output aliases of one instruction cannot create two sites.

The host retains the complete query and its immutable input/Core identities.
The rendered agent view deduplicates local dependencies and consumers while
retaining original instruction order. It is not another executable language
or a proof of the omitted program. Responses have this envelope:

```json
{"edits":[{"site":0,"changes":{"args":["right"]}},
          {"site":1,"changes":{"args":["left"]}}]}
```

Every selected site must appear exactly once. Unknown fields, duplicate JSON
keys, bool/float aliases of integer site IDs, overlap, stale snapshots and
excessive payloads fail. Both query reconstruction and final patching use the
same captured `VerifiedProgram`; a mutable caller dictionary is not read again
after capture. The same snapshot fix applies to the existing single-site API.

All replacements are assembled before the ordinary whole-module verifier runs.
For example, moving a shared loan from owner A to B while moving an exclusive
loan from B to A can be valid as one change, even though either intermediate
program violates borrowing. No intermediate candidate is admitted. Failure
leaves the input unchanged. Publication uses the existing no-replace path.

```sh
python -m hepta hia edit-batch-query program.json \
  --selections selections.json --output query.json
python -m hepta hia edit-batch-apply program.json \
  --query query.json --response response.json --output revised.json
```

`selections.json` is a list of objects with exactly `function`, `block`, `output`
and `fields`. Queries are capped at 1 MiB, responses at 64 KiB. Atomic editing
does not establish behavioral equivalence, native execution, cross-module ABI
safety or general agent productivity. The separately frozen maintenance study
in `experiments/hia_atomic_maintenance_20261027` measures its finite use.
