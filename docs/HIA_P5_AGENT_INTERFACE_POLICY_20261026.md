# P5 HIA Agent patch interface-policy gate

## Problem and explicit boundary

Standalone `hepta.hia.patch.v1` ran complete HIA Core verification, but this
only established internal type/CFG/resource validity. A valid `replace_function`
could change a function's argument signature, return shape or declared effect
without the Agent explicitly authorizing an externally observable API change;
a valid `add_function` similarly expanded the module's exported interface.

## Implemented

- v1 requests keep the existing exact three-field wire protocol and remain
  valid for **interface-preserving edits**. A v1 attempt to change any function's
  name inventory, parameter names/types, return types or declared effects
  deterministically rejects with E_HIA_EDIT.
- v2 requests require all of `schema: hepta.hia.patch.v2`,
  `expected_sha256`, `interface_policy`, `edits`. No unknown fields.
- `interface_policy: preserve` is fail-closed, even if the new candidate
  remains a completely verified and executable HIA Core.
- `interface_policy: migrate` explicitly permits a changed function
  contract, **after** the existing whole-program independent Core verifier
  checks all participating HIA code. This does not validate external
  callers absent from the submitted module.
- v2 receipts use `hepta.hia.patch-result.v2` and report the exact declared
  policy, changed function identities, explicit `interface_preserved`
  and **false** `external_callers_revalidated` claim.
- Existing version-bound source identity, overlapping edits, prepublication
  rejection and artifact no-replace publication stay intact. No second
  parser, checker, migration engine, native backend or resource IR is created.

For example:

```json
{
  "schema": "hepta.hia.patch.v2",
  "expected_sha256": "<existing program SHA-256>",
  "interface_policy": "migrate",
  "edits": [
    {"action":"replace_function","function":"increment",
     "definition":{"name":"increment","params":[],"returns":[],
                   "effects":[],"entry":"entry","blocks":[]}}
  ]
}
```

The example shows the **request shape only**; the empty block list is
deliberately invalid and must be rejected by the existing Core verifier.

## Tests and remaining blockers

`python -m unittest tests.test_hia_interface_policy tests.test_hia_program_tools -v`

The focused new tests cover legacy body-edit acceptance, changed effects and
return signatures, added exported functions, explicit migration receipts,
stale program identities, malformed policy types and v1 unknown fields.

A successful policy-aware patch is **not** functional equivalence, downstream
API migration, formal soundness or measured AI-agent benefit. A real P5
closure still requires multiple actual Agent models, frozen tasks, fair
baselines and exact token/time/error accounting. P0–P7 remain OPEN/PARTIAL;
`whole_project_blockers_closed=false`.
