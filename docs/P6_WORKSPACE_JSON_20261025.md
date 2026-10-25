# P6 strict JSON for immutable Agent workspace state

This P6 increment is stacked on PR #118 at `b81b0fc74e8c8780a0defe1586a389ef858c7662`.

## Change

The shared `_read_json` entry used by `CURRENT`, `snapshot.json` and `JOURNAL` now:
- Reads no more than `MAX_BYTES + 1` bytes, then rejects any oversized metadata before decoding. This avoids a separate stat/read race.
- Rejects duplicated JSON keys at every nesting level rather than applying the Python `json.loads` last-key-wins rule.
- Rejects `NaN`, `Infinity` and `-Infinity`, invalid UTF-8, excessive recursive nesting, malformed documents and non-object roots.
- Preserves structured `E_WORKSPACE_JSON` and `E_WORKSPACE_LIMIT` failure semantics. Legitimately published state remains canonical JSON and is unaffected.

The threat addressed is ambiguous or malformed on-disk metadata, **not** arbitrary malicious same-user mutation. A source-backed identity or signature for every manifest claim is a separate requirement; hashes computed by an attacker are not authenticators.

## Executed scope

An independent local strict-JSON analog accepted one valid metadata object and rejected **7/7** adversarial objects: top-level and nested duplicate keys, three non-finite numbers, array root and over-limit object. The committed tests additionally mutate real `CURRENT` and `snapshot.json` and require `pin` rejection plus restoration.

The complete Hepta workspace suite, native build/Agent patch transactions and actual model A/B runs remain unexecuted in this local runtime. No functional-equivalence proof or global Agent productivity advantage claimed; `whole_project_blockers_closed=false`.
