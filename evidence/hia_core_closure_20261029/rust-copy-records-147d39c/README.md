# Raw Rust Copy-record candidate: frozen local, peer and public evidence

The candidate implements native nominal admission for an explicit raw
`hepta.hia.composite.v1` subset: monomorphic Copy records with scalar, nested
or empty fields. It preserves nominal/SSA identity before erasure and derives
public scalar entries from original signatures. It reuses the existing v6 Core,
primitive checker and bound-v4 Machine. General composite input, generics,
resource fields, later composite schemas and production eligibility remain open.

## Distinct evidence identities

| Origin | Actual source commit |
| --- | --- |
| Original frozen local required gates | 505dd0435d48b687f97daba5dc9771c1473ba8a1 |
| Independent peer controls | 505dd0435d48b687f97daba5dc9771c1473ba8a1 |
| Fresh public required gates | 147d39c4a9d3ded00fb5d22439493bc006a8b76d |

Both component commits have exact tree `2050ec5e447ae5191ac2e685ba463292b2d2d3fe` and public parent `99cf106586509b08bb2b9890ed29cf042336d69e`.
The source export has 15 changed files; its UTF-8 bytes, raw Git blobs and modes
match the fetched public tree. The full-index patch independently recreated
that tree from its public parent using an isolated index. Raw commit objects
and both publication/readback snapshots are retained. No local or peer result
is relabeled as a public execution.

## Actual public focused gates

| Gate | Denominator and retained observations |
| --- | --- |
| Entire Rust crate | 96 tests / 19 harness-result blocks |
| Raw-record collector | 9 methods; 13 exact Core/export comparisons, 43 executions, 47 refusals; 103 native processes |
| Bound-v4 collector | 8 methods; 155 observations, 37 raw refusals, 72 legacy comparisons |
| Composite-v4 collector | 13 methods; 153 Rust observations, 4 raw Rust refusals, 31 native calls |
| Related source/protocol/workflow guards | 20 methods |

All required methods passed without failures, errors, skips, expected failures
or unexpected successes. These scopes overlap; their observations and the
local/public reruns are not added together as new unique language coverage.
Every actual generated native artifact retained by both composite collectors
is included and digest-checked. Both rebuilt Rust executables are identical:
4,204,464 bytes, SHA256 `090ea31c9631aae744d8a72b3eb1f753bba1a36edf887d564145546865761362`.
The selected public binary and the peer's original retained binary are included.
Full transitive toolchains/sysroots are not bundled or claimed closed.

The raw native child receives original source with no Python on PATH. Parent
Python admission/elaboration/Machine hooks are disabled during the candidate
collector launches. The separate Python oracle runs afterward. This demonstrates
the observed native code path, not a hostile-host sandbox or whole-process
memory-bound theorem. The scalar and policy transport ceilings remain explicit.

## Independent review and preserved failures

The peer performed 13 original native invocations: one exact normalization,
three full v6 execution matches, two separate private empty-param/result entry
refusals, four nominal/SSA/CFG refusals and three wide-alias refusals under
128 MiB RLIMIT_AS. Their exact fan-out codes are return `E_HIA_LIMIT`, malformed
call `E_HIA_CALL`, and malformed edge `E_HIA_TYPE`; the last two fail nominal
checks before cloning millions of erased names. They are not all quota errors.

Two real draft findings are closed in the frozen source: repeated binding/result
expansion before charging, and entry-parameter duplication before charging.
Original draft snapshots and the correction records remain unchanged. Peer
aggregation originally assumed v7/v8 chain ledger keys for a v6 result and
raised `KeyError: live_chains`. Its original script/logs and metadata-only copy
receipt error are retained. Completion used the same original 13 native outputs
with actual v6 ledger keys; no native replay or source change occurred.

Historical records that truthfully say public execution or frozen review was
still pending are kept as historical snapshots. Later summaries establish the
completed gates without rewriting those earlier records. The initial sandbox
Git transport failure and metadata inspection corrections are also retained.

## Scope and archive verification

The original 116 safety selectors remain and 10 are added, for 126 across
17 capabilities; integrated registration is 49 groups / 122 unique modules.
These are registration counts, not a new full126 or full integrated execution.
Additive branch registration preserves existing full/native CI requirements;
hosted workflows are a separate gate, and queued work is not a pass.

Production authority remains Python and optimization policy remains no_change.
Full P2 and all P0-P7 closure remain false. General raw nominal normalization,
complete API parity, cleanup/cancellation, deployment and backend refinement
still require their separate gates.

MANIFEST.json binds every retained payload file's size, mode, SHA256 and Git
blob SHA1. archive-receipt.json binds the complete archive and records full
gzip EOF/CRC and per-member readback. If parts are present, concatenate them in
the manifest's order and verify the complete archive hash before unpacking.
