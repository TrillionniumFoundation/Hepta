# Ordered native background decision stages

This component implements the ordered pure checks and exact arithmetic inside BackgroundOptimizer._decision, plus the pre-publication budget calculation in _execute. It consumes private, actual captured inputs from the enclosing native coordinator. It does not make source-verification, runtime-admission, or publication claims.

## Continuations and order

Stage 0 binds the rank schema, incumbent digests, function, decision generation, and observations digest. Generation comparison preserves Python numeric equality (including bool, binary64 integral values, negative zero, and integers beyond 64 bits), then requires the original exact integer type. Success requests canonical freezing of the two objective values.

Stage 1 compares the complete objective bytes and independently captured objective digest, checks exact admission and selected-ID types, validates costs, and sums every supplied observation in the original iteration order. No early oversized-sum shortcut suppresses a later row error. A valid abstention returns immediately. An admitted result scans the entire submitted candidate collection, preserves duplicate-last selection and unhashable-key errors, and returns the submitted and ranked source nodes for fresh verification.

The owner must freshly verify the submitted candidate first and the ranker's selected source second. Stage 2 receives their actual digests, checks observation bindings, and validates all calls, cap, runtime, and uncertainty fields in the original order. Multiplication and subtraction retain complete 128-bit intermediate values; public integers are not silently clipped to a machine word. An admitted margin must match the exact reported integer, be positive, and fit the original search cap.

Stage 3 repeats the verified-source economic check with actual submit/start/handoff observations, charges surrounding coordinator work exactly once, and computes min(net_margin - outside_work - 1, resource_cap - search - outside_work). Positive prepare budgets are bounded by the original cap. The runtime provider, not this component, owns the actual conditional publication.

## Fixed input

HIABDC01 has a 512-byte header followed by payload raw JSON, its fresh owned arena, report raw JSON, its fresh owned arena, function WTF-8 bytes, expected decision-generation decimal bytes, freshly canonical report-objective bytes, and freshly canonical input-objective bytes.

| Offset | Value |
| --- | --- |
| 8 | Stage 0–3 |
| 16 / 24 | Payload raw / arena lengths |
| 32 / 40 | Rank report raw / arena lengths |
| 48 / 56 | Function / full decimal decision-generation lengths |
| 64 / 72 | Report-objective / input-objective canonical lengths |
| 80 | Actual measured rank invocation nanoseconds |
| 88 | Zero |
| 96 / 128 | Actual incumbent Core / input SHA256 bytes |
| 160 / 192 | Actual observations / bound objective SHA256 bytes |
| 224 / 256 | Actual freshly verified submitted / ranked Core SHA256 bytes |
| 288 / 296 / 304 | Stage 3 actual submit work / start / handoff nanoseconds; otherwise zero |
| 312–511 | Zero |

The coordinator owns matching immutable raw/arena pairs and obtains all digests, timing values, and source verification results from fixed captured roles. These fields are not accepted as external caller proof or authority. Stage 0 does not consume objective-freeze results; stage 1 cannot replace either fresh source verification callback.

Workspace is at least max(131072, payload arena node count, report arena node count). Output is at least 256 bytes. No additional aggregate JSON or counter limit is imposed.

## Result

Zero returns HIABDR01. Offsets 8 and 16 are business error status and stage. Error ID is at 24. IDs 1–22 are the exact original background rejections; IDs 100–115 represent the original JSON-owned Python type errors. IDs 200 + key-label represent fixed KeyError keys. ID 299 carries a dynamic missing selected-ID key; its arena selector is at 32 and node at 40. The separate qualified string-repr component renders KeyError text.

On success, offset 64 is continuation 0 (abstain), 1 (freeze objectives), 2 (freshly verify both sources), or 3 (admitted). Actual ranking cost and total search cost are at 72 / 80; cap at 88; positive margin low/high words at 96 / 104; selected report node at 112; submitted / ranked source nodes at 120 / 128; report / input objective nodes at 136 / 144. Stage 3 outside work is the low/high pair at 160 / 168; post-coordinator margin sign/low/high is at 176 / 184 / 192; publication budget is at 200. Selected/incumbent observation nodes are private offsets 208 / 216. Other words are reserved zero.

Error codes select original exception behavior; they do not collapse different errors into one rejection. The enclosing owner uses the error renderer and preserves the original catch/worker policy.

Malformed private input returns 4294967293 and short output 4294967294; output is unchanged.

## Qualification and limits of the claim

The actual native suite compares 1,323 cases with unchanged original methods at explicit pure continuation boundaries, plus 15 private atomic controls. It covers full numeric equality, a 10,001-digit generation, error precedence, duplicate and unhashable candidates, exact cost sums, source bindings, 128-bit margins, and actual original _execute budget calculations driven by observed test clocks. Native input and canaries remain unchanged. Both sealed native compilations are byte-identical.

Original normalization and runtime callbacks are stopped only at the documented pure boundary for this suite. The suite therefore does not stand in for whole-worker or live runtime qualification. Two earlier test failures are retained: one fixture removed an observation without adjusting its earlier cost binding, and one assertion read the selected-row slot instead of the publication-budget slot. Neither required changing the native decision implementation.
