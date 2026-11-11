# Single edit-context renderer: development handoff r1

This is the complete HIA semantic owner for the existing single-query renderer, validated against the unchanged reference. It is an explicit development component; no ordinary entry point has been switched and this report does not establish cold qualification, whole-stack closure, or bounded admission of arbitrary in-process objects.

## Frozen implementation

The source freeze is `checkpoints/render-single-source-r1/source.json` (SHA-256 `9ce012318ad1685452ec2c898fc9344d0e50be5561b0027ff7a2cbd62a6022f6`). The 325,253-byte HIA source has SHA-256 `dead340dc0e2c9dbcc6b9cf886a341ce04396fe3a7f9139319a83b28fa605159`; its actual development image has SHA-256 `2959382ab5e63d9ebd231384a0ff9bd6035a2616dc6c0f3b6032d71a5066be4b`. The unchanged retained f50 B3 compiler is `0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`.

The source contains 62 functions, 1,243 blocks and 5,391 instructions; the largest function has 211 blocks and the maximum block parameter count is 12. The original compiler bounds (128 functions, 1,536 blocks, 8,192 instructions, 256 blocks per function and 16 block parameters) remain unchanged. Compilation used the original 10 CPU-second, 20 wall-second, 256 MiB limits.

HIA performs the complete shape, signature, source-operation inventory, CFG/display validation, ordering and text construction. It makes typed requests to the independently frozen native Graph JSON wire owner for the original bounded input gate and nested JSON fragments. Python test harnesses only capture private source graphs, invoke actual images, copy leases and compare complete outcomes.

## Completed actual tests

| Panel | Cases | Renderer entries | Scan entries | Emit entries |
| --- | ---: | ---: | ---: | ---: |
| Initial smoke | 12 | 39 | 30 | 45 |
| Full differential | 1,758 | 8,042 | 8,967 | 13,469 |
| Private protocol controls | 29 | 86 | 44 | 66 |
| Large accepted display | 1 | 20,012 | 40,006 | 60,009 |
| Total | 1,800 | 28,179 | 49,047 | 73,589 |

All 1,800 cases passed, with 150,815 actual image entries. The differential panel includes all 99 previously frozen, actually prepared native queries, independent valid controls, all renderer validation categories and their order, arbitrary-width source indices, finite floats, aliases, malformed graphs and the original 256-operation/64-block boundaries. Full text bytes or complete diagnostic text are compared; reference exception class and cause observations are preserved in raw evidence.

The large case contains 20,000 aliased callees. Its original canonical input is 1,020,509 bytes; its complete display is 1,160,108 bytes, byte-for-byte equal to the reference (SHA-256 `5b886b3c20ede260cfd6d3d5b31f1a4c83188e45cc4974c13060dd911378097e`). All 20,003 wire services execute the real scan and emit images. Source and completed peer leases are physically read-only, every entry checks canaries, and the complete final workspace/output and all events are retained. Its original 90 CPU-second / 1 GiB test limits were unchanged. The measured 52.013475379 seconds is a development run, not a cold-qualification or comparative-performance claim.

The large run deliberately records each complete event plus the complete final buffers rather than copying a growing multi-megabyte workspace 20,000 times. The smaller differential/protocol panels preserve full per-entry buffers. This recording distinction is explicit in the test source.

## Ordering and capacity

The initial complete bounded-wire gate precedes the display plan. After it succeeds, each reachable subtree under the same immutable graph and serialization profile is bounded by the complete input: its structural traversal and canonical bytes are no larger than those of the admitted whole. Therefore later subtree serialization cannot introduce a new user-input refusal. HIA may finish the exact semantic display plan first, fill its native wire placeholders afterwards, and publish only the complete display. This preserves the original first-error sequence while avoiding repeated semantic planning.

The display is not restricted to the input's 1 MiB limit. Workspace growth and the large accepted case demonstrate that distinction.

## Preserved earlier attempts

The original uncompiled draft and its first authoring failure (`break` unsupported by the authoring DSL), subsequent verifier logs, all compile receipts, four complete actual panels, source-before/source-after pins and the unchanged reference files are included. The first authoring draft was never executed as an actual image. No actual renderer semantic failure has been relabelled as a pass.

## Boundaries still open

* The component returns a native event and complete text. A selected public Python wrapper that instantiates the same exception class/cause objects has not been installed; Python traceback/cause-object identity is not claimed.
* The shared public `decode_json` diagnostic/normalization owner and complete batch renderer are subsequent work.
* Arbitrary foreign in-process object capture, alias/cycle capture resource order and a fixed public native entry remain open. The mechanical test Graph issuer is not itself bounded public admission.
* Private workspace/source leases require the fixed issuer and immutable lifetime. Correlation fields do not authenticate arbitrary externally supplied buffers.
* Original hosted/reference owners remain present.

