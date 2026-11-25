# Native multiversion normalized intake

This HIA preparation stage captures a raw request, runs the actual complete Core/composite normalizer in a sealed child process, preserves the original validation error, and computes the primitive scalar profile and sorted public ABI. It is the implementation of preparation's input-admission step. It does not perform totality or translation proofs, build or load a generation, select a generation, or complete the public multiversion/Future/background API.

## Actual flow and identities

The caller supplies a custody-pinned complete normalizer executable FD and retains that capability throughout entry. The owner takes its own duplicate. It copies the actual raw request once, hashes those bytes, and invokes fixed process role 1 (`hia-admit-agent-json`). It parses the complete `HIAVCF01` result, rejects malformed lengths or control words, and hashes both canonical payloads. The frame and byte limits are the existing normalizer's original limits: 8 MiB raw, each canonical payload at most 8 MiB, and a 64-byte frame.

For primitive input, the canonical original and primitive Core bytes must be identical. The private primitive intake repeats structural Core admission, canonicalization, scalar-profile decisions, and ABI extraction using the actual bytes. The outer owner cross-checks the repeated Core hash, input hash, canonical payload, totality-profile selector, ABI count, and ABI hash before returning them. The selector requests the existing profile; it is not a proof result.

For successfully verified composite input, the original multiversion API rejects the structured source with profile reason 1. This decision remains after actual normalization; the composite is not silently promoted to the primitive multiversion domain. Both its original-canonical and lowered-Core hashes are retained independently.

When normalization returns its original error exit (2 or 3), the owner closes the first output captures and invokes fixed process role 4 (`hia-verify-core-json`) through the same captured normalizer FD. It uses the same absolute deadline and cancellation capability. A complete exit-2 diagnostic transfers sealed stdout and stderr FDs to the caller; the caller must consume and close them. The original JSON diagnostic message is preserved. Neither a diagnostic boolean nor a caller-provided `verified` flag authorizes execution.

The three identities are deliberately different:

| Identity | Actual bytes |
|---|---|
| Raw request SHA | The caller's captured JSON, including original whitespace |
| Original input SHA | The normalizer's canonical original representation; the structured representation for composite input |
| Core SHA | The normalizer's canonical primitive Core |

## Callable frame

The SysV entry is `u32 hia_mv_prepare_intake(s_ptr,s_len,o_ptr,o_len,w_ptr,w_len)`. It requires disjoint private request, output, and workspace buffers. Workspace is at least 256 MiB. Output is at least 320 bytes; a successful payload needs `320 + original_bytes + core_bytes + abi_bytes`. Each native call owns separate state. The actual normalizer runs out of process, so its internal transport globals are never concurrently reused as a library.

`HIAMVNQ1` is a 128-byte little-endian header followed by exactly the raw bytes:

| Offset | Field |
|---:|---|
| 0 | `HIAMVNQ1` |
| 8 | Existing totality-profile selector, 0 or 1 |
| 16 | Already captured and closure-bound normalizer FD, 3 through INT_MAX |
| 24 | Nonzero absolute CLOCK_MONOTONIC deadline |
| 32 | Caller-owned aligned cancellation u64 pointer, or zero |
| 40 | Raw input size, at most 8 MiB |
| 48 through 127 | Ten zero words |

The process component independently verifies anonymous regular-file identity, size, and seals. Its caller must bind the actual executable SHA to the trusted normalizer source closure. This private frame is not a public arbitrary executable facility.

The response begins with a 320-byte `HIAMVNP1` header:

| Offset | Field |
|---:|---|
| 0 | `HIAMVNP1` |
| 8 | Status |
| 16 | Detailed profile/error code or required output extent |
| 24, 32, 40 | Raw, canonical-original, canonical-Core byte counts |
| 48, 56 | ABI byte count and public export count |
| 64, 72 | Totality-profile selector and actual normalizer composite profile |
| 80, 112, 144, 176 | Raw, original, Core, and ABI SHA-256 bytes |
| 208, 216 | Actual normalization and diagnostic Linux wait statuses |
| 224 | Process outcome; zero only indicates complete capture |
| 232, 240 | Diagnostic stdout and stderr extents |
| 248 | Evidence flags: normalization 1, raw hash 2, original hash 4, Core hash 8, scalar profile 16, ABI 32 |
| 256, 264 | Owned sealed diagnostic FDs, or UINT64_MAX |
| 272 through 319 | Zero words |

Status zero returns canonical original bytes, canonical Core bytes, and `HIAMVAB1` sorted ABI bytes in that order. Status 1 returns the original verification diagnostic via the two sealed FDs. Status 3 is an original scalar-profile rejection. Statuses 2, 4, and 5 are canonical/ABI/hash failures; 6 reports the exact required output extent; 7 reports a process, cancellation, deadline, or I/O failure; 8 rejects an inconsistent internal normalizer/role response. Malformed private requests or insufficient header/workspace extents return `0xfffffffd` without changing output.

The same absolute deadline applies to normalization and its diagnostic retry and is checked between pure HIA stages. The enclosing coordinator still performs the original final elapsed-preparation and cancellation checks before selecting a generation; this component grants no selection authority. Returned diagnostics are already complete, anonymous, sealed streams. All other owned transport FDs are consumed before returning.

## Source and packaging

The outer policy and packer are `multiversion_prepare_intake.hepta` and `multiversion_prepare_intake_packer.hepta`; the readable outer adapter is `tools/hia_multiversion_prepare_intake_bridge.S`. The packer includes the unchanged already-qualified process adapter and the primitive intake adapter, with fixed role calls. All role arguments, ordering, response checks, hashes, and ownership decisions are HIA.

The primitive internal component uses `multiversion_intake.hepta`, `multiversion_intake_packer.hepta`, and `tools/hia_multiversion_intake_bridge.S`. It consumes the already-selected primitive representation. Its private `HIAMVIT1`/`HIAMVIP1` frames do not implement raw composite API normalization; that responsibility belongs to the outer owner above. The initial experiment that sent raw composite source straight to primitive admission failed and remains retained as historical evidence.

The complete native packer's request is `HIAMVNK1`, a u64 role count of 9, nine u64 flat extents, and the nine actual flat images. The order is outer intake, process capture, primitive intake, Core admission, Core canonicalization, scalar-proof hash, multiversion profile projection, scalar profile, and multiversion ABI. Each flat is 1 through 4 MiB, the combined text retains the existing 16 MiB shared-linker bound, and trailing bytes are rejected. The existing HIA shared linker produces the actual shared image. No assembler, Python, or C semantic code runs in this construction path.

The scalar-proof hash source is identical to the source committed by the proof owner in `6ea531efd1b2f491429760f94ce17e17bc029eed`. Here it is compiled by the same v95 source compiler as the other eight roles, so its flat differs from the proof service's independent-seed build. All 376 original hash ABI/bounds/padding controls passed against this actual flat; no byte-equality claim is made across different backends.

## Qualification and remaining composition

The qualified product passed 456 original-oracle/private-boundary controls, 13 actual lifetime/capability controls, and 42 native packing/provenance controls. The 456 comprise 428 fresh original input/profile combinations and 28 private controls. They cover all 337 retained normalizer inputs, original scalar-profile compact/pretty cases, actual previously built scalar ABI inputs, original composite rejection, exact diagnostics, all three actual SHA bindings, raw whitespace, the original 8 MiB bound, cancellation, required-output reporting, and malformed frames. The lifetime controls prove cancellation and deadline while the controlled child is actually running and verify direct-child reaping and descriptor custody. The packaging controls compare all three readable assembly capsules and the actual nine-role object and linked image.

Exact source/flat/image pins and unchanged external evidence hashes are in `HIA_MULTIVERSION_PREPARE_INTAKE_NATIVE_QUALIFICATION.json`. The whole-native flag stays false. Proof receipt admission, build identity, image loading/mapping, finite probes, generation retention, selection, and the complete public BackgroundOptimizer/Future composition remain separate obligations.
