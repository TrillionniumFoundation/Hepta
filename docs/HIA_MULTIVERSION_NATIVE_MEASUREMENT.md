# Native publication measurement capture and policy

This component captures the original strict twelve-field measurement value, runs the existing publication measurement policy, hashes the actual canonical snapshot, and renders the complete admission decision. It does not prove a candidate, select a generation, or grant publication authority. The complete multiversion runtime remains unqualified.

## Preserved contract

The field set, exact types, validation order, 256-code-point function limit, 15..63 odd samples, all original integer bounds, median/MAD arithmetic, ordered reasons, two-second decision reserve, finite projected-cost range, and honest claims are unchanged. Preparation cost is a signed arbitrary-length magnitude. The original numerical HIA source and its actual flat are used unchanged.

The input is an owned immutable typed snapshot. Its tags preserve exact integer versus Boolean/float, list versus tuple, and string code points. This layer does not claim to capture arbitrary concurrently mutated Python objects or to provide the outer runtime's JSON ingress.

## Six-word native entry

The shared image exports `hia_mv_measurement(source, source_bytes, output, output_bytes, workspace, workspace_bytes)`. Source, output and workspace are separate borrowed views. The owner writes only output and workspace. A structured reply returns zero; private malformed frames return `0xfffffffd`; insufficient result capacity returns `0xfffffffe`. Workspace must fit 65536 plus the actual numerical packet. Output must fit both the intermediate capture reply and the final reply. Both buffers are owned by the caller for the synchronous call.

### Request

`HIAMVMT1` has a 64-byte header. Word 1 is the root typed-value extent, word 2 is the preparation sign (0 or 1), word 3 is the magnitude extent, and words 4..7 are zero. The tail is the exact root value followed by a canonical little-endian unsigned magnitude. A zero magnitude has zero bytes and sign zero.

Each typed value is tag Q, payload-length Q, payload. Tags are 0 None, 1 Boolean with one Q, 2 exact integer with canonical ASCII decimal digits, 3 float with eight bytes, 4 string with UTF-32LE code points, 5 exact list, 6 tuple, 7 exact dict, and 8 another exact type. Lists and tuples start with an element-count Q. Dicts start with a pair-count Q and retain key/value order. Required fields are validated from the actual values; no caller-provided validity assertion is accepted.

### Reply

`HIAMVMR1` has a 128-byte header:

| Offset | Meaning |
| --- | --- |
| 8 | 0 success, 1 original semantic rejection |
| 16 | Stable private rejection selector |
| 24 | Canonical captured JSON bytes |
| 32 | Admission decision JSON bytes |
| 40 | Actual sample count |
| 48 | Original exception text bytes on rejection |
| 56 | 1 for the complete capture/policy/hash owner |
| 64 | Actual 32-byte SHA-256 of the canonical captured JSON |
| 96 | Original function value's UTF-32LE extent |
| 104 | Absolute output offset of that lossless function value |
| 112, 120 | Zero |

On success the tail contains the canonical snapshot, decision JSON, and original UTF-32LE function value. On semantic rejection the original `E_HIA_MULTIVERSION` text begins at byte 128. The independent capture-only image uses the same header with word 7 zero and word 4 denoting its original numerical packet extent.

The lossless function sidecar is necessary: two separate surrogate code points and a single supplementary code point can have identical JSON encodings while remaining different original string values. The original canonical JSON and hash are deliberately unchanged. Native consumers use the sidecar for exact typed-value observation. All other returned fields are JSON booleans, exact integers, fixed strings or arrays of fixed reasons and have no such ambiguity.

## Fixed construction

The native packer consumes `HIAMVMP1`, role-count 3, three lengths, and the actual owner, unchanged measurement policy, and hash flats. Each role retains the existing 1..4 MiB packaging domain. It emits a seven-section relocatable object with one export and no imports. The actual HIA shared linker emits the loaded shared image. Production construction needs no Python, assembler, or host linker. The readable mechanical bridge is retained alongside the HIA packer.

The wrapper only supplies the three fixed native calls. HIA checks the actual full-width numerical return, result magic/status/mask/signs, sample/call/horizon identity, eligibility identity, hash return and final output extent. It does not accept a supplied successful policy decision. The complete wrapper and individual actual kernels produce identical reply bytes in the continuation gate.

## Actual qualification

The accompanying JSON record retains complete source, flat, image and independent-oracle pins, together with the original observations:

- 890 differential and private capture cases: all five original numerical test families, strict twelve-field validation, error priority, Unicode including lone and paired surrogates, exact integer/Boolean/float distinctions, and signed preparation magnitudes exceeding one MiB.
- 24 continuation and result-binding checks using the actual native measurement and hash roles, including full-width return corruption and same-wrapper byte comparison.
- 30 native packer cases, preserving per-role extents, complete object bytes, reserved headers, trailing input, and atomic short-output refusal.

The first combined image's surrogate-pair observation failure remains recorded in the private v1 evidence. The fix preserves a lossless typed sidecar; it neither changes the original oracle nor removes the case. These are component gates. Final runtime locks, identity binding, early/late measurement invocation, conditional publication and cleanup still require the runtime composition gates.
