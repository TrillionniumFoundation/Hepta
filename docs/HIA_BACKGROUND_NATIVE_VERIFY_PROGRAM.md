# Native verify_program owner

This component executes the original verification path over actual mutable value capabilities. It owns input retention, typed snapshot/structure checking, raw text and byte preflight, checked canonical freezing, the actual captured native verifier process, original diagnostic translation, immutable result construction, and cleanup. It does not accept caller-supplied verification facts. The separate complete background controller, multiversion public adapter, and final release remain independently gated.

## Actual order and compatibility

For an ordinary object, the owner invokes the qualified bounded detached snapshot and structure owner with the captured integer conversion policy. For text it preserves the original character lower bound and 4096-code-point UTF-8 chunk order, including whether a surrogate or an earlier byte-budget overflow wins. Bytes preserve the original byte bound before UTF-8 decoding. The original limits remain 8 MiB, 262144 nodes, and depth 64.

Raw input and freshly frozen object input both pass the actual strict native syntax/UTF-8/duplicate/budget checker. Only after that check succeeds does the wrapper enforce the captured integer conversion policy and decoded top-level historical nominal-v2 collision rule. The latter preserves E_HIA_VERSION_COLLISION when schema is hepta.hia.program.v2 and types is present. Escaped schema/key spellings are decoded before comparison. The original strict grammar rejects floating JSON numbers before the integer policy; three long-fraction/integer-part/exponent controls confirm this order.

The owner invokes the captured normalizer's actual hia-admit-agent-json role under HIAMVPS2, with no invented verification deadline. Actual refusal waits invoke the original hia-verify-core-json diagnostic role. Every owned child is reaped and every temporary descriptor is closed. The actual normalizer is independently pinned; its generic field diagnostic alone does not implement the historical-v2 collision rule, so callers outside this owner must use the same shared preflight or an equivalently qualified admission owner.

A VerifiedProgram profile never trusts its supplied canonical bytes. A non-None structured value must be actual bytes, is freshly verified, and must describe a composite profile. Both its complete structured and canonical spans must equal the fresh normalized result. The order of these checks preserves the original public diagnostic precedence.

## Fixed interface

The six-word export is hia_background_verify_program. The request is exactly 128 bytes.

| Field | HIABVFY1 | HIABVFY2 |
| --- | --- | --- |
| 8 | Operation 0 or cleanup-only 1 | Operation 0 or cleanup-only 1 |
| 24 / 32 / 40 | Actual input value capability | Actual canonical value capability |
| 48 / 56 / 64 | Zero | Optional actual structured value capability |
| Other words | Zero | Zero |

An all-zero structured capability or actual None represents absent structured bytes. Cleanup-only operation 1 requires every input capability word to be zero and never repeats semantic verification.

The output is at least 262144 bytes. Workspace is an exclusive, independently owned 4096-byte context:

| Offset | Captured binding or private state |
| --- | --- |
| 0 | HIABVYC1 |
| 8 / 16 / 24 | Actual value entry / context / extent (at least 256) |
| 32 | Actual lossless value transport entry |
| 40 | Actual owned JSON capture entry |
| 48 | Actual checked sorted freezer entry |
| 56 / 64 / 72 | Actual immutable payload entry / context / extent |
| 80 | Captured integer digit policy: 0 or 640 through INT_MAX |
| 88 | Actual captured sealed normalizer descriptor, at least 3 |
| 96 / 104 | Fixed integer threshold bytes / extent 10100891 |
| 112 | Actual typed structure entry |
| 120 | Actual complete value-freeze entry |
| 128 | Actual complete verification process entry |
| 136 | Actual shared raw preflight entry |
| 144 / 152 | Owner-recorded process identity / quarantine |
| 160–255 | Zero |
| 256–1151 | Saved private owner state |
| 1152–1279 | Private typed owner context |
| 2048–4095 | Private freezer context |

These are fixed composition bindings, never public providers or request-supplied authority. The enclosing composition strongly owns the actual context records, descriptor, threshold bytes, and code throughout a call and any retained cleanup. Concurrent calls require separate workspaces; cleanup is exclusive.

## Result and ownership

The 128-byte reply is HIABVFR1. Status is at 8. Status 0 returns an owned complete HIAVCF01 payload; status 1 returns an owned actual native verifier diagnostic JSON; status 2 returns an owned original typed rejection JSON containing class, code, and message. Statuses 5/6/7/8/9 represent allocation, lifecycle/capability, dependency, OS, and retained/invariant failure respectively.

The immutable payload capability is at 16/24/32, byte length at 40, detail at 48, and retained-cleanup flag at 56. A successful ordinary return releases all temporary value references, mappings, and descriptors before transferring the independent result reference. Retained failure does not return a partially usable result.

HIAVCF01 is a 64-byte header followed by complete original and canonical Core bytes. Header word 8 is zero success, words 16/48/56 are zero, profile at 24 is primitive 0 or composite 1 through 4, and original/Core lengths are at 32/40. Each span is between 1 and 8 MiB. This owner does not narrow valid programs to the separate multiversion scalar profile.

Explicit cleanup retries only dependencies that returned their qualified resumable retained-state reply. An active call whose state is unknown remains quarantined; it is never blindly re-entered or freed. Completed immutable error/result payloads survive cleanup retries without semantic replay. A typed-stage failure that did not reach semantic verification can finish cleanup without replaying verification; a fresh ordinary call is then required.

## Shared raw preflight

The raw entry accepts the complete actual UTF-8 source, output at least 4194304 bytes, and workspace at least 4096 bytes. Captured integer policy is workspace word 80. Node and depth budgets are fixed internally.

Return values are 0 (valid), 1 (syntax/UTF-8/duplicate failure), 2 (original predecode structural budget), 3 (private view/policy failure), 4 (integer conversion policy), and 5 (historical nominal-v2 collision). No caller verification flag exists. The original duplicate result is normalized to syntax failure before the integer-policy result is assigned.

## Construction and qualification

The actual source compiler produced two identical policy and packer flats. The native HIA packer and HIA shared linker each produced two identical products. The readable 483-byte mechanical bridge has no undefined imports and only dispatches native policy-requested calls and syscalls. Its bytes are checked separately against the actual HIA-packed object.

The final gates are:

- 423 comparisons with unchanged original verify_program, using the actual complete native owner and dependencies. They cover original schemas, primitive/composite programs, raw text/bytes, malformed fields, cycles and aliases, exact error classes/messages, forged VerifiedProgram pairs, integer policies 4300/0/640, structural budgets, and Unicode chunk/error priority.
- 1491 actual shared preflight comparisons plus six private atomic guards. These include syntax mutations, duplicate/escaped keys, budgets, integer policy, and 142 decoded historical-version cases.
- Fourteen ownership/failure/concurrency groups. Per-effect lifecycle fault cases drive the same actual HIA policy with an external mechanical QA driver and actual value/freezer/process/syscalls; they do not replace a dependency return with a fabricated semantic result. Six allocations fail with real kernel ENOMEM. A whole closed-bridge call fails under real RLIMIT_AS, and 32 actual complete calls run across eight threads. Immutable output survives input destruction.
- 103 private framing, pointer, context, capability, PID, and cleanup controls.
- 24 actual native HIA packer controls, including malformed-input output atomicity and mechanical-source provenance.
- Three additional original-preflight comparisons for long floating-number tokens; all are refused by the original strict grammar before digit conversion.

The companion JSON contains complete reports, native/source identities, and the exact external qualification sources. Earlier failed qualification observations remain external development evidence; they are not counted as passed gates. This checkpoint qualifies this owner and its shared preflight, not final activation or repository retirement.
