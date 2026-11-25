# Bounded workflow private continuation ABI

This is a component protocol, not a claim that the public bounded API or final installed release is qualified. The public parent captures and authenticates every executable, input and identity. U owns the bounded semantics, transformation, bound query and receipt comparison.

## Entry and state

Six-word ABI: immutable source, source extent, output view, output extent, mutable work view, work extent. Work is exactly 768 MiB. Output is at least 64 MiB. Source and output do not alias work. The parent supplies a separate 608 MiB public-parent view; neither component changes the other's original limits.

The first call has work[65536]=0. Workflow phase is work+65536, not work+0: the bound subcontinuation uses work+0. The last effect result is work+8. A normal effect completes by writing its actual result there and invoking the workflow again. The return action is:

| Action | Effect |
|---|---|
| 0 | Complete. Raw JSON is at work+82 MiB and also copied into output. work+136 is its length. |
| 1 | Perform the syscall described by the first 64 output bytes. |
| 2 | Call a fixed captured pure role, using the fields below. |
| 3 | Call the parent's captured normalizer. |
| 4 | Run fresh translation through the parent's captured normalizer and primitive engine. |
| 4294967293 | Private ABI/internal failure, no result authority. |

Action 1 uses eight u64 words: syscall number, pointer-mask, six arguments. The mask has two bits per argument: bank 0 is a scalar and bank 1 is an offset in this bounded workspace. Thus arg1 as a workspace pointer uses mask 4. The only current syscall is clock_gettime(1, work+736).

Action 2 uses workspace words +16 source kind (0 original immutable request, 1 bounded workspace), +24 source offset, +32 source length, +40 output offset, +48 output capacity, +56 scratch offset, +64 scratch length, +128 role. All workspace offsets are relative to this bounded view. Roles are fixed: 8 transform, 9 interface, 10 bound solver, 15 SHA, 16 proof graph, 17 scalar projector, 18 independent scalar Core interpreter, 19 general CNF, 20 bounded receipt. Borrowed roles 15..19 are authenticated views of the captured primitive image, not duplicate or caller-provided code.

Action 3 uses +16/+24/+32 for the raw document. The parent returns the complete normalizer result at work+82 MiB, result size at +8, and classification at +144: 0 complete HIAVCF01, 1 complete original diagnostic JSON, 2 transport failure. Success is precisely 64 bytes of header plus original-canonical JSON and primitive Core JSON. Header fields +32 and +40 give the two lengths; the workflow validates the complete header and exact extent. Empty documents still reach the normalizer to preserve original validation errors.

Action 4 uses +24/+32 for independently admitted unrolled reference Core, +40/+48 for candidate Core, +56/+64 for decoded selector bytes, +144 for the original timeout in milliseconds. The parent starts a new absolute deadline only after this action is requested, independently of the completed bound query. It normalizes, proves, rechecks actual capture identities and binds the public translation receipt. It returns complete HIAMVR01 at work+82 MiB and its length at +8. It keeps captured parent images alive for final closure. Global cancellation remains the parent's signal/process kill/reap protocol.

## Request

HIABUC01 has a 256-byte header. Every field below is little-endian u64 except raw digests.

| Offset | Value |
|---|---|
| 0 | HIABUC01 |
| 8 | Mode 1 proposal, 2 validation, 3 receipt verification |
| 16 | Timeout value |
| 24 | Feedback maximum value |
| 32,40,48,56 | Decoded selector, raw before, raw after, claimed receipt lengths |
| 64 | Exact-type flags: bit 0 timeout is an exact integer; bit 1 maximum is an exact integer |
| 72,80,88 | Raw JSON lengths for original function, maximum and timeout values |
| 96 | Actual captured whole parent SHA256, 32 bytes |
| 128 | Actual captured primitive image SHA256, 32 bytes |
| 160 | Actual public source-inventory SHA256, 32 bytes |
| 192..255 | Zero |

Tail order: decoded selector, raw before, raw after, claimed receipt, raw function JSON, raw maximum JSON, raw timeout JSON. The parent obtains strict type flags and value spans from its actual typed ingress. Invalid typed selectors use the independently qualified reserved sentinel abort; original values remain available for exact public fields. Identity fields are never accepted directly from a public caller.

Each Core input retains its original 8 MiB bound. The workflow adds no total-envelope or one-MiB receipt gate; transport ingress remains owned by the public parent. Mode 1 ignores timeout validity. Mode 3 tests the claimed proved receipt before timeout, maximum or source validation. Validation checks timeout before maximum, then follows the original source/selection/profile order.

## Persistent layout

| Region | Use |
|---|---|
| 64 KiB..1 MiB | Workflow context, selector, feedback, hashes, saved bound result |
| 9..41 MiB | First interface projection, dead before bound query |
| 49..81 MiB | Second interface projection, dead before bound query |
| 82..146 MiB | Normalizer, translation and final receipt output |
| 146..210 MiB | Transform/interface/receipt scratch |
| 210..218 MiB | Original admitted Core |
| 218..226 MiB | Unrolled reference Core |
| 226..234 MiB | Admitted candidate Core |
| 234..242 MiB | Marker Core |
| 242 MiB onward | 64-byte bound header, selector, up to 8 MiB marker |
| 251 MiB..251 MiB+4096 | Bound request's short output; deliberately not at 250 MiB |
| 256..768 MiB | General solver workspace; reused only after bound completion for the receipt packet |

The 242 MiB request can extend slightly beyond 250 MiB because its header and selector precede the marker. No persistent output occupies that overlap. The bound continuation does not touch the workflow context or 210..256 MiB persistent documents. Its own local role numbers 1..5 are mapped by the workflow to 16,15,19,17,18 before returning action 2.

The receipt packet at work+256 MiB is HIABRJ01, owned exclusively by U. It contains independently computed facts and actual callback bytes; it does not accept serialized claims as proof. Receipt verification must rerun the bound and the separately budgeted fresh translation and then compare the original binding and scope fields.
