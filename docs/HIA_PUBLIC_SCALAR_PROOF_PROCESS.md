# Native scalar proof process front-end

This component captures and runs the qualified HIA normalizer and primitive
proof engine, then binds the result through the HIA receipt owner. It is a
private binary process interface. Full public API equivalence and the final
native release are not yet established.

## Inputs and results

The executable accepts no arguments. `HIAPPR01` is a 64-byte header followed
by the exact name, before, after, and claimed-receipt bytes. Its seven
little-endian words are mode, timeout milliseconds, name length, before
length, after length, receipt length, and zero. Modes 1, 2, and 3 mean totality,
translation, and fresh verification of a claimed translation receipt.
Each Core input retains its 8 MiB limit. The private name is an ASCII
identifier of at most 128 bytes, with zero length denoting omitted selection.
This private restriction is not a substitute for the original typed public
function argument semantics. The claimed receipt is limited to 262144 bytes.

Raw before/after byte strings may be empty. In translation and fresh receipt
verification an empty after span is still passed through original validation;
it is not an absent required canonical document or a malformed private frame.
The canonical primitive child retains its nonempty input requirement. The
32 exact empty-input/timeout/claimed-receipt comparisons are recorded in
`HIA_PUBLIC_PROOF_RAW_INPUTS.json`.

The response is a complete `HIAMVR01` header and JSON receipt. A component
failure cannot create a proof; incomplete child output is never accepted.
The original normalizer's large errors are transported in full, through the
explicit diagnostic profile documented in `HIA_PUBLIC_PROOF_RECEIPT_ABI.md`.

## Capture and identity

Both child executables are embedded in the parent and copied through full
write loops into separate anonymous memfds. HIA checks their actual source
and captured hashes, private file identities, modes, exact lengths, rewind,
and all four seals before execution. The normalizer uses fixed argv0
`hia-admit-agent-json` or `hia-verify-core-json`; the proof child uses fixed
`hia-native-scalar-proof`. The already-qualified four-role process owner
handles short I/O, interruption, failure, capture, deadline and child reaping.
No caller-selected executable or argument list is admitted.

The parent hashes its complete mapped image before and after work, checks
its `/proc/self/exe` regular-file extent, and compares stable identity and
mtime/ctime fields. Receipts distinguish actual request bytes, original
canonical Core/composite bytes, and primitive canonical Core bytes. The
public checker identity binds the whole parent image. Primitive proof
receipts must bind the actual captured primitive image before public
rebinding. A claimed receipt is recomputed and compared at use.

The same 6Q SHA stream ABI is provided by the qualified composite of
`cold_sha256_stream.hepta`, `cold_sha256_nonalias.hepta`, and
`cold_sha256_alias_packer.hepta`. Its range-only mechanical alias dispatch
retains the fallback; the production packer executes no assembler or linker.

## Current validation and remaining work

The retained validation includes the original 16 semantic tests and 113
actual parent proof calls, all 391 original receipt component controls, all
337 original normalization inputs through the complete parent, 26 explicit
large-diagnostic controls, and actual 8 MiB ASCII, escaped-control and UTF-8
producer boundaries. The maximum diagnostics use an explicit 60-second
configuration. They do not imply equivalence under every default deadline.

The original error/deadline ordering is now implemented by the explicit
`HIAMVP02` absolute-deadline profile described in `HIA_PUBLIC_PROOF_DEADLINE.md`.
The original proof budget is retained across normalization and proof children;
a distinct, once-computed transport lifetime permits required preceding
validation to complete. The actual new parent also passes the original 113
semantic calls and the 12 large-input/deadline-order comparisons.

The signal cancellation component is qualified in
`HIA_PUBLIC_PROOF_CANCELLATION.md`: actual stopped-child cancellation, process
group interruption, full output-pipe interruption and failure before request
completion retain owned-child and descriptor custody. The unchanged original
113 proof calls also pass with these handlers installed.

Empty, non-ASCII and non-string function values still require the full typed
input adapter. Full public lifetime/fault, publication, installed cold,
OpenClaw integration and cleanup gates remain separate obligations. No
whole-native flag is set by this checkpoint.
