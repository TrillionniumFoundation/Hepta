# HIA JSON pretty layout source

The primary implementation is `json_pretty.hiaasm`. It owns traversal, quote/escape state, empty-container behavior, two-space indentation, colon spacing, output measurement, buffer admission, and error locations in ordinary HIA Core. Its entry uses the existing three-buffer native library ABI and returns a u64 status.

The input is compact JSON bytes already admitted and emitted by the source-bound HIA JSON wire owner. Key order, string escaping, and number spelling remain exactly the upstream bytes. This component does not admit arbitrary unvalidated JSON, serialize a foreign Python object graph, select a float renderer, or perform stdout/filesystem publication. Those owners must be closed separately before the complete CLI can be activated.

## Source and current observations

The HIA source is 16557 bytes and 395 lines, with 6 functions, 67 blocks, 248 instructions, at most 425 unique SSA names in a function, and at most 7 parameters/arguments at an edge or call. All original compiler ceilings remain unchanged.

The development observation executes this exact HIA IR through the included independent mechanical V8 interpreter. All31 declared cases passed: ordinary nested values, empty containers, escaped punctuation, UTF-8, escaped Unicode, preserved numeric lexemes, the original128 root-depth boundary, malformed layout states, short output/header/stack buffers, mode rejection, and the original8MiB wire ceiling. Measurement and emission use the same HIA control; fixed successful cases check exact output, immutable input, and sentinel bytes around the output view. This is development evidence. Public Core assembly, native compilation and native callers have not executed for this source.

## ABI

| Workspace offset | Field |
| --- | --- |
| 0 | Little-endian u64 mode:0 measures,1 emits |
| 8 | Little-endian u64 result length, reset by entry |
| 16 | Little-endian u64 input offset on refusal |
| 24 | Little-endian u64 refusal code |
| 32 onward | HIA-owned container stack |

A161-byte workspace covers the existing bounded wire depth profile. The output buffer may be empty for measurement. An emitter caller allocates the measured extent and invokes mode1 against the same immutable input. Status0 denotes success; codes1–5 are defined in DESIGN.json. A failed emission can have a written prefix which the caller must discard. The source produces no trailing newline; the existing stdout or publication owner supplies its own original newline behavior.

## Integration requirements

The development constructor and interpreter are reference tooling. The assembly is the policy implementation. No default selector, original CLI call path, global contract, installed package, or legacy implementation is changed by this checkpoint. Integration requires a matching-source native build, the exact original CLI call denominator and caller deadlines, installed resource checks, final full retained tests and cold qualification. It also requires resolving the still-open complete value and foreign-object domain rather than using a narrow wire profile to declare the complete CLI replaced.
