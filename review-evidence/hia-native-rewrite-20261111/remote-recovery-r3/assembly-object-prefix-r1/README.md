# Issued assembly object prefix — revision 1

This is new development source. No AST generation, HIA source generation, B3
compile, VM invocation or native invocation has been observed for it at this
checkpoint. Complete public assembly remains open.

The complete assembly syntax owner constructs an insertion-preserving integer
JSON representation after the original source, line, token, attribute, returned
loan, Unicode and integer digit checks. The prefix accepts that issued immutable
view. It implements the subsequent object checks from exact reference
0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5 before producing canonical bytes for a
separate complete primitive Core admission call. A successful prefix grants no
Core authority.

## Why the separate prefix is required

The reference assembles a dictionary and calls verify_program on that dictionary.
The first semantic pass is _bounded_detached_snapshot: forward traversal in
dictionary insertion order, node/depth checks, then queued-child checks.
_structure follows: dictionary keys are counted in insertion order before
values are visited right to left; canonical bytes are limited to 8 MiB.
Only then are keys sorted and canonical bytes emitted.

Passing the constructed syntax JSON through the existing raw program entry
would put its wire-byte and decoder-node gates before these object checks.
This prefix does not make that substitution.

## Complete interface

The image has the established R/W/W entry. The first buffer is the complete
immutable syntax JSON span. Both writable buffers must initially have at least
128 bytes. The operation is a pure restartable computation: GROW requests exact
physical capacities, and a subsequent invocation repeats on the same immutable
source. The final fixed parent must retain the actual issuer/lease binding.
There is no caller receipt or digest that exempts a semantic check.

The 128-byte output header contains sixteen little-endian u64 values:

| Word | Meaning |
| --- | --- |
| 0 | HIAOPE01 |
| 1 | ABI version 1 |
| 2 | action: 0 canonical, 1 GROW, 2 semantic refusal, 3 private ABI refusal |
| 3 | refusal reason |
| 4 | required output-buffer capacity |
| 5 | required workspace capacity |
| 6 | canonical output offset, always 128 |
| 7 | canonical output byte count, zero unless successful |
| 8 | observed node count, or transport upper bound during GROW |
| 9 | observed transport container depth |
| 10–15 | zero |

The returned u32 is 128 for a semantic result, 0xfffffffe for GROW and
0xfffffffd for private ABI refusal. Semantic refusal reasons map to these
complete reference messages:

1. E_HIA_LIMIT: caller-owned tree exceeds snapshot budget
2. E_HIA_LIMIT: caller-owned tree exceeds queued-node budget
3. E_HIA_LIMIT: program exceeds structural budget
4. E_HIA_LIMIT: program exceeds queued-node budget
5. E_HIA_LIMIT: program exceeds byte budget before encoding

## Transport and semantic boundaries

The first scan counts an upper bound of value nodes plus key tokens and the
actual container-stack depth, without introducing the public raw-JSON quotas.
Those measurements determine physical scratch and arena capacities. The exact
reference integer JSON decoder and preflight then run with these measured
capacities. Their grammar, decoded duplicate-key checks and UTF-8 algorithm are
retained. Only this private transport removes the unrelated raw 8 MiB,
1,048,576-node and depth-128 configuration ceilings.

The original public decoders are untouched. Source indices retain the original
32-bit decoder representation. This is a private ABI bound, not a new public
assembly gate. The public source and line limits are established by the complete
syntax owner before this interface is reached.

Snapshot traversal uses actual decoded value nodes, never the key-token
allocation upper bound. Structure traversal temporarily reverses child links
only after dictionary keys have been counted; every completed parent restores
its children before canonical output. Arrays keep their original order.
The original canonical sorter runs after both object passes, including exact
integer negative-zero normalization and ensure_ascii=False UTF-8 escaping.

This is specifically the assembly-issued strict integer JSON domain. The syntax
owner must have applied the same integer digits setting, and original assembly
lines bound integer lexemes to 16 KiB. Consequently the original enormous
integer bit-length refusal cannot become reachable here. This component does
not claim arbitrary foreign dictionaries, cyclic/shared object graphs,
surrogate-bearing foreign strings, unsupported object types, arbitrary huge
private integer tokens, or the public raw-JSON interface.

## Planned independent qualification

The new job first checks complete source identities, expands the authoring AST,
generates and independently verifies the HIA document, and compiles it using the
original 35ee92b7 compiler and unchanged gates: 10 CPU seconds, 20 wall seconds,
256 MiB address space, 1 MiB compiler output, 128 functions, 1,536 blocks,
8,192 operations, 256 blocks per function and 16 parameters per block.
A profile excess fails and requires a split; it cannot raise these limits.

Thirteen independent native groups contain 89 planned cases. They compare
complete canonical output or complete reference refusal text. Groups cover
scalar/container semantics, insertion order, Unicode keys and values, negative
zero, all controls, depth 64/65, nodes 262,144/262,145, exact/over 8 MiB, escaped
control expansion, four-byte UTF-8 expansion, malformed private transport and
short private buffers. One case deliberately combines an oversized raw wire
with an earlier snapshot queued-node violation.

Each native group retains its original 90 CPU-second, 180 wall-second and 1 GiB
process limits. Separate groups keep independent large cases from sharing a
single process budget. Source views are physically read-only and all buffers
have guard pages and two canaries. Complete inputs, outputs, workspaces,
returns and available failure buffers are saved in a durable CAS ledger.
Original Python snapshot/structure/Core and JSON entry functions are disabled
during each actual native call; the oracle runs before that interval.

No test count, native entry, compiler success or elapsed-time claim is inherited.
The tests do not execute the new syntax owner or the primitive Core admission.
Real syntax → object prefix → primitive admission, renderer roundtrip,
publication and public CLI wiring still require their own complete runs.
