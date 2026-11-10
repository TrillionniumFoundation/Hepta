# HIA source-type grammar candidate

This is a real caller-integrated **type grammar**, not the entire source parser,
a production default, an all-input equivalence theorem, or whole-stack closure.
The default remains `Parser._type_reference`. Explicit local selection uses
`HEPTA_HIA_TYPE_PARSER_MANIFEST`, schema `hepta.hia.type-parser-native.v1`.
The existing HIA lexical selector can be enabled independently; selecting only
the type parser still uses reference lexical recognition.

## HIA behavior

`examples/hia_bootstrap/source_type_parser.hiaasm` runs all type syntax decisions:

- Qualified identifier paths (including intervening comments/whitespace).
- Generic type/lifetime arguments, preserving their separate original order,
  original empty/trailing-comma refusal, and exact Buffer/Task/Sender arity.
- Slices, arbitrary-integer-length arrays, raw const/mut pointers, and read/mut
  references with explicit lifetimes.
- Iterative frames enforce the original 96 nesting limit including caller depth;
  no native compiler recursion/function/block capacities are changed.
- Physical/virtual token cursor and ordered split actions preserve the original
  `>>`/`>=` generic-close mutation, including the remaining operator's span.
- Original error categories, messages, token positions and restored caller depth.

## Candidate byte protocol

Input is **validated lexical tokens**, not raw source. Packet transport assigns
fixed lexical kind numbers and carries token positions/name bytes, without
recognizing type syntax. The 48-byte LE-u64 header is magic, token count, start
index, caller depth, payload offset and payload bytes. Each token row has seven
u64 words: kind, code-point start/end, line, column, name-payload begin/end.
Only identifier/lifetime value bytes are transported. Array lengths refer back
to the already recognized integer Token value, including arbitrary magnitudes.

The explicit application profile is at most 4,096 tokens including EOF, 1 MiB
input, and 9,472 workspace bytes (96 fixed frames plus state). Out-of-profile
existing callers retain the original reference path. A broken selected image or
source binding **inside** the profile refuses; it cannot silently fall back.
These application limits do not change the compiler or existing language caps.

A result has an 80-byte header, 64-byte flat typed nodes and 16-byte split
records. Header words: node/split counts, physical position, virtual second
character, root node, grammar error, error position/virtual state, expected
kind/special category, special-name token. Node words: tag, value-token index,
name list, argument list, lifetime list, element, next sibling, reserved. Tags:
0 named, 1 slice, 2 array, 3/4 raw const/mut, 5/6 read/mut reference, 7 name part,
8 lifetime. Split records contain original token index and original kind.

HIA first validates/counts, then publishes the entire result in a second pass.
Malformed packets, short workspace and short result capacity leave output
unchanged; grammar errors are structured results retaining prior split actions.
Code/source buffers are immutable and scratch is private per call.

## Evidence gates and remaining work

Tests observe independent Core VM byte results **before** constructing a seed,
then compile real B0/B1/B2 successors and require fixed-point byte equality.
Conformance includes original diagnostics/cursors/token mutations, 96/+1 depth,
nonzero caller depth, random recursive types, guards/refusals/concurrency, and
300 real source files. Real Parser callers run with `_type_reference` disabled;
separate cases also disable the reference lexer and select the HIA lexical image.
Finite observations do not establish all-input equivalence.

Python still authors HIA, allocates/transports buffers, constructs Token/Span/
Type/Diagnostic objects, validates manifests, and operates the build/evidence
chain. Declarations/statements/Pratt expressions, semantic checking, modules,
packages, general runtime, optimizer, production tools and delivery are still
foreign. Do not delete their existing implementations or call the task closed.
