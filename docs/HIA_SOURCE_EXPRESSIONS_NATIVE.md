# HIA source expression parser

This component implements the complete existing `Parser._expr` / `_prefix`
expression grammar as a separately selected HIA program. It does not replace
statement/declaration recognition, semantic name/type/effect checking, module
resolution, or the complete compiler/runtime/release stack.

## Actual implementation

`examples/hia_bootstrap/source_expressions.hiaasm` recognizes:

- Integer, finite floating-point and Boolean literals, names and qualified paths.
- All existing unary/binary operators, their precedence and left associativity.
- Ordinary named calls, arrays, indices, fields (including the contextual field
  name `match`), grouping, and casts.
- Explicit `::<...>` type arguments, including the existing one-list rule and
  the exact partial `>>` / `>=` closing-token behavior.
- Struct literals, field values/trailing commas, and the existing `allow_struct`
  behavior. Call arguments, array elements, indices and parenthesized operands
  intentionally use the same independent `allow_struct=True` behavior as the
  existing parser.
- Exact source spans, qualified-name records, consumed positions, current parse
  errors, and the existing caller's remaining syntax nesting budget.

The grammar uses explicit 160-byte Pratt frames. No recursive expression call
is delegated to Python. The composed HIA type recognizer handles every cast and
explicit type argument, records its exact source range, and returns to the
expression frame. During object materialization the separately pinned HIA type
image produces the shared `Type` value for that same range. This second native
type pass preserves the existing value bridge; it does not call the Python type
grammar.

Python constructs `Expr`, `Type`, `Span` and literal objects, validates arena
structure, synchronizes the surrounding token cursor, and retains host image
selection/allocation/loading. Integer magnitude and binary64 conversion are
provided by the bundled actual HIA lexer. The Python source generator remains
an explicitly inventoried development authoring aid.

## Explicit selection

Build from an actually completed matching cold compiler:

```sh
python -B -m tools.build_hia_source_expressions \
  --compiler /absolute/path/to/B3.bin \
  --cold-report /absolute/path/to/cold.json \
  --output /absolute/path/to/new-expression-installation
```

The builder first builds and binds `source-types/manifest.json` and its
`source-lexer/manifest.json`, then compiles the expression program with that
same compiler. It verifies the supplied compiler/source/cold-report bytes did
not change while building. Set
`HEPTA_HIA_SOURCE_EXPRESSIONS_MANIFEST=/absolute/path/to/manifest.json` to select
this component in the actual parser. Missing/drifting manifests or images fail
closed. The component has no automatic fallback to the reference expression
or type grammar.

Selection does not activate a production service or replace a release lock.
The existing reference implementation remains available for independent
comparison and for the unselected development route until the whole stack is
qualified for retirement.

## Native ABI and bounds

Entry uses the existing three-buffer flat HIA ABI:
`f0(readbuf source, mutbuf output, mutbuf workspace) -> u32`.
Workspace is exactly 29,184 bytes or larger. The caller supplies:

| Workspace byte offset | Value |
| --- | --- |
| 8528 | Remaining nesting budget, 1 through 128 |
| 8640 | Pratt minimum precedence, 0 through 12 |
| 8648 | `allow_struct`, exactly 0 or 1 |

Existing production parser callers retain their 96-level total nesting limit;
128 is only the standalone native profile maximum. Inputs are bounded to
8 MiB, arena events to 2 Mi, and output to `64 + 96 * event_count` bytes. The
native compiler's source/function/block/instruction/workspace/deadline limits
are unchanged. The current generated grammar has 54 functions, 603 blocks,
2,652 Core operations and 151,943 source bytes.

Return codes are the positive exact output byte count, `0xffffffff` for an
actual lexical/parse refusal, `0xfffffffe` for insufficient output, and
`0xfffffffd` for an invalid caller-supplied input/workspace profile. The native
count/admission pass completes before any output byte is written. Invalid
source and insufficient output therefore preserve the original output bytes.
The bridge starts with a 4-KiB output and, when needed, resizes only from the
native count result; it does not allocate an arena proportional to an unused
source suffix for every short expression.

Each output has a 64-byte header and 96-byte postfix construction events. The
header binds the magic `HIAEXPR1`, event count, exact used bytes, consumed Unicode
characters/UTF-8 bytes, version, root kind and zero reserved field. Events carry
kind, arity, character span, line/column, exact byte range, auxiliary tag and
three zero reserved words. The bridge checks these values and all operand-stack
shapes before exposing the result.

| Event kinds | Object operation |
| --- | --- |
| 1, 2, 3 | Integer, floating-point or Boolean value |
| 4, 5 | Unary or binary expression |
| 6, 17, 7, 8 | Name start, path part, native type argument, name completion |
| 9, 10, 11, 12 | Call, index, field, native type cast |
| 13, 14 | Parenthesized span replacement, array |
| 15, 16 | Struct field association, struct completion |
| 18 | Exact type-closing operator split; no AST operand effect |

Split events are required to distinguish a type-closing `>>` from a binary
shift. An event for a partially consumed `>=` legitimately includes the one
unconsumed `=` byte. Only that event kind may extend its end by one beyond the
consumed prefix; the full original operator bytes, source range and unique split
position are still checked. The initial development bridge incorrectly rejected
this valid boundary; the original failing test log is retained.

## Qualification and remaining trust

`tests.test_hia_source_expressions_native` independently executes complete arena
byte windows in the Core VM before building B0, compares actual native successor
bytes, exercises every production and precedence, fuzzes deterministic valid and
truncated expressions, compares real repository source expressions/full-parser
callers, checks exact diagnostics/nesting, executes concurrent private native
calls while reference grammar/lexer are patched to fail, and checks poisoned
scratch/output guards, transactional refusals, manifest drift and malformed
construction arenas.

These are finite, source-bound engineering controls. A passing local suite does
not prove all-input compiler refinement, qualify later changed source, or close
whole-repository/remote/platform/clean-install gates. The OS/hardware/native
loader and the Python object/cursor bridge remain trusted. This executable image
is not an untrusted-code security sandbox. Whole-stack HIA closure and legacy
retirement remain open until their separately defined complete gates pass.
