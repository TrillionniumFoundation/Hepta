# Whole-source HIA grammar candidate

This caller-integrated, bounded-profile implementation executes the existing
source parser grammar in HIA. It is not an all-input equivalence theorem, a
production/default switch, semantic checking, or whole-stack self-hosting.
`Parser.parse` explicitly selects `HEPTA_HIA_SOURCE_PARSER_MANIFEST`, schema
`hepta.hia.source-parser-native.v1`. Without selection it delegates to the
unchanged `_parse_reference`. Outside the declared packet/state profile it also
uses the reference; a broken selected image inside the profile refuses.

## Native grammar and composition

`examples/hia_bootstrap/source_parser.hiaasm` contains a nonrecursive task
machine for program/module/import, struct/enum/function/ABI/generic/lifetime,
parameter/borrow/effect/resource declarations; all existing statements;
Pratt prefix/postfix/binary/cast/explicit-generic/struct/array expressions;
match patterns and arms; namespace validation and completed AST depth checks.
The original 96 nesting limit, caller depth, first-error diagnostics/cursor,
qualified path observations and `>>`/`>=` generic-close token splits remain.
The compiler's function/block/instruction/source/time limits are not increased.

Input is validated lexical tokens, not raw untrusted source bytes. The lexical
recognizer can be selected independently, including the HIA integer/binary64
conversions. Numeric token values are referenced as objects, not reparsed by the
AST bridge. The bridge performs buffer/manifest custody, flat-record validation
and dataclass construction, not syntax decisions. No semantic or module loader
implementation is replaced by this application.

## Byte and state profile

The 48-byte little-endian u64 header contains magic, token count, start index,
caller depth, payload offset and payload size. Each 56-byte token row contains
kind, code-point start/end, line, column and string-value payload begin/end.
All string token values are transported; integer/float values remain token
references. The explicit profile admits up to 4,096 tokens including EOF,
1 MiB packet bytes, caller depth 0 through 96 and no prior qualified paths.

Private workspace is 3,158,016 bytes: 256 header bytes, 4,112 fixed 128-byte
task slots and an arena beginning at 528,384 with up to 20,544 128-byte records.
The grammar depth bound is separate from implementation scheduling slots.
The output is a 128-byte header, 128-byte tagged AST/list/path/split/edge records
and 16-byte ordered token-split actions. A source-span mark is twice the original
token index plus the virtual half flag. Token references are mark plus one.

Header words: result magic; node count; split count; physical cursor; virtual
kind; program root; error code; error begin/end marks; error argument; reserved;
error reference; four reserved words. Native validation/counting finishes before
any output write. Malformed packets, short workspace, short output and private
capacity refusal leave output unchanged. Grammar errors publish structured
results and preserve prior cursor/split/qualified-path effects.

## Verification and remaining foreign implementation

Independent Core VM observations precede the seed. Native tests build actual
B0/B1/B2 successors, require B1/B2 byte identity, compile the HIA application and
compare ASTs, diagnostics, spans, cursor, tokens, caller depth and qualified paths.
Coverage includes 300 repository sources, 1,500 deterministic text mutations,
exact token/byte boundaries, depth 96/+1, nonzero entry cursor, output/workspace
canaries and concurrent private calls. Actual Parser entry runs with all Python
grammar methods disabled, separately with reference and HIA lexical recognition.
These are finite tests, not a universal proof; clean-source acceptance and remote
results must name their exact commits.

Python still authors the checked HIA source, allocates/transports buffers,
constructs AST/Token/Span/Diagnostic objects, validates custody and drives builds.
Semantic checking, modules/packages, optimization, general runtime and delivery
remain foreign. The default reference and older implementations are retained.
The full-stack rewrite is open, not closed by this grammar candidate.
