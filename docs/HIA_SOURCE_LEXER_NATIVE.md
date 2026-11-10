# HIA source lexical recognizer

`examples/hia_bootstrap/source_lexer.hiaasm` is an actual HIA program for the
high-level Hepta source grammar, **not** the selfhost assembly scanner. It
recognizes identifiers/keywords, lifetimes, punctuation, integer/float token
grammar, ABI strings, line comments and nested block comments. UTF-8 scalar
decoding and Unicode code-point positions, CR/LF/CRLF line tracking, numeric
separator rules and lexical diagnostic spans execute in HIA.
The same image parses nonnegative source integers in decimal, hexadecimal,
octal and binary, including strict prefix and separator validation. It emits
a minimal little-endian magnitude; Python only constructs the integer object
from those bytes, without calling a host literal parser.

The first pass validates and counts tokens. Only a successful first pass with
enough output capacity permits the second pass to emit the token table.
Invalid input, an exhausted token budget or short output therefore cannot
partially publish token rows. Workspaces and outputs are private per call.

## Exact candidate profile

- Linux x86-64 LP64, immutable source/hash-bound local executable image.
- At most 8 MiB scalar UTF-8 source and 1,048,576 tokens **including EOF**.
- Manifest schema `hepta.hia.source-lexer-native.v2` declares a little-endian
  u64 command at workspace offset 120. Command 0 uses 128 workspace bytes;
  each token row is seven little-endian u64 fields:
  kind, code-point start/end, line, column, UTF-8 value start/end.
- Command 1 parses one integer using 2,176 workspace bytes, at most 8,192
  input bytes and a 2,048-byte output magnitude. The unchanged 4,096
  non-separator-character limit includes a radix prefix. Zero emits one zero
  byte. Unknown commands and the old v1 manifest refuse explicitly.
- Numeric lexical length limit remains 4,096 non-separator characters.
- Limits of the selfhost compiler are unchanged. Application token buffers do
  not expand compiler source/output/workspace or process deadlines.

Build from an already completed, matching cold compiler qualification:

```sh
python -B -m tools.build_hia_source_lexer \
  --compiler <cold-directory>/qualification.evidence/B3.image.bin \
  --cold-report <completed-cold-report.json> --output <new-private-directory>
```

Only explicit operator selection via `HEPTA_HIA_SOURCE_LEXER_MANIFEST` routes
the existing `hepta.lexer.tokenize` API and its real parser callers through
this image. Default behavior is unchanged. Source outside the bounded scalar
Unicode representation, including Python strings containing lone surrogates,
retains the reference API. A broken selected artifact inside the profile
refuses; it does not silently fall back to the reference scanner.

## Remaining boundaries

The Python bridge still allocates buffers, constructs Token/Span/Diagnostic
and integer objects, converts finite binary64 values, and
maps paths/errors into the existing API. Python also authors the checked-in
HIA source and builds the B0 seed. The source parser, AST/type checker,
composites, module/package resolution, general linking, standalone toolchain
and production services are **not rewritten by this change**. The selected
image is trusted local executable code, not a sandbox or an all-input proof.
No default, production deployment or release lock is activated.


## JSON CLI and native observer composition checkpoint

This continuation imports the bounded v2 lexer/integer application from exact
source `c57fb17e83e776eb805fe6511a8aeee123277a93` into the executable-JSON-CLI
lineage `841fce792b3ed75ca52ddc0b99188756062156f5`. Parent acceptance is not
combined acceptance. The composition testcase builds an actual standalone JSON
compiler CLI, uses it to compile the lexer Core payload, compares that image
with the independent actual HIA compiler result, then executes the emitted
lexer in a fresh HIA-native observer with the old child-loader API forbidden.
Host payload JSON parsing/serialization and the host compile driver are also
forbidden during the standalone CLI invocation. Every observer packed-byte
reference is evaluated in the independent VM before B0.

Token/Span materialization and Python supervision remain explicit foreign
boundaries. Default tokenization remains unchanged; floats are still converted
by the documented host bridge. This checkpoint does not merge the separate
native-float candidate, change compiler/deadline/resource limits, or establish
whole-stack closure. Development16tests and shared-identity15tests passed;
fresh clean-source qualification is required before publication as accepted.


The fresh clean-source continuation f063abb subsequently passed the109source,
5049native/all38cold phases,1242language,97combined components and all installed/
default caller gates described in the whole-selfhost ledger and public
`source-lexer-cli-composition-native-summary.json`. This supersedes only the
pending status of this local checkpoint, not any remote/full-source failure or
whole-stack boundary above. Parent841fce7 remote cold failed180s/26of38phases;
the new candidate still requires its own remote and full-repository outcomes.
