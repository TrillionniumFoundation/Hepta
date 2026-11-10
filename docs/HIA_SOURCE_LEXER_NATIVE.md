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
Decimal floating-point literals are converted to binary64 bits using only HIA
integer arithmetic: exact numerator/denominator accumulation, binary scaling,
quotient/remainder comparison and nearest ties-to-even rounding. Normal,
subnormal, underflow-to-zero and nonfinite-overflow handling execute in HIA.
Python only constructs a float object from the eight returned bytes.

The first pass validates and counts tokens. Only a successful first pass with
enough output capacity permits the second pass to emit the token table.
Invalid input, an exhausted token budget or short output therefore cannot
partially publish token rows. Workspaces and outputs are private per call.

## Exact candidate profile

- Linux x86-64 LP64, immutable source/hash-bound local executable image.
- At most 8 MiB scalar UTF-8 source and 1,048,576 tokens **including EOF**.
- Manifest schema `hepta.hia.source-lexer-native.v3` declares a little-endian
  u64 command at workspace offset 120. Command 0 uses 128 workspace bytes;
  each token row is seven little-endian u64 fields:
  kind, code-point start/end, line, column, UTF-8 value start/end.
- Command 1 parses one integer using 2,176 workspace bytes, at most 8,192
  input bytes and a 2,048-byte output magnitude. The unchanged 4,096
  non-separator-character limit includes a radix prefix. Zero emits one zero
  byte.
- Command 2 parses one decimal floating literal using 6,272 workspace bytes,
  at most 8,192 wire bytes /4,096 non-separator characters and exactly eight
  output bytes. Three 2,048-byte private integer arenas hold the rational and
  temporary scaling values. Nonfinite overflow returns a distinct refusal;
  unknown commands and old v1/v2 manifests refuse explicitly.
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
and numeric objects from native bytes, and
maps paths/errors into the existing API. Python also authors the checked-in
HIA source and builds the B0 seed. The source parser, AST/type checker,
composites, module/package resolution, general linking, standalone toolchain
and production services are **not rewritten by this change**. The selected
image is trusted local executable code, not a sandbox or an all-input proof.
No default, production deployment or release lock is activated.


## Executable JSON compiler composition continuation

This branch composes the exact float application from implementation
6933f8c88376410d2900e34d79054919de45f814 with the accepted standalone JSON
compiler/native observer lineage2d12212. Parent acceptance is not combined
acceptance. The actual standalone JSON CLI generates the lexer image; a fresh
HIA observer executes it with the old child loader forbidden, and token values
are materialized through the native integer/float commands. The independent
observer packed-byte VM reference is evaluated before B0. Existing lexical,
integer and float random/boundary/transactional controls are retained.
No compiler caps, process limits, deadlines, source-identity membership, default
routes, release lock or production implementation is changed by this import.
Fresh clean-source combined qualification is still required.


The clean combined5253985 subsequently passed the109source,5049native/all38cold,
1242language,100combinedcomponents and all selected/default/installed gates in
`source-float-cli-composition-native-summary.json`. This completes this local
checkpoint only: full-current-source/remote/clean-machine/generalfrontend
closure and eventual old-production retirement remain open.
