# Native source effects and resources clauses

This component implements the existing source parser's complete `effects` and
`resources` subgrammars in HIA. It does not implement the surrounding function,
statement or expression grammar, semantic checking, module resolution, or the
whole compiler/tool stack. Selection remains explicit:
`HEPTA_HIA_SOURCE_CLAUSES_MANIFEST=/absolute/build/manifest.json`.

The selected parser uses the bundled actual HIA source lexer. The HIA clause
image recognizes delimiters, allowed name/literal token kinds, separators,
trailing effect commas, duplicate names, and the exact consumed prefix.
Resource integers and finite binary64 literals are decoded by that separately
bound HIA lexer; the adapter does not call a host integer/float literal parser.
Python still constructs tokens, spans, diagnostics, sets, dictionaries and
numeric objects, owns the surrounding parser, and supervises image loading.

## Representation and bounds

The public image ABI remains the three-buffer entry
`f0(readbuf, mutbuf, mutbuf) -> u32`. Input is at most 8 MiB. A clause arena has
a 64-byte header and 40 bytes per entry, with at most 1,048,576 entries. The
selected lexer retains its own original token and numeric-literal limits.
Entry rows contain exact source-byte ranges, not an embedded second copy of
every name/value.

Command 0 measures the clause and publishes no output bytes. Measurement alone
does not establish name uniqueness. The adapter uses the observed entry count to allocate the
output and a private power-of-two table, at most half full. Command 1 validates
grammar and name uniqueness before any output write, then publishes the arena
on a second pass. Even a failed measurement is replayed through native
uniqueness checking: an earlier duplicate must retain precedence over a later
missing delimiter or malformed value. This rule fixes a real development
counterexample, `resources {n0=false;n3=0x7f;n8=true;n0=0x7f;n`.

The table holds source ranges. HIA computes FNV-1a buckets, resolves collisions
with linear probing, and compares complete name bytes; hash equality is never
treated as name equality. Every call owns its workspace. The protocol also
reports character and byte cursors separately so Unicode comments and CR/LF
positions do not change the surrounding parser's tokens or diagnostics.

Malformed syntax, duplicates, short buffers and invalid workspace profiles
leave the output unchanged. The adapter validates header/range/order/cursor
invariants before constructing values and rejects a broken selected artifact
without reverting to the reference clause grammar. Trusted local native images
are executable code; these checks are not a sandbox or an all-input refinement
proof.

## Building and validation

`python -m tools.build_hia_source_clauses --compiler /absolute/B3.bin
--cold-report /absolute/cold-report.json --output /absolute/new-build` requires
the completed matching cold compiler through the existing lexer builder. The
builder retains source/image/compiler identities and the native compile
receipt, and does not activate a production/default worker.

`python -B -m unittest tests.test_hia_source_clauses_native -v` independently
executes every byte of three manually specified arena examples in the Core VM
before constructing B0, then builds actual B1/B2 successors and the HIA clause
and lexer images. Tests cover grammar, exact diagnostic precedence, truncated
and deterministic randomized clauses, bucket collisions, 2,048-entry clauses,
concurrent calls, transactional refusals, poisoned guards, manifest drift,
actual repository source files, and real functions with the reference lexer
and both reference clause methods disabled.

The source-file test enumerates all actual `.hepta` files under `tests` and
`examples`, rejects an empty corpus, and prints its observed count. A numeric
slice limit is not a claim about how many files were present. Component passes
must remain distinct from current-source cold replay, complete repository
qualification, remote CI, production activation, and eligibility to remove
the existing host implementation.
