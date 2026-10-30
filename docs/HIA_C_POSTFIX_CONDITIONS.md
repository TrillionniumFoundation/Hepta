# Captured C postfix conditions and unmodified musl `strncmp`

The C migration frontend now accepts an integer local or parameter's postfix
`++` or `--` as the complete controlling expression of an `if`. Parentheses,
logical `!`, and Clang's implicit integer-to-Boolean conversion may enclose it.
The existing scalar and record/view project routes share this lowering.

## Sequencing contract

For `if (!n--)`, the lowerer emits three operations in order: save the old value
of `n`, update `n` using the existing arithmetic rules, then branch on the saved
value's negation. Both successors therefore observe the completed update.
The captured Clang AST stays unmodified and can be retained as original evidence.
Generated temporary names are separate from source-local and parameter names.

Unsigned updates wrap at their declared width. Signed updates use the existing
checked arithmetic; executions that would overflow signed C arithmetic trap in
HIA and are outside the original program's defined-input equivalence domain.
Small signed `i8`/`i16` updates still reject because their integer promotion and
implementation-defined narrowing have not been qualified. Boolean, floating,
pointer, array-element and record-field postfix lvalues do not enter this profile.
Deferred scalar locals must still be definitely assigned before their old value
can be read.

This is a finite full-expression rule. Postfix values in `&&`, `||`, arithmetic,
comma expressions, return values and loop conditions remain rejected. Prefix
increment/decrement remains rejected in conditions. No general side-effectful
expression model or arbitrary C evaluation-order guarantee is added.

## Real upstream component

`tests/fixtures/c_migration/musl_strncmp` contains the complete, byte-identical
generic `src/string/strncmp.c` from musl 1.2.5, the complete upstream copyright,
and explicit archive/commit/file identities. Its original `if (!n--)` previously
failed with `E_C_UNARY`. The source is now captured, translated and admitted
without rewriting its function body.

The declaration header and slice contracts are authored adapters. The qualified
configuration is observed Linux x86-64 LP64, C11, `-funsigned-char`, `-fno-builtin`,
`-O2` and `-fPIC`. Signed-char input still rejects its unqualified pointer element
reinterpretation. The read contracts require two initialized live slices of at
least `n` bytes; they can narrow the C function's domain when a NUL occurs earlier.
They do not infer provenance or accept an arbitrary foreign allocation.

The authored client accepts two packed eight-byte values and a length. It creates
owned storage, calls the translated borrowed function and releases both owners.
Only this scalar entry crosses the public ABI. The direct LLVM target contains
the HIA object and an observation harness; it does not link the original C body
or a Rust-generated replacement. The original-C reference is built separately
from the unchanged upstream source and a separately inventoried C client.

## Reproduction

Use the native backend's required Clang version and its matching original-type
reader. If using an extracted LLVM distribution, configure the loader dependency
path for libclang as well as the compiler executable. The qualification records
the selected loader path and LLVM/libclang library digests. It does not attest
all operating-system dependencies.

```bash
python -m unittest tests.test_c_postfix_if -v
python tools/qualify_hia_musl_strncmp.py \
  --clang "$CLANG" --source-sha "$(git rev-parse HEAD)" \
  --output /absolute/new/evidence/directory
```

The qualification requires clean committed implementation inputs. Its fixed
386 input cases cover byte boundaries, each first-difference position, zero
length, early/equal NUL, length rejection and deterministic random pairs. Every
case runs with no allocation refusal, refusal at the first allocation, and
refusal at the second allocation. Original C, direct HIA LLVM and the HIA VM
are checked against an independent byte-string/resource oracle. Both successful
and partial failed runs retain their process and observation ledgers.

The tests also cover old-value/new-state ordering, nested conditions, unsigned
wrap, signed-overflow traps without executing undefined C, deferred reads,
nonlocal lvalue rejection and preservation of short-circuit boundaries.
These finite results do not establish all-input source or backend refinement,
universal C/C++ migration, performance superiority, measured human effort or a
general AI development advantage. The previous Agent study failures and their
stopping rules remain unchanged.

## Subsequent-release maintenance protocol

The separately pinned musl 1.2.6 official release was announced on 2026-03-20.
Its generic `strncmp.c` is byte-identical to the 1.2.5 input; its complete
COPYRIGHT differs. The official archive is bound by SHA-256, and its source,
copyright and README were compared with files from the mirror's exact tag
commit. The tag commit is explicitly mirror-derived because the official cgit
request returned HTTP 503. HTTPS download and byte identity are recorded; no
PGP signature verification is claimed.

`tools/qualify_hia_musl_strncmp_update.py` fixes an **unchanged-body release
maintenance** profile before the new qualification runs. The previous receipt
must be complete and all of its retained files, input cells, native process
outputs and resource results must revalidate. The successor archive, both
function bodies, authored declaration/contract/client files, production Hepta
Python sources, compiler/Python/library identities and fixed input matrix must
match their registered conditions. A changed function body or adapter requires
a new protocol and new semantic qualification; this protocol refuses it.

The maintenance command starts a new capture, direct LLVM build, 2,316 native
process observations and 1,158 VM executions. It retains all newly observed
results, requires the same readmitted Core, and records capture, build and
whole-qualification wall time. Previous results are only the maintenance
baseline; they are not copied into the new observations. This is a regression
matrix reused intentionally across releases, not a fresh holdout experiment.

```bash
python tools/qualify_hia_musl_strncmp_update.py \
  --baseline /absolute/musl-1.2.5/qualification-directory \
  --release-archive /absolute/musl-1.2.6.tar.gz \
  --acquisition-receipt /absolute/acquisition.json \
  --clang "$CLANG" --source-sha "$(git rev-parse HEAD)" \
  --output /absolute/new/maintenance-directory
```

The acquisition receipt records the official archive URL/hash, the mirror
commit, timed download processes and whether signature verification occurred.
Archive-member validation is performed again by the maintenance command.
The command's timing excludes prior discovery and development; separately
recorded acquisition timing excludes earlier failed or exploratory requests.
Neither timing measures human labor or proves a comparative migration saving.

This example establishes only a real subsequent release's unchanged generic
component in the declared build and ownership contract. It does not qualify
the whole later musl release, changes to its unrelated routines, changed-body
maintenance, complete libc ABI compatibility or general C++ library migration.
