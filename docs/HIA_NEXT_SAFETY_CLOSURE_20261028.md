# Next safety increment: source snapshots and selected LLVM lowering checks

This increment starts from public `2f49151ab9d8812eeb02ac2056f224f140099d76`.
It preserves the six-outcome report's negative results and does not convert
unproved whole-language claims into accepted ones.

## Audit convergence

The following nine files are first imported byte-for-byte from the selected
public audit head `a14291c804814c83d69a2def9e8df442d2091d62` in commit
`8508232`. This imports the reviewed production changes and their executable
counterexamples; it does not merge the donor's older implementation tree.

- `hepta/migration_ir.py`
- `tools/c2hepta.py`
- `tests/test_c2hepta_api_path_isolation.py`
- `tests/test_c2hepta_bounded_source.py`
- `tests/test_migration_ir_identifier_guard.py`
- `tests/test_migration_ir_literal_guard.py`
- `tests/test_migration_ir_neg_payload_guard.py`
- `tests/test_migration_ir_parser_budget.py`
- `tests/test_migration_ir_structural_budget.py`

The guards reject unrepresentable or reserved identifiers, oversized and
ill-shaped literals, malformed/cyclic or explosively shared IR, excessive
emitted-parser nesting and ignored negation payloads. The direct migration
API rejects aliased source/output/report paths and bounds regular-file reads
at both intake and source recheck. Older audit results retain their donor
identity; the combined implementation requires its own execution.

## Actual bytes given to Clang

The scalar C importer previously hashed a source path, later asked Clang to
reopen that path, then rehashed it. A concurrent A → B → A change could make
Clang translate B while the report identified A. It now supplies the admitted
UTF-8 bytes through bounded stdin and records that exact digest and length.
The original path is still rechecked to reject a persistent change. This
profile excludes includes and preprocessor directives, so it needs no
directory-dependent source search.

The same importer now uses the existing file-backed `run_bounded` capture
for version, target, target-width and AST invocations. It enforces output
limits while the tool is running, before loading the AST into Python, and
uses the existing owned-process-group cleanup. This is not filesystem
containment, a CPU/RSS quota or a defense against a compromised compiler.
The new regression changes the source to B during a real Clang invocation,
restores A, and verifies that Clang actually translated the captured A bytes.
Other regressions execute child processes that emit excessive stdout/stderr.

## Selected scalar Core → emitted LLVM obligations

`hepta.hia_scalar_lowering_check.verify_scalar_lowering` validates one
acyclic, scalar, single-result Core function, with at most 128 pure
operations, 128 blocks and 32 parameters. The function can be selected from
a larger fully verified primitive module. Its reachable scalar call graph
must also be acyclic, contain at most 16 functions, and stay within the same
aggregate operation budget. It reuses the existing pinned HIA scalar SMT
encoder as its reference. A separate closed LLVM parser consumes the actual
emitted internal function, including its overflow intrinsics, casts, signed
and unsigned arithmetic, comparisons, selects, aborting guard blocks, branches
and block-argument PHIs. Calls expand the actual closed callee body and carry
its abort and poison predicates back to the caller. Explicit path expansion
has its own finite budget; recursive calls in altered LLVM are refused too.
It also checks that oversized shifts, zero divisors and the signed division
overflow case cannot reach a poison-producing instruction.

Each accepted SMT obligation quantifies over all well-typed input bitvectors
of that selected function. Unknown LLVM flags/opcodes, unaccounted
blocks, cycles, missing SSA values, malformed types, solver timeouts or
unknown outcomes cannot pass. Values and whether execution aborts must agree;
native `abort` does not expose the Core trap category, so no equality of native
error messages or trap labels is claimed.
The checker requires the emitter's unchanged external `abort` declaration
and rejects custom abort definitions, aliases and module assembly. The
semantics of the linked runtime's abort and any external interposition remain
trusted; a declaration is not proof of the actual native runtime behavior.

`tools/qualify_hia_scalar_lowering.py` freezes a clean source identity before
executing its fixed per-op/type matrix. It retains the exact Core, emitted
LLVM, SMT query, solver identity/outcome, counterexamples and mutations.
Negative controls alter actual emitted addition, a divisor guard, signed
right shift and a branch condition; an unreviewed `nsw` flag is refused by
the closed parser. Unit values can be constructed internally; they do not
gain an unreviewed native input ABI.

This is a finite inventory of lowering shapes, each with an all-input query.
It is not a theorem quantifying over all programs of the profile. The Core
encoder, LLVM subset parser and Z3 remain trusted: their correspondence to
the production VM and the full LLVM specification is not proved here.
ABI wrappers, memory operations, recursive calls, loops, resource cleanup, concurrency,
LLVM optimization and final machine code are outside this check. The new
validator has no production admission or publication authority.

`tools/qualify_hia_cursor_math.py` adds a separate specification for an actual
selected `(offset: usize, index: u64/i64, extent: usize) -> usize` helper.
It uses 66-bit signed mathematical addition, wide enough for every input,
and requires a return exactly when `0 <= offset + index < extent`, with the
returned value equal to that sum. There are no input preconditions or
sample-derived restrictions. The tool first checks the actual closed Core
and emitted LLVM call closure, then asks a different SMT query about the
external arithmetic requirement. A negative control returns `offset` on the
success path: faithful lowering still passes, but the independent math spec
must produce a counterexample. This establishes selected index arithmetic
under the encoders, not a pointer provenance or allocation-validity theorem.

Full language soundness, source-to-Core refinement, complete Core-to-native
refinement, general concurrent safety, native process-memory bounds and
absolute resource safety remain separate unclosed claims.
