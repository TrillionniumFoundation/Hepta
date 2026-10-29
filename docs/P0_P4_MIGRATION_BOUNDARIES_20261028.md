# C pilot boundary convergence

This increment is based on `2f49151ab9d8812eeb02ac2056f224f140099d76`
(PR #352). It incorporates the migration safety changes from PRs #349,
#350, #351, #353, #354, #355 and #356, whose final source is
`a14291c804814c83d69a2def9e8df442d2091d62`.

The restricted `migration_ir` and the scalar Clang pilot are existing public
entrypoints. Independently constructed IR previously bypassed importer-only
name checks, and the pilot's subprocess output limit applied after an
unbounded in-memory capture had already completed. Direct API path aliasing
could also replace a C input with a rejection report. These boundaries need
the same checks regardless of whether a caller enters through the CLI.

## Integrated checks

- Migration IR identifiers, token types and scalar literal lengths are checked
  before hashing, recursive traversal or source emission.
- Iterative shape admission bounds node count, nesting, parameters and emitted
  Hepta parser depth. Cycles, malformed fields and explosive shared trees
  produce `IRValidationError`.
- An inactive payload on unary negation is rejected, so ignored fields cannot
  acquire a distinct accepted IR identity.
- Source, output and report paths must resolve to distinct paths before any
  input processing or report publication.
- Both C source reads are bounded to 256,001 bytes and require a regular file.
  A sampled prefix of an oversized file is never reported as its full digest.
  POSIX nonblocking open prevents waiting on a FIFO writer.

The integrated IR file and the seven upstream regression files were checked
against their exact Git blob identities. The newer compiler selection logic in
`backend.py` remains the compiler identity implementation for this candidate.

## Live compiler capture

The pilot now uses the existing `hepta.clang_capture.run_bounded` implementation
for all four compiler operations. Capture is file-backed, checks limits while
the process runs, and reaps the POSIX process group after success, failure,
timeout or excess output. The complete streams are read into Python only after
the limits have passed.

| Compiler operation | stdout cap | stderr cap | Wall-time cap |
| --- | ---: | ---: | ---: |
| Version query | 64,000 bytes | 256,000 bytes | 10 s |
| Target query | 64,000 bytes | 256,000 bytes | 10 s |
| Predefined macros | 1,000,000 bytes | 256,000 bytes | 10 s |
| JSON AST | 8,000,000 bytes | 256,000 bytes | 20 s |

Empty successful version/target responses, malformed UTF-8 and nonzero exits
are explicit rejections. Rejected conversion preserves an existing output
artifact and publishes a bounded rejection reason. Filesystem effects and
children that deliberately escape a process group are outside this process
budget; the capture layer is not an operating-system sandbox.

## Reproduce focused validation

Use the pinned Rust 1.90.0 compiler and actual Clang on a Linux host, then run:

```sh
python3 -m unittest \
  tests.test_c2hepta \
  tests.test_migration_ir_identifier_guard \
  tests.test_migration_ir_literal_guard \
  tests.test_migration_ir_structural_budget \
  tests.test_migration_ir_neg_payload_guard \
  tests.test_migration_ir_parser_budget \
  tests.test_c2hepta_api_path_isolation \
  tests.test_c2hepta_bounded_source \
  tests.test_c2hepta_bounded_capture \
  tests.test_clang_capture -v
```

`test_c2hepta_bounded_capture` launches actual noisy and failing compiler
processes, checks child cleanup after both normal completion and timeout, and
converts C with real Clang. Its native test builds the original C and the
emitted Hepta through the Rust backend and compares ten signed/unsigned
boundary observations, including unsigned wraparound. These are finite native
comparisons in the existing scalar profile.

The IR's scoped contract is still distinct from standalone HIA Core. These
checks do not qualify general C/C++ migration, callbacks, foreign resource
lifetimes, direct LLVM aggregate exports, compiler refinement or whole-language
soundness. `whole_project_blockers_closed=false` remains the project status.
