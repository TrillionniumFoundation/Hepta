# P1 source-bound scalar SSA bridge: bounded implementation and acceptance

This PR is stacked on the exact #55 head
`926401cc371bca7373539491a44b12c00f7dc69b`.
It adds a real, *limited* path from the PR #14 source-bound
`hepta.hsir.v0` layout through versioned HSIR v1 to the PR #37
CFG / scalar SSA / independent SSA verifier. It does not merge the
two full compiler branches and does not grant LLVM code generation.

## Closed scalar mapping profile

The new `hepta/hsir_scalar_bridge.py` accepts only complete, already
typed, source-bound v0 documents with an exact known field set and
empty project imports, ADTs, owned types, volatile sites, external
obligations, foreign assumptions and resource-contract inventories.
Every function must have by-value scalar parameters and scalar return,
no lifetime/returned-loan/generic capability, no resource clause, no
`ffi`, `unsafe`, `alloc`, `spawn`, `block`, `write`, or I/O
effect, and no C-imported extern function. Supported body operations
are local scalar declarations/assignments, numeric/bool literals,
scalar variable reads, pure/panic arithmetic and comparisons,
ordinary if/else, while, and return.

A new source format operation or unfamiliar field is **not dropped**:
it rejects the whole document. Calls, array/indexing, pointers,
Buffer, tasks, exception/callback contracts, casts and short-circuit
operators deliberately reject. In particular short-circuit operations
could change panic/evaluation order if translated as ordinary eager
binary expressions. Explicit float NaN/Infinity values reject.

The bridge constructs the exact *structural* frozen scalar HSIR
representation used by #37 CFG; it does not claim that #14 and #36
have the same complete type model. The original v1 snapshot and its
embedded v0 source remain provenance authority, and an independent
SHA-256 for the **derived scalar HSIR** is recorded. The versioned
consumer checks the v1 input, maps the strict source-bound subset,
then runs #37's original CFG, scalar SSA and SSA verifier. Its output
binds source v1 SHA, source v0 SHA, derived scalar SHA, CFG SHA,
SSA SHA, and SSA-verifier SHA. Project hash, when available, remains
in the provenance report; it is not silently discarded.

## Commands

PR #37 source path:
    python -m hepta ssa-v1-verify SOURCE --rustc PINNED_RUSTC

New exchange-file analysis-only path, including a v1 producer export:
    python -m hepta ssa-v1-import /path/to/hsir-v1.json

The new import entry is **not a native check**. Its output always has
status=analysis_only_no_native_check and native_validation=not_run,
even when the imported file contains a false/old checked marker.
The import result cannot be used by LLVM build routines as native
authorization. The original CLI and legacy SSA paths remain unchanged.

## Executed local evidence and unrun tests

A local isolated Python environment ran:
    python -m unittest test_hsir_scalar_bridge test_hsir_scalar_differential

Result: **27/27 passing** in the final local run, comprising 22 mapping/negative tests, 3 Python differential tests and 2 native C control tests. Of these, 22 test exact AST shape and
fail-closed rejection of ownership, FFI, resource, generic and
unmodeled expressions. Three independently interpret source-bound
and translated scalar ASTs on 60 bounded integer inputs, verify a
deterministic output, and detect an intentionally incorrect +1 to +2
translation. These are finite *synthetic* fixtures, not a compiler
soundness proof or a representative benchmark.

The repo-level tests in tests/test_hsir_sourcebound_ssa.py and
tests/test_hsir_v1_import_cli.py have been committed but **not run**
in the execution container because the complete Hepta PR branch
is unavailable locally (GitHub clone DNS fails). They exercise the
actual CFG/SSA verifier and CLI, preserve the no-codegen claims, and
reject unsafe source formats. Native Rust, C/C++, hardware and full
production qualification were not executed.

## What still blocks full P0-P7 acceptance

P0 source-level branch reconciliation and single compiler authority;
P1 complete type/loan/region/provenance representation and
source-to-IR/backend refinement; P2 arbitrary real C projects;
P3 cross-toolchain/platform ABI; P4 C++ classes/RAII/templates
with safe migration; P5 complete LLVM backend plus meaningful
memory and latency benchmarks; P6 real-model Agent tests;
P7 real hardware, long-run performance and recovery. All remain
open and whole_project_blockers_closed=false.


## Repeat from a full checkout

The isolated local test command in this report assumes the locally staged test
modules are directly importable. From the real repository root, run:

    python -m unittest discover -s tests -p 'test_hsir_scalar*.py' -v
    python -m unittest discover -s tests -p 'test_hsir_sourcebound_ssa.py' -v
    python -m unittest discover -s tests -p 'test_hsir_v1_import_cli.py' -v

The second command depends on a checkout with working CFG/SSA and compiler
modules, and was **not run** in the environment used for the local 27-test
record. A missing native toolchain or unsupported schema must be reported as
not run/rejected, never silently counted as passed.

## Further executed independent native C controls

A separate hand-written C11 loop/branch reference (not an automatic C-to-Hepta
translation) was compiled using GCC 14.2 and Clang 17, each with -std=c11,
-O2, -Wall, -Wextra, -Werror, -shared, and -fPIC. Each native executable
function was called across the same 60 defined integer inputs (-10..49)
and compared with the translated scalar AST evaluator. Both matched.
An intentionally incorrect C program (+2 instead of +1 for the then branch)
was independently compiled and detected as a mismatch.

The final local Python run included
tests/test_hsir_scalar_native_oracle.py and passed 27 tests total.
The exact uploaded Git blobs for the four locally tested files, the
compiler identities, the finite denominator, and explicit limits are
preserved in evidence/p1-sourcebound-scalar-local-20261025.json.
No Hepta LLVM/native binary or real Rust compiler was executed here.
