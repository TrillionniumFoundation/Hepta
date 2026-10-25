# P2/P7 Clang JSON intake budgets (2026-10-25)

Exact dependency: PR #99 head `193b1ffbce050d6da69b8050282b64e6511778ac` (and thus PR #98 / #97).

Clang process stdout was already bounded with shared file-backed capture,
but both strict C11 `migrate_c` and C++20 `migrate_cpp` used `json.loads`
without controlling parsed AST nesting or total reachable nodes.
`hepta.c_migrate._load_bounded_clang_ast` now serves both callers
before any recursive strict-source lowering.

The prototype caps UTF-8 JSON at 32,000,000 bytes, visited JSON values at
250,000 and post-decode nesting at 128 levels. Nonfinite JSON constants,
non-translation-unit roots, malformed JSON, deeply recursive decoder
exceptions, unknown values and invalid budget types reject as structured
`MigrationRejected` (E_CLANG_AST_FORMAT or E_CLANG_AST_LIMIT).
The bound applies to the *entire captured JSON tree*, not just the
function bodies selected for conversion.

An independent local Python 3.13 / Clang 17 mirror completed 9/9 checks,
including real C11 and C++20 Clang AST capture, malformed/nonfinite JSON,
node/depth/byte quotas and wrong budget types.
The same bounded adapter and negative publication tests are included in
`tests/test_clang_ast_limits.py`, requiring actual repository execution
before production qualification.

**Limits:** This is NOT an OS process memory/cpu sandbox, a bounded Clang
parser RSS guarantee, or a proof of Hepta frontend/native behavior.
json.loads still materializes at most the file-backed capture's bounded
byte input before iterative structure validation; the toolchain and
allocator remain trust dependencies. C++ L1 and C migration retain their
current fail-closed unsupported syntax/ABI obligations.
`whole_project_blockers_closed=false`.
