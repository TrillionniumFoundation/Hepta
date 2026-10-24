# Same-instance scalar C frontend

This integration is an exact child of #20 (`64c85e4716eb9882bdd667beffe7e36f2fc30fb9`).
It reuses the independently reviewed #21 same-instance helper and transport,
while retaining #20's complete active-TU inventory and #19's direct-library
resolved-path guard. It does not introduce #18's competing main-only inventory.
Neither the newer #14 (`cbb03dfd6efbe68253c2be1e59eacdeb93f9dfc5`) features nor
its release qualification are imported. See C_SCALAR_INTEGRATION.md for policy
and diagnostic-precedence reconciliation.

## Enforced boundary

`migrate_c` requires a locally built `hepta-c-frontend`, selected through
`HEPTA_C_FRONTEND` (or that executable name on PATH). Missing dependencies fail
closed with `E_C_FRONTEND_ENV`. There is no AST-only fallback.

The helper installs `PPCallbacks::MacroExpands` before parsing, in the same
CompilerInstance that produces the complete translation-unit AST. It compares
`SourceManager::getExpansionLoc` FileIDs with the main FileID, not presumed
filenames or parsed textual diagnostics. Thus a main-file `PLUS` operator macro
is detected even though the JSON expression AST has no macro location wrapper.
Actual active main-file expansions, including empty macros, builtin macros,
macro include names and expansions in `#if`, reject with `E_C_MACRO`.
Pure `defined`/`#ifdef` references without expansion and inactive source are not
rejected by this callback policy. Unused macro definitions remain allowed.
Header-internal macro expansions and canonical included-header typedefs remain
supported. This is not a complete preprocessor policy or inactive-branch audit.

The source SHA-256 and length come from the same SourceManager buffer. Integer
and pointer widths and the target triple come from that CompilerInstance's
TargetInfo. AST JSON is transported as an unchanged string: reserializing its
objects can reorder keys and invalidate Clang's globally elided physical-file
locations. The Python consumer preserves that original order.

No envelope is emitted unless ToolInvocation succeeds, diagnostic error/fatal
flags are clear and exactly one translation unit completed. The caller checks
compiler identity, target, source binding, data model, event shape and protocol;
duplicate or concatenated envelopes reject. Both stdout and stderr are bounded
while reading, with a combined 32 MB limit and 30-second subprocess deadline.
The helper's 64 MiB AST check occurs after dumping; it is not a process-memory
hard limit. The subprocess may consume memory before either output check.

## Reproducible local build

The qualified configuration is Linux x86-64, Debian Clang 19.1.7 (3+b1), matching
LLVM 19.1 libraries and headers, and G++ 14.2. The two official development
packages and their SHA-256 values are in `c-frontend-toolchain-lock.json`.
Verify those archive hashes before extracting into an isolated prefix; no system installation is required. Matching
`libclang-cpp.so.19.1` and `libLLVM.so.19.1` are also required. The build script
performs no network downloads, records the source, Version.inc and supplied link-library file hashes and
requires explicit paths. Runtime checks reject other compiler identities and LLVM versions. The receipt
does not hash every extracted header or prove which transitive shared-library
files the dynamic loader used; retain a controlled matching local toolchain.

```
python tools/build_c_frontend.py \
  --include /isolated/usr/lib/llvm-19/include \
  --clang-library /isolated/lib/libclang-cpp.so.19.1 \
  --llvm-library /isolated/lib/libLLVM.so.19.1 \
  --output /isolated/bin/hepta-c-frontend
export HEPTA_C_FRONTEND=/isolated/bin/hepta-c-frontend
# Set LD_LIBRARY_PATH if required for those isolated matching shared libraries.
python -m unittest discover -s tests -v
```

The selected `clang` supplies its resource directory and requested target as
configuration, not as independent evidence of the parsed source semantics.
The helper uses a fixed raw C11 profile; it accepts no user-supplied compiler
flags, PCH or module configuration. Other toolchains are unqualified, not
silently treated as equivalent.

## Evidence and limits

Before the #21 donor repair, five regression tests produced eight failing assertions:
operator macros under multiple unusual paths and `#line`, empty/nested macros,
header-defined operators, active conditional expansion and missing-helper
fallback. This includes dependency-enforcement tests, not eight distinct
miscompilations. No wrong arithmetic output is alleged for PLUS.

The same-instance prototype passed 23 real compiler cases, including parse and
preprocessor errors with no stdout. Independent review caught the AST key-order
transport issue before repository integration. The #21 donor passed 39 migration tests, seven protocol tests and 685 full tests.
These are historical donor results, not qualification of this integration.
The combined exact-source results are recorded separately.


Still not established: frozen transitive header/configuration CAS, arbitrary C
translation correctness, foreign implementation safety, inactive declarations,
project/C++ macro enforcement, physical hardware qualification or whole-language
soundness. No remote CI queried and no merge or deployment performed.
