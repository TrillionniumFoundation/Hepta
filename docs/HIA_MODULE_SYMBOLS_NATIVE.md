# HIA native module-symbol policy

The explicitly selected `HEPTA_HIA_MODULE_SYMBOLS_MANIFEST` image executes the
existing module duplicate-declaration and import-alias rules, local/type/term
name selection, qualified imported names, privacy/extern/export visibility,
local enum namespaces and built-in `Result` namespace treatment in ordinary HIA.
The complete existing resolver policy is implemented; it is not a whitelist of
particular projects or names. There is no host-policy fallback after selection.

The binary packet transports declaration and import facts as UTF-8 byte ranges.
HIA validates every table/range/flag before reading payloads and emits the
resolved UTF-8 name or the original module diagnostic category. Output shortage
and malformed packets reject without publishing partial output. Per-call
buffers are private. The inherited 8 MiB transport bounds inputs; unsupported
size rejects explicitly rather than silently selecting the old implementation.

The generator is host authoring code. The checked-in HIA assembly is the actual
runtime algorithm and compiles with the existing source-selfhosting compiler.
The host bridge only serializes AST facts and materializes strings/diagnostics.
The default remains the old path pending whole-stack qualification.

## Still foreign and not closed

Filesystem reads, symlink/package-root checks, dependency graph traversal and
cycle diagnostics, package/lock parsing, source hashing and prefix construction,
AST traversal/copying, semantic checks and build/runtime orchestration still run
in Python or external tools. This application does not claim full native module
or package loading, a default switch, clean-machine acceptance or legacy removal.
Whole-stack native-only retirement remains incomplete.
