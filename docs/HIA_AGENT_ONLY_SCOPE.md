# HIA Agent interface

HIA Core is the only language. High-level syntax, AST, source checker, migration
frontends and their native ports are removed, not frozen or delivered as a
compatibility package. The Python package name `hepta` and versioned Core schema
names remain identifiers; they do not provide a high-level source language.

`hia` accepts standalone Core JSON or explicit HIA assembly only. It offers
verification, instruction catalog, native ELF object generation and snapshot-bound
local editing. The hosted entry still requires Python.

The separate HIA-native stdio program provides capabilities, verify, compile,
render-assembly and direct assembly with no Python at runtime. The explicit
`hia-patch-core` application applies snapshot-bound structural edits and checks
both primitive Core programs natively. Durable Agent metadata, reference and
request authority, nominal/composite normalization, build/install ownership and
whole-product acceptance remain open. See HIA_CORE_ONLY_SCOPE.md.
