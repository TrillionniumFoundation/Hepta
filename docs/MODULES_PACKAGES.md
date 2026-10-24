# Modules and local packages

An optional `module name;` is followed by explicit imports:

```hepta
import math;
import codecs::binary as wire;
```

`math::sum` names a public imported function. `wire::Packet` names a public
imported type; `wire::Error::Truncated` names an imported enum variant. Import
aliases are unique and cannot collide with local declarations. Functions,
structs and enums are private by default; `pub` exposes them. C import/export
functions are module bindings with an explicit external symbol.

For standalone files, imports resolve below the entry file's directory. For
packages, they resolve below `source_root` (default `src`). A dependency alias
resolves to that library's entry; trailing path components resolve below its
source root. Source symlinks cannot escape the applicable source root. Cycles
and missing modules are errors. Shared modules are loaded once. Declarations
are flattened by AST transformation, never source-fragment splicing.

Generated identifiers beginning with `M` plus 16 lowercase hexadecimal digits
and `_` are reserved in source. Private names exposed in inspection metadata
therefore cannot become source-level access paths. Project identity hashes
source bytes, relative entry and resolved import edges, including alias
retargeting between already-loaded modules. Transactions recheck lexical path
bindings as well as bytes.

## Manifest

```toml
[package]
name = "app"
version = "0.1.0"
kind = "bin"
source_root = "src"
entry = "src/main.hepta"

[dependencies]
math = { path = "../math" }
```

Names are ASCII identifiers; versions are explicit major.minor.patch.
Dependencies must be libraries (`kind = "lib"`, default `src/lib.hepta`).
Unknown keys, remote registry/Git dependencies and build-script fields reject.
This mechanism never downloads or executes dependency scripts.

`hepta lock DIRECTORY` atomically writes `Hepta.lock` after rechecking the graph.
It hashes manifests, all `.hepta` files under participating source roots and
present C-import sidecars. `--locked` rejects changed bytes, added sources,
changed topology or missing locks. Paths are relative and the lock is portable
when package layout is preserved. It does not sign authorship, sandbox unsafe
execution or prove foreign implementations.

Directory, manifest and direct-source arguments are accepted by check/inspect,
emit/header/build/run. Files outside their discovered package source root reject.
Reports retain per-file spans and source/generated symbol mappings.

## C imports

`import-c` emits a reserved marker and paired `.imports.json`. Loading through
the project driver requires matching source and native-host identities. A
present original header within the owning package must match its recorded hash.
Metadata participates in graph identity and package locks. Cross-target reuse
is refused until a target-specific import profile exists. Low-level APIs using
handwritten extern declarations still carry explicit foreign assumptions;
metadata is not an authentication or sandbox mechanism.

No remote registry, version solver, cyclic imports, re-exports, glob imports,
incremental cache or arbitrary multi-file edit transaction is implemented.
One semantic patch changes one body while validating and coordinating with its
complete imported graph.
