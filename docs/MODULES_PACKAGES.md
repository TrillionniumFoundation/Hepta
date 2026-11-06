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
An explicit local candidate set can additionally constrain and resolve versions,
as described below.
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

No remote registry, network version resolver, cyclic imports, re-exports, glob imports,
incremental cache or arbitrary multi-file edit transaction is implemented.
One semantic patch changes one body while validating and coordinating with its
complete imported graph.


## Offline local version resolution (P12 increment)

A dependency may use exactly these three fields instead of `path`:

```toml
[dependencies]
math = { package = "math", version = ">=1.2.0, <2.0.0", candidates = ["../math-1.2", "../math-1.9"] }
```

Every candidate must already exist locally, declare `kind = "lib"`, and have
exactly the requested package name. Paths are relative to the declaring package.
Aliases need not match the package name. The resolver reads manifests and source
entry metadata, never downloads code, executes source, or runs build scripts.
Missing candidates or invalid package metadata are errors, not silently ignored
alternatives. Transitive dependency declarations are inspected when a candidate
is reached during search. An invalid dependency declaration on a reached candidate
is an error, not a version conflict that silently selects another candidate.

Requirements are exact `major.minor.patch` versions, optionally prefixed by
`=`, `>=`, `>`, `<=` or `<`. Comma-separated comparisons are ANDed. Leading zeros,
prerelease/build suffixes, wildcards, caret, tilde and OR syntax are unsupported
and rejected. Requirements have at most 256 characters and eight comparisons.
This restricted syntax does not claim full SemVer range compatibility.

For candidate dependencies, one canonical local path is selected per `package`
name across the reachable graph. All referring edges must allow that path and
version. The resolver visits dependency aliases in sorted order, tries higher
numeric versions first (canonical path order breaks equal-version ties), and
backtracks when later requirements or dependency cycles make a choice impossible.
It returns the first complete solution in that deterministic order, not a globally
optimal version vector. Each load rebuilds the reachable graph, including
candidate constraints, rather than reusing dependency edges from an earlier
resolution. Each declaration permits 1–32 distinct candidates; a search permits
at most 64 selected candidate identities and 4,096 graph attempts.
Exhausting a bound reports `E_PACKAGE_RESOLUTION_LIMIT`, never a proof that the
graph is unsatisfiable. A fully exhausted search reports `E_PACKAGE_RESOLUTION`.
These bounds are search limits, not a global compiler memory/CPU guarantee.

Existing `{ path = "..." }` dependencies remain fixed by path. They can retain
multiple versions of the same package name, and do not create candidate-version
constraints. This preserves legacy graphs. A fixed path and a selected candidate
that resolve to the same directory share one loaded package object.

`hepta lock` and `--locked` use the same resolver. The existing `hepta.lock.v1`
format records the selected graph, versions, manifests and source content. It
does not pin every unselected candidate's bytes. Resolution is recalculated on
each fresh load: if an available candidate changes enough to produce a different
selected graph, `--locked` refuses the old lock. Refreshing requires an explicit
`hepta lock`; no fallback ignores a conflict or silently rewrites a stale lock.
A lock does not authenticate authorship or guarantee availability of candidate
paths on another computer. Layout-preserving relocation remains supported.

This implements bounded offline candidate selection as a P12 increment. Remote
registries, registry indexes, downloads, general dependency solving, signed
packages/releases and production ecosystem compatibility remain open.


The offline regression entry points are:

```sh
python -m unittest discover -s tests -p test_package_resolution.py -v
PYTHONPATH=. python tests/package_resolution_oracle.py
```

The independent oracle enumerates all assignments for 500 deterministic mixed
three-identity graphs, including fixed paths and candidate cycles. It checks
satisfiability and the returned graph without reusing the resolver's range or
search implementation. Neither entry point compiles or executes Hepta programs.
