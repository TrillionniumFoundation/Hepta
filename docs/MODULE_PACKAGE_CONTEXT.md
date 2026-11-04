# Consistent package context for shared modules

Module identity is a resolved file path, but imports inside a module are
resolved using its package's source root and dependency aliases. Reusing the
same file under a different package context would silently reuse the first
context's entire import graph.

## Reproduced wrong result

Consider an ordinary application with a dependency declared as
`dep = { path = "src/vendor" }`. Both packages use their default `src` source
roots. The application helper returns 7; the dependency helper returns 42.
The dependency's `src/lib.hepta` contains:

```hepta
import helper;
pub fn answer() -> i32 effects {} { return helper::value(); }
```

With only `import dep`, `dep::answer()` returns 42. Adding the unused import
`import vendor::src::lib as unused;` before `import dep` made the same call
return 7. Reversing those two imports restored 42. Both C and Rust frontends
accepted all cases; actual GCC O0/O3 with UBSan and the public locked CLI build
confirmed the differing runtime results. Rust runtime was not available in the
local discovery environment.

These are ordinary regular files, without symlinks or concurrent changes.
Each lock was freshly generated. The graph digest changed with the source
edit and accurately recorded the selected edge: this is wrong package-context
selection, not a stale-lock acceptance or hash-collision claim.

## Narrow refusal

The loader's existing path-cache hit now compares the cached unit's canonical
package root with the requested package root. Different roots reject with
`E_MODULE_PACKAGE_CONTEXT` at the import that attempted conflicting reuse.
Both ambiguous import orders reject before checking or native compilation.

Package root is the comparison key, not the package name, version, dependency
alias, or source root. Distinct package roots may have identical metadata or
overlapping source directories but different dependency namespaces. Repeated
aliases and shared dependency diamonds resolving to the same canonical root
continue to deduplicate.

This does not choose an implicit owner by searching for another manifest. A
single local path keeps its existing local-import context; a single declared
dependency path keeps its dependency context. Nested vendored layouts and
overlapping source roots are not rejected merely for existing. Only conflicting
reuse of one physical source in one loaded graph is refused.

Using `(path, package)` as a cache key alone is not an equivalent repair:
generated symbols and reports remain file-path based. Supporting multiple
instantiations would need a separate namespace design. This repair changes
neither that design nor manifests, lock schema, checker or backend semantics.

## Evidence requirements

Regression controls cover both ambiguous orders, locked/unlocked loading,
directory/manifest/direct-source entrypoints, source overrides, equal metadata
with different roots, same-root aliases and shared dependencies, ordinary
single-context vendor/local imports, and real CLI entrypoints. Positive finite
scalar controls use actual GCC O0/O3 with UBSan. Rust parity runs only with an
actual compiler, after C prerequisites; missing Rust is an explicit local skip,
not native success.

`python tools/test_module_package_context.py` is the strict hosted gate. It
requires actual GCC and pinned Rust, the frozen unique planned/executed method
inventory, and zero failures, errors, skips, expected failures or unexpected
successes. The workflow binds the exact PR head/tree on Linux x86-64 and
AArch64 and retains original logs and source/tool identities. Hosted results
must be reported for that commit rather than inferred from another draft.

This is finite module/package correctness evidence, not full isolation,
filesystem atomicity, resource-budget accounting, whole-language soundness,
foreign implementation correctness or production readiness. Other module
scope/generic fixes and Part03 relocation are not included in this independent
patch. No recursive, object-layout or worker-lifecycle qualification is added.
