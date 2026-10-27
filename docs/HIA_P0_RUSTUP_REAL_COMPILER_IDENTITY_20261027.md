# Hepta P0/P7 — Rustup real compiler identity on the HIA v7 integration

**Exact recipient:** PR #289 `5973146bb717473997fed4abfaadf41bb8e88c86`.
**Reviewed donor:** PR #115 `4ac39e626acd7f78e2f66708be741e78308b4e6a`,
specifically the `hepta.backend` compiler-selection contract and its
`tests/test_toolchain_selection.py` regression module.

## Actual conflict resolved

The HIA v7 recipient `find_rustc()` used `Path(...).resolve()`
and could return a `rustup` dispatcher when `rustc` was a proxy symlink
or hardlink. The resulting `toolchain_info` queried the dispatcher using
its own argv identity and could hash the dispatcher bytes rather than the
selected pinned compiler. In addition, `Path(rustc).read_bytes()`
materialized the entire compiler binary just to compute its hash.

## Bounded same-owner implementation

- Transplant only the reviewed `_resolve_rustc_executable()` and
  `find_rustc()` from #115; no C++/Task I/O/other backend donor code was
  overwritten, preserving the v7 receiver's current runtime semantics.
- Resolve a rustup proxy via `rustup which rustc` with
  `RUSTUP_AUTO_INSTALL=0`, require one absolute executable that is not the
  manager itself, refuse malformed answers/timeouts/absent explicit compiler.
- Prefer the explicit SHA-locked bootstrap path before ambient PATH for
  implicit selection, as the donor already does.
- Reuse existing `native_tool_identity.digest_executable`, the **sole**
  bounded 1 MiB-chunk compiler hashing authority. Hash the actual selected
  compiler both before and after the `-vV` identity query; reject changed
  bytes and return a digest bound to those exact bytes. This does not prove
  malicious OS execution or toolchain provenance.
- Carry exact donor toolchain selection regression fixtures, plus
  no-whole-file-hash and mutated-digest-negative controls. The latter
  simulates one digest changing across the query, not an actual hostile
  process racing execution.

## Exact-head acceptance

```sh
python -m unittest tests.test_toolchain_selection -v
python -m unittest tests.test_backend tests.test_native -v
```

Our current container has Python/Clang/GCC, but no actual pinned Rust compiler
or a resolved GitHub clone. These committed in-repository tests are
**NOT RUN** here. The previous donor's native tests are attributable only
to its earlier exact source SHA and do not automatically apply to this merge.

P0 cross-branch semantic unification and all P1–P7 production prerequisites
remain OPEN. This is a narrow toolchain binding and memory-budget improvement,
not source→Core→native soundness proof.
`whole_project_blockers_closed=false`.
