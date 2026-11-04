# Module scope and package-context composition

This candidate combines two reviewed source changes rather than inferring a
combined result from their separate CI runs:

- #664 at `aa68fb7354f187f44aef19055bfa18f252d234cb`, tree
  `2e4a6ad492f8833ad17c851eedcd3cc67007da1d`, including its complete function,
  nominal-type, local-binding, generic-binder and same-source restrictions.
- #665 at `017e8c469f3b55f6b4ac6ae0391527442d1432b7`, tree
  `af7ab6e78e4dcbfdd0383f525057c377a0af3ae9`, adding the completed-unit
  package-root consistency check and its regression controls.

The common ancestor is `f2b76f5741c83822be2e12cf5a50b50a8d27b96a`. The
candidate preserves #664's complete tree and adds #665's three production
lines at the existing cache hit. It does not copy the older #665 loader over
the later scope repairs. No checker, backend, package-loading rule or binding
transformation is otherwise changed. The component documents describe their
original independent changes; this document defines their combined boundary.

## Diagnostic order is part of the contract

The loader first checks source-root escape, then an active import cycle, then
the package context of an already completed cached unit. Escape and active
cycle diagnostics retain their priority. Parse, read, import-alias, C-import,
lock or other graph errors encountered earlier in traversal can still stop
loading before a conflicting cache hit is reached.

When a completed file is reused under a different canonical package root,
`E_MODULE_PACKAGE_CONTEXT` raises from graph loading at that second import.
It therefore precedes the later module privacy/namespace/scope transformations
and checker diagnostics. The module exception occurs before an `Analysis`
object is constructed. Its root order and original import span are preserved.
This is not a blanket claim that context errors always take precedence.

Same-root aliases and real dependency diamonds remain valid cache reuse.
When such a graph contains a source-local generic/nominal collision, analysis
still returns a populated project and checked result with check-phase
`E_GENERIC_PARAMETER`, without generated code. Renaming that generic binder
restores the valid source case. Unrelated module nominals do not reserve a
generic parameter's spelling, and local values do not bind to foreign functions.

Single-context local and dependency imports retain their own package contexts:
the finite helper fixture returns 7 through its local route and 42 through its
dependency route. No nearest-manifest ownership fallback is introduced. The
cache key and path-based namespace identity remain unchanged; even apparently
context-independent files cannot be reused under two different roots.

## Exact combined inventory

The #664 runner has 450 unique methods and the #665 runner has 124. Their
86 shared identities are executed once, giving **488 inherited methods**.
Fourteen new intersection methods make **502 unique combined methods**.
The context component contributes 13 new context methods plus seven protocol-v3
and 18 workspace methods absent from the scope runner. Adding only the 13
context methods would omit those 25 inherited controls.

The additional `tests.test_module_scope_context_union` suite covers the
intersection: successful aliases and diamonds with generic/local identities;
same-source refusals through valid reuse; precise context-before-later-error
diagnostics in both import orders with single-route counterexamples; local and
dependency helper routing; distinct equal-named packages; source overlays;
escape/cycle priority; and physical-checkout CLI behavior. Positive native
controls are finite scalar/record/enum/generic cases.

`tools/module_scope_context_union_inventory.json` freezes every complete test
identity in execution order. The new runner rejects a changed, missing,
duplicated or reordered identity, including a same-count substitution. It
records planned, executed and passed identities explicitly, because native
receipt output can interrupt ordinary unittest progress lines. The existing
component runners and their historical counts remain unchanged.

## Qualification requirements and limits

Run `python -B tools/test_module_scope_context_union.py` with actual GCC and
`RUSTC` pointing to the real pinned Rust 1.90.0 binary. The gate refuses missing
tools, imports outside the physical checkout, any inventory mismatch, failures,
errors, skips, expected failures or unexpected successes. It hashes the
selected source files and records actual toolchain identity.

The dedicated workflow checks out the exact PR head and records its Git tree,
compiler versions and executable digests on Linux x86-64 and AArch64. The
finite positive controls compile and execute with GCC O0/O3 and UBSan and
with pinned Rust O0/O3; native receipts bind generated source, artifacts and
observed results. Artifact upload runs even after a failure. Existing component
and repository workflows remain intact. A new head needs its own complete
results; previous heads and separate component greens do not qualify it.

The initial local execution of the 488 inherited methods recorded 400 passes,
46 skips, 24 failed methods and 18 errors. The unpassed methods require the
absent real Rust compiler, through existing prerequisites or native-reference
assertions. Those original outcomes are retained; none is converted into a
passing result, a new skip, a stub compiler or a relaxed assertion. Hosted
qualification must resolve these prerequisites and execute the full inventory.

This is finite module/package composition evidence, not security isolation,
filesystem atomicity, whole-language soundness, resource accounting, recursive
execution qualification, worker-lifecycle qualification or production readiness.
