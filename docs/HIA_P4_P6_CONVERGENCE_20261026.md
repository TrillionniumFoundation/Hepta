# HIA v6 P4/P6 exact-blob convergence — 2026-10-26

This is direct development on the integrated HIA v6 code, **not** a claim of all
P0–P7 blockers closed and **not** a whole-tree import from older divergent PRs.

## Immutable starting point

- Base: PR #242, exact `29c0e22dc1067f9fb5f9e5e2353e031acec90e54`.
- Old source branches consulted: P4 PR #240 `1c2baef01ada7635e880a9c19e21a3a93517f73f`,
  P6 PR #237 `40518e28718ee275e8efe7c9f36f3343e58adc3b`.
- GitHub compare confirms #240 and #237 **diverged** from the active HIA tree;
  importing their entire changed file blobs would silently discard unrelated
  more recent source work.

## P4: preserve newer canonical migrator

The HIA v6 tree's existing `hepta.c_migrate._conditional_value` already
recognizes nested parenthesized C++20 lvalue ternaries through strictly
type-preserving `ImplicitCastExpr` wrappers and reuses the checked pure
`_ternary` path. PR #240's narrower single-wrapper source patch therefore
must **not** replace current code.

Only the missing adversarial regression fixtures are brought forward:
- ternary requiring unsigned-to-signed integral conversion;
- ternary with side-effecting postfix increment.

Both must reject without creating output. A local Clang 17 `-std=c++20`
source-only AST inspection observed `IntegralCast` for the first and
`UnaryOperator ++` for the second, whereas an admitted lvalue ternary
has a type-preserving `LValueToRValue` wrapper. These were **independent
upstream-Clang AST controls**, not actual end-to-end Hepta migrator runs.

## P6: restore structured source graph identity refusal

The v4 pinned Agent semantic inspector previously accessed `graph.identity`
directly twice. An absent attribute could raise `AttributeError` instead of
the declared `WorkspaceError(E_AGENT_IDENTITY)`. A mutable/dynamic identity
property could also produce a different report than was originally checked.

The repair captures `getattr(graph, "identity", None)` once, validates the
exact 64-hex identity and later reports **that same validated value**.
Regression tests require rejecting missing attributes without leaking an
untyped exception and returning the first pinned identity after exactly
one read from a deliberately changing property. The existing test for graph
mutation after lowering is retained unchanged.

## Recommended exact-source acceptance

```bash
python -m unittest tests.test_agent_semantics tests.test_cpp2hepta_l1 -v
python -m unittest tests.test_hia_program tests.test_hia_vm_call_depth -v
python tools/release_check.py
```

No complete checkout exists in this execution environment. Actual repository
unittests, pinned Rust/Clang20 native Hepta qualification, ABI differential
execution, full language semantic soundness, arbitrary C/C++ migration,
real-provider Agent trials, physical devices, production performance and
source-to-Core/backend refinement are **not evidenced by this change**.

`whole_project_blockers_closed=false`.
