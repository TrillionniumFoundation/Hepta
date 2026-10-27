# HIA v6 VM call-depth budget alignment (P1/P2)

**Baseline:** PR #236 exact code SHA
`b41db78816c39ab59dd42d35c28426c54d1fe45d`.
This change is stacked and does not modify the main branch or replace
HIA's canonical verifier, interpreter, static budget analyzer, LLVM backend,
Agent semantics, C/C++ migration or native sandbox.

## Verified implementation defect

`hia_static_budget.analyze_static_budget` defines `max_call_depth` as a
**root-inclusive** number of live function invocation frames. The root alone
requires depth 1; a root calling a child requires depth 2.

The HIA VM `_Machine.invoke(fn, ..., depth=0)` instead rejected only when
`depth > max_call_depth`. As `depth` starts from zero, this admitted an
additional frame. In particular, `max_call_depth=1` admitted a child at
`depth=1`, despite the static analyzer correctly declaring that call graph
depth 2.

## Fix

Reject when `depth >= max_call_depth` before the invocation-entry tick or
execution of any callee instruction. The default 256-frame dynamic limit
continues to include the root frame; callers cannot request depth zero.

The independent `tests/test_hia_vm_call_depth.py` records:
- a root-only function passes depth 1;
- a root-to-child call rejects at 1 **before executing the child**;
- two sibling calls are allowed with a depth bound of 2;
- recursive Core is admitted by the Core verifier but deterministically
  stopped at exact root-inclusive limits 1, 2, 3 and 5;
- static `max_call_depth` and the dynamic VM convention agree.

The finite evaluator's `HIAProgramBudgetExceeded` remains a **budget stop**,
not an HIA language trap, not ordinary owner cleanup, not a native machine
stack bound, and not a production whole-language soundness guarantee.

## Run locally on exact checkout

```bash
python -m unittest tests.test_hia_vm_call_depth tests.test_hia_static_budget tests.test_hia_program -v
```

Any completed native or project-wide qualification must use this exact
source commit and matching toolchain. The CI queue is not an engineering
stop signal; no unexecuted test is counted as passed.

`whole_project_blockers_closed=false`.
