# Physical union of module scope and local bindings

This integration starts from draft #660 commit
`1d34e3ca0ff8cb3d1ebd29cc9c8d8905b6178282`, tree
`5565a1d1bc61fb1991ecfe626682b1dca8724f8a`, which combines function-scope #658
and nominal-type-scope #659. It incorporates the local-binding pass from #661
commit `dce4f11ca800a0c6b3c8dcaeafc0caf8fd312942`, tree
`6985ab5539c95a34ead969acda0d70b912379c02`. The common source ancestor is
`f2b76f5741c83822be2e12cf5a50b50a8d27b96a`.

The helper is unchanged from #661. The loader reuses #660's `flat_functions`
inventory for both collision selection and generated-name freshness. Ordering
is significant: load the complete graph, compute flat inventories, deep-copy
each declaration, isolate local bindings, then resolve module references.
Moving reference resolution earlier would reject legitimate colliding locals.
The pass continues to exclude same-module function spellings and protected C
boundary parameters. It never renames call targets, types, aliases or fields.

## Three explicit diagnostic reconciliations

An original, unmodified run of #661's 32 methods on the physical union produced
one failure, two errors and one missing-Rust skip. These original outcomes are
not successful integration evidence. All three mismatches arise because a
protected exported parameter's name expression now reaches #660's earlier
module-scope guard:

- The protected parameter/local duplicate with `return secret` raises
  `E_MODULE_SCOPE` before checker collision/duplicate reports.
- The exported C keyword parameter with `return switch` also raises
  `E_MODULE_SCOPE`; its extern counterpart still reaches `E_C_IDENTIFIER`.
- The public CLI's same exported-keyword fixture emits `E_MODULE_SCOPE`, rather
  than the isolated local-binding branch's `E_C_IDENTIFIER`.

The three methods now assert the exact module diagnostic, including original
source span. Complementary exported fixtures retain the colliding parameters
and duplicate binders but return a literal. They still exercise the original
checker errors and unchanged parameter/local/header spellings. The extern
expectation is unchanged. No broad either-code acceptance, skipped control or
checker relaxation is used.

## Independent cross-fix controls

Nine new methods combine the mechanisms rather than merely repeating their
isolated suites. They cover a qualified public call with a same-spelled import
alias and scalar local; the corresponding forbidden private call; an unimported
nominal type argument alongside a renamed scalar; legitimate own/aliased types;
the existing generic-shadowing refusal; protected C diagnostic precedence;
generated C-symbol freshness; repeatable identities and source spans; and real
CLI subprocesses importing this physical checkout.

New native controls are finite scalar programs, compiled and executed using
real GCC at O0/O3 with UBSan. Separate Rust parity requires two scalar controls
at both optimization settings, after C prerequisites. New nominal checks are
loader/frontend-only, not new object-layout or native qualification.

## Exact-source gate

`python tools/test_module_scope_union.py` freezes **407 unique methods**: the
deduplicated union of the three existing runners has 398, plus nine new methods.
The original counts 107, 149 and 276 overlap and must not be added. All inherited
test methods remain, including the three explicitly reconciled methods.

The gate requires actual GCC and pinned Rust, checks the imported compiler root,
records ordered planned/executed test identities, and rejects failures, errors,
skips, expected failures and unexpected successes. Its workflow checks the
exact PR head/tree and clean source on Linux x86-64 and AArch64, records compiler
identities and retains original logs even when a test fails. CLI controls use
the same on-disk checkout; an in-memory loader replacement is insufficient.

Independent #660 or #661 CI does not validate this union. Its local results,
hosted native results and broader workflow results must be reported separately
against the new exact commit. A missing local Rust compiler is not a native
pass. Earlier in-memory experiments neither qualified the physical CLI nor
executed Rust and are not substituted for this gate.

The integration does not include other draft repairs or Part03 relocation.
It is finite regression evidence, not complete language soundness, arbitrary
object layout, recursive programs, worker lifecycles, foreign implementation
correctness or production readiness. No merge or deployment is authorized by
this integration work.
