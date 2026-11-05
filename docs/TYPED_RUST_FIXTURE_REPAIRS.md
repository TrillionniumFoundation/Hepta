# Preserve typed qualification while repairing Rust fixture kinds

This qualification-only correction is based on exact #719 `b67d1a00acec941ecc7f4218020a2eae8f6cd2b4`.
It copies all 19 reviewed qualification/documentation changes from #708
`021c0731e6105dcda7fe0fcafc4b62836e81657e` byte for byte, including the exact
#705/#706 Unit and numeric repairs and the #708 ordinary-store trace repair.
Production, all ten workflows, all source libraries and original archived
suppliers remain unchanged. No compiler defaults, output permissions, signal
assertions, optimization flags, timeouts or skip policies change.

Three existing runnable callers inherited their original defects: the Unit
trap omitted binary emission and compilation, the shared numeric helper omitted
binary compilation, and the store trace omitted binary compilation. The original
compiler correctly defaults to a library. The repairs request executable kinds
explicitly, without chmod or a production workaround. Three retained upstream
contract regressions mock Rust compilation/execution but retain actual C work.
They are not native Rust evidence.

## Preserve provenance and inventory

The complete #708 repair helper and inverse manifest retain their exact Git
blobs and SHA-256 identities. `verify_typed_fixture_repairs.py` pins both before
using them, then checks every downstream repair against its own exact repaired
and original identities. Exact inverse edits recover the historical verifier,
runner and inventory bytes. Historical component manifests, every existing
archive, and every previous production inverse remain unchanged and active.
Only verified original projections feed historical hash checks. Test discovery
and execution always use the actual repaired source, not projected test code.

All 407/415 original typed methods remain in relative order. The three added
contract regressions produce 410 C-only / 418 required-Rust identities. The
inherited store, array, numeric and Unit inventories are respectively
352/360, 335/338, 321/323 and 289. Required Rust still fails closed when absent.

The versioned typed union retains every original 484/492 method in relative
order and now requires 487/495 methods. All 65 package and 12 joint migration
identities are unchanged. The union gate's inventory preflight can be run with
`python -B tools/qualify_versioned_typed.py --verify-only`; it does not execute
test bodies or native programs. None of the full union aggregate is executed
as part of this repair's bounded local evidence.

## Bounded reproduction and evidence limits

Run source verification without test execution:

```sh
python -B tools/verify_typed_fixture_repairs.py
python -B tools/verify_typed_stdlib_sources.py
```

The three Rust-independent contracts can be run explicitly, keeping the broader
aggregate separate:

```sh
PYTHONPATH=.:tests:tools python -B -m unittest -v \
  test_c_unit_values.UnitValueTests.test_rust_trap_requests_binary_contract_without_native_rust \
  test_c_float_int_casts.FloatIntCastTests.test_rust_success_consumer_requests_binary_without_native_rust \
  test_c_store_adt_composition.StoreAdtCompositionTests.test_rust_trace_requests_binary_contract_without_native_rust
PYTHONPATH=.:tests:tools python -B -m unittest -v test_typed_stdlib
```

The 12 unchanged migration methods are a separate bounded check:

```sh
PYTHONPATH=.:tests:tools python -B -m unittest -v test_versioned_typed
```

Those scoped checks do not replace the full inherited compiler/library/package
gates. Fresh exact-head hosted execution is needed for native Rust, ARM and
Python 3.11. Old hosted successes, local mocks and queued workflows do not
qualify this corrected source. No new workflow, fanout or dispatch is added.

## Retained failures and exclusions

Original upstream Unit/numeric/array/store hosted failures remain failures;
their exact runs and causes are retained in the copied contracts. Original
#710's store workflow also failed at its original head in
[run 42025621232](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42025621232).
No old result is relabeled by this source correction. Original #719's two
failed Python 3.13 aggregates and standalone bytes oracle retain their
`cc1`-killed result and unproven cause. That heavy oracle is not rerun or fixed
here. Earlier interrupted #721 execution remains unknown, not a pass.

Initial local candidate construction stopped because the #719 verifier uses an
inline identity expression whereas #721 uses a named byte variable. The
incomplete-build import failures are retained separately. Corrected construction
adds only the intended inverse projection to each existing shape.

No full 410/418 or 487/495 aggregate, recursive program execution, source-literal
validation, function-signature audit, output/hardlink/alias investigation,
adjacent security repair or signature guard is included in this scope. Reduced
evidence does not remove those gates or count unexecuted methods as passing.
No whole-language, production, performance or complete blocker-closure claim.
P01/P11/P12 remain PARTIAL. Draft only; no PR/main merge, release or deployment.
