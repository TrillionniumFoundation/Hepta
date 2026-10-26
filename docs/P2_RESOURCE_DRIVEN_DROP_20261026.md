# P2: finite verified Resource IR → actual Owned LLVM Drop helper composition

**Status:** partial native codegen consumption; whole-language HIA v1 executable ownership SSA is NOT implemented.

Exact parent: HIA + Resource IR v5 integrated candidate PR #166
`da6a1488de246d5bf686a8ab79575ecf16944667`.
This is an incremental change to existing `hepta.llvm_owned_backend`.
No new native compiler, parser, C/C++ migration engine or borrow checker is introduced.

## What changes operationally

`emit_owned_llvm` first regenerates actual checked-source Resource IR and runs
the existing independent resource graph verifier. It now passes the *verified
type table* to its existing `_Emitter` before generating LLVM.

When `_Emitter.drop(T)` visits a concrete Resource IR type entry, the new
`hepta.owned_drop_plan.derive_resource_drop_plan` derives which struct
fields or enum payloads actually carry an owner. `_Emitter.drop` consumes
those decisions when choosing nested native Drop helper calls. It also
independently checks the native layout name/order/type identities and
cross-checks every child-owner decision against the checked source's existing
`is_owned_type`. A mismatch refuses generation with
`E_LLVM_OWNED_DROP_PLAN` before Clang or artifact publication.

The known `Buffer<u8>` kind must match the independently verified Resource
IR type; its existing native allocator/deallocator functions are unchanged.
Absent *non-generic* concrete Drop types reject instead of silently trusting
an invented native type. Absent *instantiated generic* types retain the
existing finite checked-AST specialization as an explicitly unclosed fallback;
this is **not** complete independent IR-based Drop codegen.

## Real evidence, separated by scope

Pure `tests/test_owned_drop_plan.py` is locally executed (Python 3.13):
5/5 tests passed; exact committed helper blob must be compared against that
executed source. They cover nested struct/enum ownership, negative missing
dependencies/cycles, forbidden resource arrays/views and generic absence.

`tests/test_owned_drop_llvm.py` exercises the full checked Hepta source and
the existing Owned LLVM text emitter, including positive concrete Buffer
cleanup and forged field-owner/ordering negative controls. It MUST be run on
the exact full checkout; source/text inspection and offline helper tests do
not count as completed native integration qualification.

Suggested commands (independent of whether remote CI is queued):

    python -m unittest tests.test_owned_drop_plan tests.test_owned_drop_llvm -v
    python -m unittest tests.test_llvm_owned_backend tests.test_cpp_owned_llvm -v

## Remaining P1/P2 blocker

This makes a **finite resource-dependent part of code generation** consume
verified Resource IR. Scalar expressions, CFG, borrows, native allocator call
sites, owner moves, panic/error edges, Drop dispatch for absent generic
instantiations and actual machine lowering are still interpreted from
checked source AST in the existing Owned LLVM backend.

True HIA Core v1 closure requires a single executable type/value/ownership
SSA (including loan, drop, provenance and effects) consumed exclusively by
the backend, independent Source→IR and IR→Native validations, native
differential execution, and target-specific qualification.

whole_project_blockers_closed=false
