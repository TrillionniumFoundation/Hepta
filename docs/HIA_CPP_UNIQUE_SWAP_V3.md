# Captured unique_ptr member swap profile v3

`cpp20-direct-unique-byte-array-reusable-swap-v3` extends the existing
declaration-bound migration of `std::unique_ptr<unsigned char[]>`. Select it
explicitly with both `reusable_released_owners=True` and `owner_swaps=True` in
`lower_unique_reset_project`. The v1 and v2 profiles continue refusing member
swap. Invalid profile option types reject before opening the project.

## Ownership semantics

An owner slot and its allocation have separate identities. A bound `a.swap(b)`
exchanges the allocation identity, current length and corresponding Hepta
linear binding between the two slots. Source variable names and declaration
order stay with the slots, so destruction still proceeds in the C++ reverse
declaration order. This also preserves the order of observable frees after a
swap. The default deleter has no additional modeled state.

The translation introduces neither a raw pointer nor a duplicate linear value.
Live/live, live/empty, empty/live and empty/empty swaps use the same rule. Self
swap preserves the slot. Every subscript is checked against the current
allocation length, so a guard about an allocation that previously occupied the
slot does not justify a later read. Empty owners cannot be read. A continuing
branch may not change owner bindings under this profile's existing join rule.

## Admission and trust boundary

The complete active Clang translation unit and library declaration census are
captured. Member references must bind to the compiler-owned standard-library
probe, and the expanded standard-library headers must equal the reference
configuration. This binds the operation to the captured default-deleter
contract; it is not a formal proof of the standard-library implementation.

The profile remains sequential LP64 with explicit capacity and index guards.
Custom deleters, retained aliases, escaped pointers, free-function `std::swap`,
move assignment, general control-flow joins, C++ class ABI, concurrency and
process-crash recovery remain outside its admission boundary.

## Reproduction and evidence

`tools/qualify_cpp_unique_swap.py` compiles the original C++ component and the
standalone Hepta/Core/LLVM result. Both are called by independently compiled C
callers. The target imports no original C++ object. An independent chronological
oracle checks returned values, allocation/refusal counts, allocation identities,
ordered frees and zero live resources. It covers zero lengths, unequal lengths,
boundary indexes, capacity refusal, allocator refusal, exceptions, early returns,
empty-slot adoption, repeated swap and self swap. It also compiles a deliberately
wrong but resource-safe cleanup order; that control must fail the lifecycle
oracle. Removing a required owner drop must reject before object publication.

Fresh-source refusal controls cover v1/v2 profile boundaries, stale lengths,
empty reads, branch joins, retained aliases, free-function swap and escaped raw
pointers. `tests/test_cpp_unique_swap.py` exercises the same native qualification
and admission entry points when Clang20+ and system C/C++ tools are available.

The two project/API variants are authored integration fixtures. This extension
does not add a real upstream project upgrade sample. It is finite native
differential evidence, not an all-input source-equivalence theorem. Migration,
native build, execution and observed peak RSS costs are recorded; human labor
and an application performance advantage are not inferred.
