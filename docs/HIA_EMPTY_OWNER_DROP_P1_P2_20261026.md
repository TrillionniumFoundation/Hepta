# P1/P2 — zero/failed HIA Owner Drop has no foreign free(NULL) event

**Scope:** finite HIA program v6 owned-byte profile; source authority, Core
verifier, memory model, Clang/LLVM emitter and artifact publisher remain
exactly the previously existing ones. This is a native backend semantic
correction, not a new verifier or HIA opcode.

## Concrete mismatch

The Python HIA VM creates an empty owner for `buffer.new(0)`, successful
`buffer.try_new(0)`, and failed nonzero `buffer.try_new(n)`. Dropping
these capabilities consumes the Owner but makes **zero allocator/free calls**
because they do not own an allocated payload. The current LLVM producer
represents each of them as `%hia.buffer {ptr null, i64 0}`, but before this
patch it unconditionally emitted `call void @free(ptr %ptr) nobuiltin`.

Although standard C permits `free(NULL)`, this is an observable foreign
call under an interposed allocator. A high-fidelity memory-resource ledger
must not report no deallocation while the native implementation calls a
deallocator with NULL. A concrete Clang 17/Linux x86-64
`-Wl,--wrap=free` control counted **one** invocation of unconditional
`free(NULL)` and **zero** with an `icmp ne ptr` guard.

## Fix

Change only the original `hepta.hia_program_llvm._FunctionEmitter` Owner
Drop emission. Extract the pointer, branch to a non-null release block,
call `@free` with existing `nobuiltin` only there, and rejoin the
control-flow graph. This applies to all supported Core versions because the
resource instruction semantics are common.

Zero-size Owner and failed try-new: no foreign free invocation.
Real owner: exactly one call with the actual allocated pointer.
No new C bridge, alternative LLVM emitter, or AST interpretation is added.

This keeps native drop sequencing explicit; no unreviewed LLVM
nonnull/noalias attributes or resource proof upgrades are introduced.
The source-independent HIA verifier still requires normal-path consumption.

## Adversarial qualification

`tests/test_hia_empty_owner_native.py` checks:

1. Actual verified HIA VM ledgers for empty owners, normal allocation,
   zero-size fallible allocation and intentionally failed allocation.
2. Actual emitter output on x86-64 and AArch64: native free only inside a
   non-null guard; the original `nobuiltin` deallocation is preserved.
3. On a supported host, compile the **actual emitted LLVM** as an object
   and run a C observer using `--wrap=malloc/calloc/free`: zero-size and
   failed owners must not trigger `free(NULL)`; positive owner must
   still produce exactly one allocator call and one matching release.

The local independent Clang 17 hand-written LLVM control executed and
printed `free_calls=1 null_frees=0` for one real allocation plus an empty
drop. That demonstrates the patched LLVM branch pattern, NOT an
end-to-end Hepta program build; the new in-repository regression must be
run on the exact integration commit to qualify its actual emitter.

## Boundaries

No general pointer provenance or Memory SSA proof, all-target native
translation correctness, arbitrary C/C++ L2/L3, GPU/DMA qualification,
AI model A/B or production allocator stability is asserted.

`whole_project_blockers_closed=false`
