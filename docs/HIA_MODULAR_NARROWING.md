# Proof-checked modular width narrowing

`hepta.hia_narrowing` adds an independently checked optimizer proposal for
unsigned wrapping arithmetic whose observable result is truncated to a smaller
width. It executes through the existing standalone HIA Core and direct LLVM
backend. It does not add a source language, LLVM opcode, unsafe annotation or
alternative resource runtime.

For example, a buffer fill may compute

```text
u8(u32(index) +wrap seed)
```

as

```text
u8(index) +wrap u8(seed)
```

The identity follows from arithmetic modulo a power of two, but this explanation
is not the admission rule. The independent bit-vector checker must prove the
actual proposed program, including scalar arguments passed into resource and
call operations and every first-trap outcome. A proposer that substitutes
subtraction for addition gets a concrete solver counterexample and cannot build
an admitted native artifact.

## Supported proposal and structural contract

`propose_modular_narrowing(program)` is untrusted. It proposes wrapping
truncations through unsigned wrapping add/subtract/multiply, bitwise
and/or/xor/not, constants and compatible wrapping casts. It stops at checked
arithmetic, division, shifts, calls, loads and other unsupported expressions.
Existing preceding operations are retained, including their possible traps.
LLVM may remove an unused nontrapping wide expression under its own trusted
semantics; the HIA proposal cannot delete a checked operation on that basis.

The proposal uses `hepta.hia.modular-narrowing-proposal.v1` and includes the
actual base Core SHA, complete candidate Core, and an ordered edit inventory.
Each edit identifies the original function, block and operation and contains
the exact replacement instruction list. The admission routine reconstructs
the candidate from that inventory and requires byte-for-byte canonical Core
equality. It rejects undeclared changes, duplicate or absent roots, signed or
checked-cast roots, resource operations in a replacement, non-wrapping casts,
out-of-order edits and changes to any other original instruction.

Limits are 128 rewritten roots, 2,048 replacement instructions and an untrusted
expression traversal depth of 32. Traversal exhaustion makes the proposer
abstain on that expression; it never disables a proof obligation. Normal Core
admission checks all resulting SSA definitions and types.

`verify_modular_narrowing` then invokes the separate
`hepta.hia_optimization.verify_optimization` checker. Each scalar/effect segment
must have an UNSAT counterexample query over all inputs at their declared
widths. There are no producer-supplied numeric assumptions. Exact control-flow,
signatures, ordered resource operations, calls and first traps are preserved.
SAT, unknown, timeout, unsupported correspondence, identity drift and exhausted
operation or obligation budgets fail closed.

## Composition with guarded reduction

The guarded-narrowing proposal contains two stages:

1. Prove the existing guarded checked-reduction transform, including its input
   guard, every inductive CFG edge, each removed overflow check and full
   fallback.
2. Prove modular narrowing from that precise intermediate Core to the final
   Core, on both guard branches.

`verify_guarded_narrowing` independently verifies both stages. The first proof's
candidate SHA must equal the second proof's base SHA and the actual intermediate
program. The second proof's candidate SHA must equal the final program. The
verification has one shared deadline, one whole-chain operation bound and one
shared obligation bound. A valid isolated narrowing certificate attached to an
unrelated guarded program is rejected.

The final fallback may have narrowed pure expressions; its behavior is equal
to the original fallback by the second proof. This is explicitly described as
fallback equivalence, not unchanged fallback instruction bytes. Under the Core
model, successful and failed allocations, lifetimes, effect order, return
values and first-trap behavior are preserved. VM tick counts, proof costs,
native code size and wall-clock costs can change.

## Native publication and identity

`build_narrowed_native` and `build_guarded_narrowed_native` accept actual base
and proposal inputs. They freeze those inputs, obtain fresh proofs, reverify
the final Core and compile through the existing direct LLVM backend. A supplied
receipt cannot substitute for this work. They bind original/final Core,
verification, exact native bytes, compiler and target, and recheck checker and
solver identities before and after atomic publication. A failed identity check
withdraws the output link owned by the build.

Native execution still requires the existing sealed-image loader identity
gate. `tools/qualify_hia_narrowing.py` exercises both branches around a small
guard, loads the sealed actual artifacts, verifies both exported function
addresses and compares actual returns against a separate arithmetic oracle.
It also saves full actual binary disassembly. The qualifier records proof and
build costs but deliberately produces no performance qualification.

## APIs

| Operation | API |
| --- | --- |
| Propose a modular transform | `propose_modular_narrowing` |
| Independently check it | `verify_modular_narrowing` |
| Obtain verified Core | `narrowed_program` |
| Check, compile and bind native bytes | `build_narrowed_native` |
| Propose a guard plus narrowing chain | `propose_guarded_narrowing` |
| Independently check both stages | `verify_guarded_narrowing` |
| Obtain the chain's verified final Core | `guarded_narrowed_program` |
| Check both stages and bind native bytes | `build_guarded_narrowed_native` |

The proof encoders, Z3 implementation, Core checker, LLVM, native linker,
loader, C allocator, operating system and hardware remain trusted. No backend
refinement proof, arbitrary-program optimizer completeness, global optimum or
performance superiority follows from this finite transform. Native speed,
tail distributions, peak memory and all optimization costs require their own
registered measurements and strong baselines.
