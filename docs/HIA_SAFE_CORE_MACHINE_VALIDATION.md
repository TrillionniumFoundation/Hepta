# Safe Core: Core semantics to the final machine image

Status: **opt-in candidate validation profile**. This entry does not change the
current release lock, default HIA emission, worker/catalog identity or production
deployment. A successful result is an all-input SMT result for the explicitly
stated independent models, not a Lean-kernel proof of the hardware ISA or of the
whole language.

## Accepted program boundary

The profile identifier is
`hia.safe-core.unsigned-acyclic-single-borrow.x86_64.v1`.

| Boundary | Accepted scope |
| --- | --- |
| Core | Explicit primitive Core v1-v8; one function and one scalar return |
| Scalars | `u8`, `u32`, `u64`, `usize`, `bool` |
| Operations | Constants; wrapping/checked unsigned add and subtract; bitwise and Boolean operations; six unsigned/equality comparisons; wrapping casts; scalar select; buffer length/load/store |
| Control flow | At most 16 blocks / 64 operations; acyclic branch/jump/return/trap; no internal calls or recursion |
| Borrowed storage | At most one `readbuf` or `mutbuf` function parameter; no owner creation, allocation, transfer, returned loan or concurrency |
| Public ABI | SysV AMD64, at most six expanded argument words; a loan expands to pointer/length; borrowed entries return the existing packed ABI status / `u32` result |
| Machine choices | Canonical direct emitter; Agent machine-plan variants are outside v1 |
| Object / image | Direct ELF64 object, GNU-ld Linux x86-64 shared library, exactly one immediately bound `abort@GLIBC_2.2.5` import |
| Resource boundary | 64 KiB text, 16 KiB assumed available caller stack, bounded symbolic paths/steps, and a 100-60,000 ms symbolic-validation deadline |

Outside-profile programs, missing Z3, solver `unknown`, a deadline, incomplete
paths, unsupported bytes or loader metadata all reject. There is no sampled
execution fallback that can turn an unknown proof result into approval.

## The chain being checked

1. **Exact Core.** The existing canonical verifier rechecks the actual primitive
   operations and resource interfaces. A separate interpreter in
   `hia_safe_core.py` encodes their unsigned bitvector and byte-array semantics.
   It does not call the production VM or copy a desired answer into the model.

2. **Lowering and instruction templates.** The normal direct emitter produces
   actual object/text bytes. `hia_safe_core_x64.py` independently decodes the
   *linked* bytes and symbolically executes its closed instruction set. It does
   not import `Code` or the lowering implementation. Arithmetic, carry/zero
   flags, conditional branches, byte stores, stack operations and calls are
   interpreted from the decoded bytes. Unreviewed instructions are rejected,
   including instructions in unreachable regions.

3. **ABI.** The model starts with arbitrary raw argument-register words. Narrow
   types and Boolean normalization therefore cover dirty upper register bits.
   It checks call alignment, saved registers, return-stack restoration and
   caller-memory effects. For borrowed entrypoints the independent Core-side
   model also covers oversized extents, nonempty null ranges and address-wrap
   rejection before entering Core.

4. **Relocation and loader authority.** `hia_safe_core_elf.py` compares every
   final text byte against the object, permitting differences only in the exact
   two admitted `E8 rel32` call fields. Internal calls must land at the exact
   function boundary. The external call is bound through PLT bytes, the GOT
   slot, `R_X86_64_JUMP_SLOT`, the `abort` dynamic symbol, libc version metadata
   and the actual `PT_DYNAMIC` table with immediate binding. All nonempty
   allocated sections, including dynamic symbols/strings/relocations/hash and
   version tables, must refer to the bytes the `PT_LOAD` mapping really loads.
   Partial overlapping page mappings, extra executable segments and unreviewed
   loader hooks reject. SysV/GNU hash tables must actually resolve the checked
   entrypoint; a matching symbol-table label alone is insufficient.

5. **Final immutable image.** `build_safe_core` links into a private temporary
   directory, validates those final bytes, and publishes the exact bytes only
   after every obligation passes. The result binds Core, source implementation,
   object, linked text and final image hashes. A saved JSON receipt grants no
   execution authority and is never consumed as a substitute for recomputation.

## Obligations and meaning

Each accepted image retains five solver queries:

| Obligation | Required answer |
| --- | --- |
| The caller contract has at least one valid state | `sat` |
| A machine read/write/return can escape admitted memory | `unsat` |
| A call/return can violate stack alignment or saved-register preservation | `unsat` |
| Any admitted input can lack a terminal Core or machine-model outcome | `unsat` |
| Core and the final image can disagree on return/abort or caller byte contents | `unsat` |

Byte-array equality includes preservation of bytes outside each intended write.
The comparison observes caller memory even at an abort, so replacing a check
with a late check after an incorrect write cannot pass merely because both
executions eventually abort. The native ABI's observable trap is nonreturning
abort; this entry does **not** promise preservation of distinct HIA trap codes.

The proof quantifies over arbitrary scalar words and caller bytes. Native
execution tests separately exercise the published image and boundary/canary
cases. Those finite tests are not the source of the all-input claim.

## Trust and caller assumptions

The caller must supply live initialized borrowed allocations for every admitted
nonempty range. They must be disjoint from the active stack, and a mutable range
must be exclusive during the synchronous call. Numeric pointer/length checks
cannot establish allocation provenance, liveness or physical mapping. A
foreign pointer that numerically passes these checks but names invalid memory
violates this caller contract.

The actual loader must map the inspected bytes and resolve the immediately
bound abort slot to the expected nonreturning libc implementation. Hostile
interposition, concurrent memory modification, signals and hardware faults are
outside this profile. The model assumes the declared 16 KiB of stack is
available; it does not turn an exhausted process stack into a safe call.

The independent Python Core/x86/ELF models, the canonical verifier and the
identified Z3 binary/bindings remain trusted. Their correspondence to a full
Intel ISA model has not been machine-checked. The receipts accordingly retain:

```json
{
  "all_input_refinement_in_independent_model": true,
  "machine_checked_isa_refinement_proved": false,
  "python_checker_soundness_proved": false,
  "foreign_pointer_provenance_or_liveness_proved": false,
  "whole_language_soundness_proved": false,
  "serialized_receipt_authorizes_execution": false
}
```

The next formal step is to connect this closed decoder and state relation to a
kernel-checked ISA definition. Increasing the Core profile requires new
operation/flag/memory/ABI obligations and negative controls before admission.

## Reproduce a build

Use Linux x86-64, GNU ld/glibc and the existing `z3-solver==4.15.4.0` optional
verification dependency. The receipt records the actual loaded Z3 library and
Python binding hashes, not only the package version.

```sh
python tools/build_hia_safe_core.py \
  --source examples/hia_safe_core/scalar_add.hia.json \
  --output /tmp/hia-safe-core-scalar

python tools/build_hia_safe_core.py \
  --source examples/hia_safe_core/guarded_update.hia.json \
  --foreign-extent 4096 \
  --output /tmp/hia-safe-core-borrowed
```

The output directories must be new. They retain original/canonical Core,
candidate object/text, raw `.smt2` queries and per-query results, attempt timing
and the authoritative terminal `attempt.json`. A rejected or unknown attempt
keeps its report and available queries; it has no published `program.so`.

## Reproduce the adversarial qualification

```sh
python tools/qualify_hia_safe_core.py --output /tmp/hia-safe-core-qualification
```

This runs the full targeted test inventory with no allowed skips, builds three
positive examples, retains four wrong-backend object/image pairs, and replays
every retained query with a fresh solver context. The wrong producers mutate
addition into subtraction, admit the equal-to-extent byte access, emit an
eight-byte store in place of a byte store, and clobber a callee-saved register.
They are accepted by their own image regeneration step and must still produce
real semantic `sat` counterexamples in the independent checker.

The binaries named `candidate.rejected.*` are negative-control evidence and must
not be loaded. `original-files.json` binds every retained file. The qualification
does not move the default release, alter a production task, or establish that
the complete HIA language is sound.
