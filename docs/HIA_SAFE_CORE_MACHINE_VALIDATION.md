# Safe Core: Core semantics to the final machine image

This is an explicitly selected validation profile. It checks exact Core,
object and final executable bytes under independent models. A successful result
is an all-input symbolic result for that stated model; it is not a kernel-checked
proof of the hardware ISA or whole language. Installation identity and complete
scope must match before a result can satisfy a required claim.

The native path uses HIA subject, ELF, instruction, machine-observation,
obligation and proof-scope owners, including `supplied_safe_core_proof.hepta`.
The admitted native CNF solver discharges the resulting obligations. Current
source and executable identities come from the actual release and checker
receipt, not from the historical hosted implementation.

## Accepted program boundary

The profile identifier is
`hia.safe-core.unsigned-acyclic-single-borrow.x86_64.v1`.

| Boundary | Accepted scope |
| --- | --- |
| Core | Explicit primitive Core v1-v8; one function and one scalar return |
| Scalars | `u8`, `u32`, `u64`, `usize`, `bool` |
| Operations | Constants; wrapping/checked unsigned add and subtract; wrapping unsigned multiply; bitwise and Boolean operations; six unsigned/equality comparisons; wrapping casts; scalar select; buffer length/load/store |
| Control flow | At most 16 blocks / 64 operations; acyclic branch/jump/return/trap; no internal calls or recursion |
| Borrowed storage | At most one `readbuf` or `mutbuf` function parameter; no owner creation, allocation, transfer, returned loan or concurrency |
| Public ABI | SysV AMD64, at most six expanded argument words; a loan expands to pointer/length; borrowed entries return the existing packed ABI status / `u32` result |
| Machine choices | Canonical build entry preserves its producer-identity check; the separate supplied-ELF entry admits independently validated bytes in the same closed instruction/ABI model |
| Object / image | Direct ELF64 object and Linux x86-64 shared library in the admitted loader shape, exactly one immediately bound `abort@GLIBC_2.2.5` import |
| Resource boundary | 64 KiB text, 16 KiB assumed available caller stack, bounded symbolic paths/steps, and a 100-60,000 ms symbolic-validation deadline |

Outside-profile programs, unavailable admitted solver, solver `unknown`, a deadline, incomplete
paths, unsupported bytes or loader metadata all reject. There is no sampled
execution fallback that can turn an unknown proof result into approval.

The checking request selects the versioned profile explicitly. A new version does not broaden an
earlier version's Core operations or instruction decoder:

| Version | Additional admitted scalar semantics |
| --- | --- |
| v2 | `u16` values and checked unsigned casts |
| v3 | Checked unsigned negation and checked variable left/right shifts |
| v4 | Checked unsigned multiplication at u8/u16/u32/u64/usize widths |
| v5 | Checked unsigned division and remainder at those five widths |
| v6 | Signed i8/i16/i32/i64/isize arithmetic, comparisons, shifts and mixed-sign casts |

The v4 Core model multiplies zero-extended operands into a full 128-bit
product and aborts when that product exceeds the declared unsigned type's
maximum. ABI inputs are normalized to their declared widths first; a u8 input
with raw word 256 therefore means zero. Narrowing the result before checking
would discard an observable overflow and is rejected. All versions retain the
same finite control-flow, storage, ABI, loader and resource boundaries above.
The v5 Core model uses unsigned quotient/remainder and traps exactly when the
normalized divisor is zero. Signed arithmetic is admitted separately by v6,
without widening any earlier profile.

## The chain being checked

1. **Exact Core.** The existing canonical verifier rechecks the actual primitive
   operations and resource interfaces. An independent HIA Core model encodes their versioned integer bitvector and byte-array semantics.
   It does not call the production VM or copy a desired answer into the model.

2. **Lowering and instruction templates.** The canonical build entry retains its
   producer-identity check. The supplied-ELF checker directly consumes an object
   and final image and never imports or invokes the encoder or linker.
   The independent HIA instruction model decodes the
   *linked* bytes and symbolically executes its closed instruction set. It does
   not invoke the lowering implementation. Arithmetic, carry/zero
   flags, conditional branches, byte stores, stack operations and calls are
   interpreted from the decoded bytes. Unreviewed instructions are rejected,
   including instructions in unreachable regions.

   The register-only 64-bit two-operand `IMUL` leaf uses the exact low
   product, with carry derived from signed truncation. Its undefined zero flag
   becomes a fresh arbitrary Boolean on each model execution. A candidate that
   relies on the prior zero flag surviving multiplication must therefore pass
   for both outcomes; the checker does not assign a convenient fixed value.
   Checked multiplication remains outside v1/v2/v3. Memory/narrow `IMUL` forms
   remain outside every version. These leaf extensions do not prove refinement
   to the full ISA.

   The v4 decoder additionally admits register-only `REX.W + F7 /4` unsigned
   `MUL`. Both input words are read before updating RAX and RDX, including when
   either implicit output is also the explicit source. RDX receives the high
   64 bits and RAX the low 64 bits. CF and OF indicate whether the high word is
   nonzero; SF/ZF/AF/PF are undefined. The model supports CF-consuming conditions
   and assigns a fresh arbitrary value to ZF; conditions consuming OF/SF/PF are
   still outside the decoder. It does not carry an old ZF through multiplication
   or derive ZF from the product. These rules follow the
   [Intel SDM Volume 2B, order 253667-080US, MUL, pp. 4-146–4-147](https://cdrdv2-public.intel.com/782151/253667-sdm-vol-2b.pdf).
   Independent GNU assembler encodings and executed alias/flag boundary cases
   supplement the all-input independent-model obligations.

   The v5 decoder additionally admits register-only `REX.W + F7 /6` unsigned
   `DIV`. It reads the old full RDX:RAX dividend and explicit divisor, then
   writes the quotient to RAX and remainder to RDX. A zero divisor or an
   unrepresentable quotient causes `#DE`; every arithmetic flag is undefined.
   These rules follow the
   [Intel SDM Volume 2A, order 253666-060US, DIV, pp. 3-285–3-287](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf).
   The modeled CF and ZF receive separate arbitrary values. `#DE` is outside
   the admitted return/abort outcomes: any reachable fault makes terminal
   coverage fail, or the existing no-terminal-outcome rule rejects the image.
   It cannot implement the Core's explicit libc-abort behavior.

   The division model retains the complete 128-bit dividend. For base
   `B = 2**64`, unsigned words H/L and nonzero D, `(H*B+L)//D < B` exactly
   when `H < D`. Only when independent execution has simplified H to the
   exact constant zero does it reduce the result expressions to 64-bit
   `UDiv`/`URem`. A source operation, profile label or saved receipt never
   supplies this premise. The integer quotient bound, overflow criterion and
   Euclidean uniqueness have separate all-integer UNSAT regression queries;
   native nonzero-high and operand-alias cases check the complete path as well.
   This exact simplification preserves the existing proof deadline. An unknown
   result still rejects rather than granting a narrower sampled guarantee.

3. **ABI.** The model starts with arbitrary raw argument-register words. Narrow
   types and Boolean normalization therefore cover dirty upper register bits.
   It checks call alignment, saved registers, return-stack restoration and
   caller-memory effects. For borrowed entrypoints the independent Core-side
   model also covers oversized extents, nonempty null ranges and address-wrap
   rejection before entering Core.
   Every `CALL` also decrements the stack pointer and checks its implicit
   return-address store before entering the callee, including nonreturning
   `abort`. Treating the callee as terminal cannot skip the calling instruction's
   memory access or admit a stack pointer outside the caller's stack budget.

4. **Relocation and loader authority.** The independent HIA ELF model compares every
   final text byte against the object, permitting differences only in the exact
   two admitted `E8 rel32` call fields. Internal calls must land at the exact
   function boundary. The external call is bound through PLT bytes, the GOT
   slot, `R_X86_64_JUMP_SLOT`, the `abort` dynamic symbol, libc version metadata
   and the actual `PT_DYNAMIC` table with immediate binding. All nonempty
   allocated sections, including dynamic symbols/strings/relocations/hash and
   version tables, must refer to the bytes the `PT_LOAD` mapping really loads.
   Partial overlapping page mappings, extra executable segments and unreviewed
   loader hooks reject. `PT_LOAD` entries must retain the gABI's ascending
   virtual-address order in the actual program-header table, before any sorted
   overlap calculation. Reordering a complete load-header record can leave all
   section bindings unchanged while breaking the loader's mapping bounds.
   SysV/GNU hash tables must actually resolve the checked
   entrypoint; a matching symbol-table label alone is insufficient.
   The native shared linker constructs both required symbol-lookup tables.
   `hia-elf-link-shared` consumes one generated ET_REL object on stdin and
   writes candidate ET_DYN bytes on stdout. Linker refusal has no external
   linker fallback. Linkage itself does not validate Core or authorize loading;
   the independent semantic and loader checks still gate verified publication.

   See [ELF gABI, Program Header / PT_LOAD](https://gabi.xinuos.com/elf/07-pheader.html).
   The single `PT_GNU_RELRO` must retain its reviewed read-only header shape and
   file/virtual mapping inside the GOT's writable load. Its effective protection
   is `[floor(start / 4096) * 4096, floor(end / 4096) * 4096)` and must cover the
   entire GOT. A raw range that contains the GOT is insufficient: it could also
   remove execution from the checked text, or a second RELRO header could select
   a different range. This follows the trusted glibc loader's
   [`_dl_protect_relro`](https://sources.debian.org/src/glibc/2.44-1/elf/dl-reloc.c/)
   and remains limited to this Linux x86-64, 4 KiB admitted shared-image shape.

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

## Independent consumer entry

`validate_safe_core_artifact(core, object_bytes, final_bytes, ...)` accepts exact
immutable byte strings. Its default profile is
`hia.safe-core.unsigned-acyclic-single-borrow.supplied-elf.x86_64.v1`; explicit
versions 2 through 6 select the matching versioned supplied-ELF profile.
It uses the same Core operations, ABI, loader and resource limits above, but
requires no producer object, emitter invocation or compiler correctness premise.
The ELF reader derives `.text`, function extents, symbols and relocations from
supplied bytes rather than accepting a producer's symbol map. Both the object
and image are untrusted inputs. Mutating both consistently still has to pass the
independent semantic obligations.

The existing `validate_safe_core_image` and `build_safe_core` entries preserve
the canonical profile and its reemission identity check as producer provenance.
Their semantic result is computed by the independent consumer entry. Reemission
is labeled `semantic_proof: false`; it is never substituted for the SMT checks.

The native consumer receives the captured Core, object and final-image bytes
through the admitted source-bound role. Their exact sizes and digests are bound
before proof work. Retain canonical Core, all query and result bytes, timing,
counterexamples and the terminal status, including refused attempts. The
checker does not load or execute the candidate. Any later loading action must
independently bind the inspected bytes to its own authority.

The old function names in this contract distinguish canonical-producer and
supplied-artifact semantics. They do not advertise a retired hosted CLI. The
installed `hia-safe-core-prove`, `hia-safe-core-loader`, `hia-core-proof-wire`
and `hia-proof-cnf` roles use their admitted binary protocols; Agent callers
use the discovered `hia_verify` operation described below.

Each successful result carries `subject`, `property`, `profile`, `assumptions`,
`checker` and `unproved_obligations` in its raw validation record. Retain the
complete validation record with the result. Checker identity separates consumer
model sources and the pinned solver from optional producer provenance. The
supplied-artifact path requires no producer invocation; its model and query
inputs are the captured bytes. Adversarial controls replace `MOV RAX,0` with
`XOR RAX,RAX` plus NOPs: these noncanonical bytes may pass the semantic checker,
while jointly changing object and final-image addition into subtraction produces
a real counterexample. Matching producer hashes are insufficient in either case.

Qualification must recheck its declared positive and negative artifacts with
pinned input hashes. These checks do not broaden the compiler support matrix.
The complete selfhost compiler, loops, multiple functions, owned resources and
general ELF remain outside this finite
semantic profile; a whole-selfhost refinement proof remains an open obligation.

## Agent artifact consumption

The MCP `hia_verify` path exposes an explicit scalar projection of the supplied
artifact validator. After `hia_emit`, request `lowering_refinement` using a
`native_artifact` subject naming the returned native artifact and build receipt.
The method is `independent_safe_core_machine_validation`, with the discovered
Agent profile `hia.agent.safe-core.scalar-supplied-elf.x86_64.v1`.

The build retains the original `image.object_bytes` in a dedicated immutable
`build-object` artifact. Both native metadata and the build receipt bind that
reference and hash to the exact Core and final image. Verification and receipt
consumption check those bindings. They never reemit an object as a replacement
for missing retained evidence. Core, object and final bytes used for checking
and hashing are the same immutable observations; the transport captures and
binds the complete inputs before checking and refuses changed identities at
publication.

This Agent profile admits only final shared ELF and one unsigned scalar acyclic
function with an empty foreign export manifest. The broader raw borrowed-range
profile remains available through its separate native checking contract; the
Agent's existing scalar target ABI does not acquire that calling authority.
Object-only builds,
loops, multiple functions and other unsupported Core/ELF/instruction forms do
not get a refinement proof. A valid scoped native proof can satisfy an exact
artifact's required lowering claim while the existing workload, equivalence,
resource and conditional adoption gates still apply.

The proof envelope carries the raw report, all five ordered obligations, the
actual independent checker and solver identities, and immutable query
references. Nonvacuity must be SAT and the four violation queries UNSAT. A
real SAT violation is a refutation; budget expiry, an unknown solver result or
incomplete evidence cannot be promoted to `proved`. Checks after the final
solver/identity read and before Agent publication enforce the frozen deadline.
The canonical whole-Core lowering request remains unsupported and machine-plan
proofs remain conditional on their original producer assumptions.

Current acceptance must exercise actual native proof production and receipt
consumption, including changed subjects, wrong object/image bindings, weakened
assumptions, altered solver identity, replay and deadline expiry. A component
build or source inventory alone is not evidence that these proof gates ran.

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

The independent HIA Core/x86/ELF models, canonical verifier and admitted
native solver remain trusted. Their correspondence to a full
Intel ISA model has not been machine-checked. The scope therefore keeps these obligations open. A legacy-compatible receipt
may retain the field name `python_checker_soundness_proved`; its value remains
false and does not identify a current dependency. The actual `checker` record
identifies the executing implementation:

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

## Source-bound qualification

Use the current native checker roles from the verified installation. Record
the exact selected profile, Core, object, final image, query bytes, solver
identity and full scoped outcome. Native query generation and native solver
execution must both be observed. Current evidence is indexed by
[CURRENT.md](CURRENT.md); former hosted experiments are retained only in
[historical qualification provenance](HIA_HISTORICAL_QUALIFICATION_PROVENANCE.json).

Positive cases must be accompanied by independent wrong-producer controls:
addition changed to subtraction, equal-to-extent access admitted, byte store
changed to a word store, saved-register corruption and an invalid stack before
a nonreturning abort. A same-producer byte regeneration can accept these pairs;
the independent semantics must still refute them. Retain failed queries and
counterexamples, and never load a negative-control candidate as a qualified
program. Replay each query using fresh solver state with its original budget.

A qualification cannot claim completion with skipped or missing obligations.
It does not select a production release or establish whole-language soundness.

## Signed integers in version 6

`hia.safe-core.integer-acyclic-single-borrow.x86_64.v6` and its
`supplied-elf` counterpart add `i8/i16/i32/i64/isize` to the preceding
unsigned operation set. The original one-function, acyclic control-flow,
borrowed-memory, ABI and resource bounds remain in force.

The independent Core model represents signed arguments by exact low-width
sign extension and checks arithmetic in a sufficiently wide domain before
narrowing. Signed division truncates toward zero, and the remainder follows
the dividend. Both operations abort on a zero divisor or `MIN/-1`. Checked
casts compare the mathematical source value with the destination interval,
including mixed signed/unsigned conversions through the full 64-bit range.
Negative shift counts and counts at or above the value width abort before
the machine masks CL.

The v6 decoder adds 64-bit SAR, NEG, CQO, full IMUL, IDIV and signed/overflow
conditions. CF, ZF, SF and OF follow each actual instruction: zero-count
shifts preserve flags; one-bit shifts define OF; multi-bit shift OF and
multiply/divide undefined flags remain arbitrary. The signed division model
uses the actual old RDX:RAX and divisor, including aliases. Architectural
#DE is an uncompleted machine path and cannot stand in for a Core abort.

Register kernels use caller-saved registers and no stack on successful paths.
Their abort stub retains the modeled 16-byte stack effect. Narrow checked
multiplication retains the architectural overflow branch so that the
full-product relation can be discharged within the unchanged default
15-second proof deadline. Unsupported register pressure can select the
ordinary checked route before proof; failed proof never triggers a fallback.

Signed qualification must cover independent Core and instruction semantics,
ordinary final images, borrowed-memory effects, noncanonical producers, raw
argument normalization, live register aliases, sealed loading, every admitted
signed width and deliberately wrong final images. Solver `unknown` and expired
deadlines remain failures. Historical external-assembler or Rust comparisons
are supplemental observations; the current native qualification must retain
its own actual source-bound controls.

Instruction semantics follow the [Intel instruction-set reference](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html).
