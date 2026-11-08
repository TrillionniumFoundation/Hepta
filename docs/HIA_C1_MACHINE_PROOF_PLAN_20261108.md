# Minimum complete next layer for original C1 machine refinement

## Proposed goal, not an implemented proof

The next useful layer is an all-input refinement proof for the exact original
C1 Core and one exact whole native compiler artifact. For a first target, use
the ordinary ELF B0 translation of the unchanged C1 Core. It already exists as
an unproved artifact, with canonical Core, object bytes, complete symbol and
relocation inventory, and a normal linker receipt. If its normal link options
are changed for a new declared artifact profile, freeze the resulting new
final-image hash as a new subject. Do not attribute a proof to a different
earlier image.

The property must compare all observable return/abort outcomes and caller bytes
under the actual three-buffer entry contract, including malformed input and
capacity failures. It must preserve termination and prove native memory bounds
and the exact stack/register ABI for this artifact. This establishes that the
machine compiler executes the C1 Core algorithm. It does not establish that the
C1 algorithm correctly compiles arbitrary source programs.

Keep the existing small Safe Core validator and its labels unchanged. A separate
compiler-specific validator/profile is required; raising the old numerical
limits or ignoring paths cannot provide this property. The current Python ISA
and SMT trust base must remain explicit. A proof inside that model would still
not be a kernel-checked refinement of the complete hardware ISA.

## Actual size and control structure

The retained canonical C1 has the following measured structure:

| Item | Actual C1 / B0 | Existing Safe Core limit or rule |
| --- | --- | --- |
| Primitive functions | 45 | Exactly 1 |
| Blocks | 1,152 | At most 16 |
| Core operations | 3,177 | At most 64 |
| Functions containing CFG cycles | 18 | Acyclic |
| Direct call sites | 744 | Calls excluded from admitted Core operations |
| Maximum function arity | 9 | External ABI budget 6 words; a different issue from internal arity |
| Direct self call | `f43 -> f43` | Recursion excluded |
| Public compiler entry | readbuf + mutbuf + mutbuf | At most 1 borrowed range |
| B0 machine text | 518,646 bytes | At most 65,536 bytes |
| Largest reported B0 function frame | 19,008 bytes (`f7`) | Existing stack assumption/model bound is 16 KiB |
| B0 public exports | `f0`, `f32` | One entry/export in the old artifact profile |

Frame sizes above are the retained producer metadata, not an independently
proved stack bound. A complete proof must derive machine frame effects from
actual bytes and compose call-chain use; even the reported largest single
frame already exceeds the old 16 KiB premise. Merely increasing a timeout or
assuming unlimited stack does not discharge that obligation.

C1 uses 19 Core operation names. Four are outside the present Safe Core
operation list: `call`, `int.mul.wrap`, `int.shl.checked`, and
`int.shr.checked`. It does not need owned allocations, chain operations or an
allocator FFI to prove this particular compiler. Those wider-language obligations
remain separate.

## Required engineering and acceptance gates

### 1. Freeze the whole subject and its entry set

Pin C1 Core `10284cea893a06091e3bb1de5c9e593148915469f820993d49952386503c428b`,
the exact object, final ELF, target and checked entry contracts. Bind all actual
functions, symbols and relocations, including the `f0` and `f32` exports and
the nonreturning `abort` import. If a report covers only a selected entry, its
entry set must be explicit and consumers must reject other entrypoints; a claim
covering the original candidate's whole public surface must cover both.

Reuse the existing exact-byte and immutable-input discipline, source/solver
identity checks, typed reports and query retention. Add a separate closed
artifact binding for the real larger symbol/relocation inventory. Do not alter
metadata to make the artifact resemble the old two-function shape. Loader and
hardware assumptions must remain visible; this work does not itself prove
the loader or complete ISA.

Completion gate: an independent consumer derives all callable code boundaries
and resolved targets from the supplied bytes and rejects any unaccounted code,
call, import or public entry within the claimed scope. Producer inventories
can be hints, never the authority for this check.

### 2. Model the existing three-buffer ABI completely

The production byte ABI expands each loan into pointer/length words. For `f0`
that is six public words. The exact wrapper has ordered extent, nonempty-null,
address-overflow and alias guards; it packs the ABI status with the Core u32
result and does not enter Core or touch caller bytes on rejection. The next
reference model must reproduce that actual error order and packed result,
including empty ranges and overlap rules when either range is mutable.

For admitted calls, represent source, output and workspace bytes, lengths,
permissions and pointer/stack disjointness under the existing live-allocation
contract. Both mutable buffers are caller-observable. Workspace cannot silently
be excluded from the equality check or assumed initially zero. Arbitrary initial
bytes, malformed source, short output/workspace and all valid length boundaries
belong to the declared input domain.

Completion gate: establish a non-vacuous caller contract and prove every guard
outcome, read/write permission and memory effect for all admitted ABI words and
initial byte arrays. Do not manufacture disjointness or capacity assumptions
from the finite replay's allocated buffers.

### 3. Add compositional function and loop reasoning

The current Core interpreter enumerates finite acyclic paths, and the machine
executor rejects revisiting an instruction. Both must gain a separate reasoning
path appropriate to C1's actual loops and calls. Exhaustively unrolling the
one-MiB input domain is not a complete practical substitute.

Use independently checked relations at each Core block/function boundary:
which exact machine location represents each live scalar or loan; how private
argument/result slots correspond; which registers, flags and stack cells are
live; and how caller memory corresponds. A producer may supply maps and
invariants as certificates, but the checker must verify all initialization,
edge-preservation and return obligations. Invalid or overly strong invariants
must fail, rather than remove reachable paths.

For each call, verify the actual private calling convention, parameter widths,
result storage, frame ownership and saved registers. The scalar/slot layout
must be derived for the chosen artifact; C1's generated private ABI must not
be conflated with its Python seed backend's layout. Call summaries require
checked premises at every call site and independently discharged postconditions.

Termination needs its own evidence. Derive ranking measures for each of the 18
cyclic functions under proven bounds, including unsigned wrap behavior and
early failure paths. Establish the precondition and decreasing measure for
`f43`'s self call; the finite replay's recursion depth is not a universal bound.
For all loops, prove invariant initialization, preservation, useful exit facts,
and a well-founded decrease. A mere finite search depth cannot become a completed
termination proof.

Completion gate: every reachable entry and control-flow edge, loop backedge,
call and terminal return/abort has a checked obligation. Missing invariants,
unsupported recursion, solver unknown/timeouts or unbound edges must produce
an incomplete result that cannot authorize evaluation or adoption.

### 4. Close the actual Core and machine instruction semantics

Add the four missing Core operations with exact scalar widths, wrapping,
checked-shift traps and call effects. Independently inventory the selected
artifact's actual instruction forms and add only reviewed forms required by
that image. CMOVNE alone is insufficient. Preserve old-register alias rules,
flags, partial-register behavior, addressing, signed immediates and all trap
paths while proving agreement with the corresponding Core transition.

For a later proof of the *self-generated* C1 image, additional known forms
include the stack probe `48 8b 04 24`, zero-extending u32 normalization `89 c0`,
and accumulator AND `48 25 ff 00 00 00`. That flat image also has a different
public wrapper and trap representation. It is a separate artifact/ABI target;
success on B0 must not be transferred to it by matching source names or finite
bootstrap observations.

Completion gate: decoded instructions form a closed inventory; every decoded
form has independently reviewed semantics and positive/negative actual-subject
checks. Unreachable bytes remain checked. The final report states exactly which
ISA/model assertions remain trusted instead of claiming a complete hardware
proof.

### 5. Prove stack/resource and end-to-end composition

Derive frame extents and complete call-chain bounds from the selected machine
bytes and proven call/loop behavior. Bind required available stack to an
explicit caller contract supported by the intended runtime. Stack alignment,
saved registers, return addresses and any stack probes must be covered. The
existing 16 KiB Safe Core premise cannot simply be reused for this compiler.

Combine block simulation, call summaries, memory framing and termination into
the final all-input statement: same specified ABI result or abort, same caller
bytes, no out-of-bounds machine accesses, preserved SysV state, and a covered
terminal outcome. VM step/heap quotas and native wall/CPU limits are different
mechanisms; a runtime timeout is not a semantic proof of termination, resource
equivalence or cleanup.

Completion gate: retain every obligation and its actual SAT/UNSAT/unknown result,
counterexamples, exact inputs and checker source identity. Independent replay
must recompute the proof for the same artifact and complete scope. Native tests
remain corroboration, never the substitute for a missing universal obligation.

## What this would close, and what remains

Completing all five work items could qualify one whole native C1 compiler under
an explicitly declared, independently checked model and caller contract. It
would be a real next layer beyond scalar leaf proofs. Integrating it into
`hia_verify` would require exact matching of candidate, native artifact, target,
entry set, property, assumptions and checker identity before granting that
specific lowering-refinement claim.

It would not make C0 and C1 all-input equivalent. The preserved original
counterexample remains: old INVALID versus newly emitted code for a select
input. The extension task still needs the two distinct algorithmic properties:
preservation over the old supported source domain, and conformance to the source
specification over the newly admitted select domain. Those are properties of
the compiler's source-to-output algorithm, not of executing its Core algorithm
faithfully on a machine. The current strict four-claim gate must continue to
reject until the applicable required properties have genuine proofs. Provider
history and unavailable costs cannot be reconstructed by any of these steps.

This document specifies work and acceptance gates only. None of the new
multi-function/loop/three-buffer machinery is implemented or claimed proved
by the associated ten-refusal replay.
