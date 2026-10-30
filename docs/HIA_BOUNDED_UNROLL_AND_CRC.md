# Checked finite scalar loops and the captured CRC kernel

The new `hia_bounded_unroll` profile bridges a specific gap in the existing
optimization validator: a real captured CRC function contains a loop, whereas
the acyclic value/first-trap checker deliberately returns unknown for loops.
This profile retains the canonical verifier and existing SMT semantics. It
does not widen the older acyclic checker or turn a producer's trip count into
an assumption.

## Obligations before a candidate can be used

The selected public primitive v1-v7 scalar function must contain exactly one
DFS feedback edge. Resources, calls, recursion, additional feedback edges and
unsupported scalar operations remain outside this profile. The graph copier
renames every SSA definition and edge argument, unfolds at most 32 feedback
traversals, and rechecks the resulting acyclic Core. Both generated programs
remain under the existing 128-block / 2048-operation symbolic limits.

The validator independently reconstructs the reference from the actual source
Core, ignoring any serialized proposal or purported bound. Its marker program
preserves scalar operations and all original traps, replaces normal returns
with `false`, and returns `true` only at the synthetic truncation edge. It asks
Z3 whether any typed input reaches that marker or lacks a symbolic outcome.
Only UNSAT establishes the finite bound. A SAT bound is replayed by the ordinary
interpreter; solver absence, exhaustion or unsupported inputs never admit code.

Once that obligation passes, the existing acyclic checker compares the
reconstructed reference and actual candidate for all typed inputs, preserving
all returned values and the first specified trap code. Every other function
and the module interface must remain exact. `verify_bounded_translation_receipt`
recomputes both queries against current bytes; a receipt is not authority.
The SMT timeout applies separately to the two queries, not to an asserted hard
global execution deadline. VM fuel counters and diagnostic step traces are
outside the equivalence observation.

The graph copier, canonical verifier, SMT encoder and Z3 remain trusted code.
This is not a machine-checked preservation/progress theorem, a proof of the C
frontend, a resource analysis or a final machine-code refinement proof.

## Binding the real application

The study captures `examples/hia_filecheck/checksum.c` and `chunk.c` through the
existing C project frontend. The selected `c_checksum_byte(u32,u8,u32)->u32`
contains seven Core blocks and its actual eight-iteration loop. A proposed
`calculate(u32,u32)->u32` kernel performs the eight reflected CRC bit steps on
the combined state XOR byte and an arbitrary polynomial.

The source bridge structurally inlines the **actual baseline Core bytes** into
the captured function signature, supplying the XORed byte and polynomial.
The bounded checker proves the loop terminates within the proposed traversal
budget and that this replacement has the same values and first traps for every
typed input. The receipt also binds the exact kernel digest. A changed kernel,
swapped same-type parameters or a silently fixed polynomial changes the proof
obligation and is rejected when behavior differs.

Guarded IEEE and Castagnoli proposals use the existing specialization producer
and retain the generic path for every other polynomial. The finite context
factory independently rechecks each candidate's all-input equivalence, actual
emitted selected LLVM, compilation identity and finite VM/native differential
before holding a sealed native image. GNU C execution of the unchanged source,
the captured VM and an independent integer CRC recurrence form a separate
finite source differential; they do not prove arbitrary C translation.

## Preregistered context comparison

The fixed [protocol](../experiments/hia_crc_context/protocol_v1.json) was published
before performance measurement in commit
`2b2486744e0a7094e99c3d9a9d397381cc714c25`, with SHA-256
`75f5f0bef5b5c49020b14b83c7c1f9257f989c5f2f0b3a365f5b7ba858329948`.

Five arms compare fresh-child baseline, coalesced baseline, each coalesced
static guarded version, and coalesced polynomial dispatch. Each trace processes
64 independent 1024-byte CRC requests from fixed Filecheck-generated inputs.
There are three polynomial workloads, separate training and validation inputs,
and seven repeated trials: 210 observations / 2856 child contexts. These are
generated application inputs, not a production trace or independently sampled
user workloads. All arms load only the images they actually reference.

The principal observation includes complete child creation, image loading,
execution, unload, exit and host result validation. Trace preparation/oracles
and full host orchestration are retained separately. A fixed polynomial
dispatch is a strong static policy, not an online NDU decision. A reduction in
process launches establishes only batching benefit.

Cold setup includes the complete source bridge, all candidate proofs/builds,
finite original-C/VM/native controls and sealed publication, including losing
candidates. Final descriptor release is charged to that setup. Performance
trial overhead is reported separately and in complete study wall; it is not
misreported as online optimization decision latency. A conservative finite-job
economic gate subtracts the complete cold setup from the observed dispatch
saving against the fastest coalesced static control. Any conditional break-even
count is a hypothesis about amortization, not observed profit or production
demand. No economic result grants execution, deployment or NDU authority.
