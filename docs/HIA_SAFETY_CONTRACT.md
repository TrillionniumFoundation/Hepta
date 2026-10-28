# HIA safety contract and executable boundaries

This contract describes the integrated implementation. It does not establish
absolute safety or whole-language soundness. The production authority is
`hepta.hia_program.verify_program`, applied to the actual immutable Core
snapshot. A producer, an AI agent, NDU, a serialized receipt, and this document
cannot confer admission or publication authority.

The companion [machine-readable matrix](HIA_SAFETY_CONTRACT.json) freezes the
reviewed schema registry, names actual entrypoints, states each capability's
exclusions, and links it to existing executable boundary regressions. Run it
from the repository root with the qualified Clang, Rust and Z3 environment:

```sh
python tools/qualify_hia_safety_contract.py --output /tmp/hia-safety/report.json
```

The output path must be new. The runner rejects registry drift, unresolved
entrypoints, missing tests, test skips, failures and source changes during the
run. The runner also pins the canonical identity of this reviewed matrix before
resolving any dynamic entrypoint. Removing capabilities, substituting tests or
changing scope, exclusions or trust assumptions cannot qualify as the same
protocol. A deliberate protocol revision requires reviewing and updating the
matrix and its independent identity in the runner together. This identity fixes
the qualification scope; it is not a semantic proof or program admission token.
It records per-test outcomes, source hashes, tool identities and the
remaining unproved claims. A passing report means the selected regressions
passed on those bytes and that host. It is not a soundness or refinement proof.
The runner does not replace or wrap the Core verifier and does not admit an
otherwise rejected program. Adding a future schema requires a deliberate
matrix review; it cannot inherit these guarantees merely by changing a version.

## Typed state and instruction obligations

The following judgment names the state already checked by the implementation:

`Gamma; Omega; Lambda; Effects |- instruction => Gamma_next; Omega_next; Lambda_next`

`Gamma` holds exact scalar and resource types, SSA definitions, block parameters
and function interfaces. Integers have explicit widths and signedness, and
checked versus wrapping arithmetic have distinct operations. The current
machine-word model is 64 bits. Unknown operations, missing effects, malformed
types and mismatched block/call arguments reject, including in unused functions.

`Omega` holds linear owner identities and their availability. Moving an owner
consumes its old binding. Dropping it consumes the live ownership obligation.
A normal return must consume or explicitly transfer owned resources through
the checked result signature. A failed `buffer.try_new` still produces a
logical empty owner that cannot be silently forgotten. Payload size zero does
not make a linear token duplicable or remove its obligation.

`Lambda` holds loan origins, permissions and parent/child relationships.
An active mutable loan excludes conflicting access. A reborrow suspends the
relevant parent until the child is ended. CFG joins must preserve resource
identity and ancestry as well as matching types. The verifier refuses aliasing
mutable call arguments and resource movement while a live loan forbids it.
Primitive v8 `return_loans` binds each borrowed result to its actual incoming
parameter origin; the caller keeps the corresponding parent suspended.
Source-level v8 lowering additionally restricts each borrowed return to one
stable nested byte field or a byte-view parameter. The older spelling
`return_origins` is not a second executable grammar.

These rules are implemented checks. A mechanically checked preservation or
progress theorem for the complete source language, elaboration, Core and
runtime is still absent. Tests expose violations of individual rules; they do
not quantify over every possible program and implementation behavior.

For a compact rule notation, let `root(x)` and `parent(x)` name capability
ancestry, `children(x)` name live direct children, and `free(o)` mean that the
owner has no other live capability with its root. `fresh(y)` means a new SSA
definition. Every rule also requires the declared operand/result types and
effects, and every referenced value must still be available.

| Instruction / boundary | Preconditions → post-state | Status |
| --- | --- | --- |
| `owner.move o -> o2` | `o ∈ Omega`, `free(o)`, `fresh(o2)` → remove `o`, transfer its unique owned resource to `o2` with the same owner type | Specification of existing checks; not a soundness proof |
| `owner.drop o` | `o ∈ Omega`, `free(o)` → remove `o`; ordinary execution performs the appropriate resource release | Specification of existing checks; not a cleanup theorem for traps |
| `borrow.read x -> l` | `x` is a byte owner or compatible byte view; no mutable capability at the same root lies outside `x`'s ancestor chain; `fresh(l)` → add read loan `(l, root(x), parent=x)` and preserve origin | Specification of existing checks; shared siblings remain possible |
| `borrow.mut x -> l` | `x` is a byte owner or mutable byte view; no other capability at the same root lies outside `x`'s ancestor chain; `fresh(l)` → add exclusive loan `(l, root(x), parent=x)` and preserve origin | Specification of existing checks; no permission escalation from a read loan |
| `loan.end l` | `l ∈ Lambda`, `l` is local, `children(l)=∅` → remove `l`; its parent becomes accessible when it has no other children | Specification of existing checks; a callee cannot end the caller's external loan |
| Memory access through `l` | Correct read/mut permission, `children(l)=∅`, correctly typed indices; runtime range condition holds → perform read/write; otherwise the semantic bounds trap occurs before the memory operation | Static permission plus runtime range check; no whole-backend refinement theorem |
| CFG edge / join | Edge arguments match target parameters; each linear capability transfers once on that edge; incoming renamed owner/loan forests and origins agree → target state has the same resource obligations under the explicit renaming | Specification of existing checks; matching types alone is insufficient |
| Normal `ret values` | Exact result types; every local resource consumed or explicitly returned; returning owners satisfy `free`; borrowed results require v8 declared parameter origins and legal represented ancestry → caller receives checked results and retains required parent suspension | Specification of existing checks; no arbitrary escaping lifetime rule |

These are abstract rules for the current checker, not an alternative executable
specification. The concrete checks remain in `hia_program.py`'s capability,
instruction, edge and return validation. The JSON matrix points to refusal
tests for the relevant ownership, alias, join and return cases.

## Profiles remain separate

| Layer | Admitted capability | Boundary |
| --- | --- | --- |
| Primitive v1–v6 | Closed typed SSA, explicit CFG/calls, byte owners and versioned byte operations | No borrowed function results, raw pointers or arbitrary foreign instructions |
| Primitive v7 | The preceding rules plus typed owned byte-buffer chains | Dynamic chain length is not a finite allocation or destruction-time certificate |
| Primitive v8 | The preceding rules plus parameter-origin returned loans and checked result aliases | Resource descriptors remain internal; arbitrary lifetime relations and public borrowed-result ABI are excluded |
| Composite v1 | Nominal records/enums and explicit cooperative tasks | Normalizes to primitive v6 |
| Composite v2 | Nominal operations with the v7 resource grammar | Normalizes to primitive v7 |
| Composite v3 | Explicit partially initialized record states | Normalizes to primitive v7; no implicit v8 returned-loan extension |
| Hepta source | Finite checked scalar/record/Result profiles and closed specialization; v1 by default or explicit v8 | No stored returned borrows, general foreign calls or hidden Rust/C fallback |
| Independent Rust shadow | Separately closed scalar, byte-owner, returned-loan and owned-chain Machine profiles | Independent finite comparison; never production admission or deployment authority |
| Direct LLVM | Native code from immutable reverified HIA | Compiler, runtime and platform remain trusted; full Core-to-native refinement is not proved |

The JSON matrix includes the exact profile strings and features from
`hia_schema.py`. Public constructors of supposedly verified objects are not
trusted: consumers recheck their actual bytes. Source/compiler adapters also
preserve public-entry eligibility. Flattening a record into scalars does not
grant a new public scalar C ABI.

## Execution boundaries

| Boundary | Implemented obligation | What is not established |
| --- | --- | --- |
| Normal return | Consume or transfer live owners and end or validly return loans; check CFG and call interfaces | End-to-end source/native refinement |
| Error as a value | Use the same normal-return resource rules; clean earlier allocations on an admitted failure path | General exception unwinding or automatic repair of omitted cleanup |
| Semantic trap | Preserve the stopped VM ledger; native traps abort | Destructors running, recovery, or a cleanup completion theorem |
| Evaluator budget stop | Distinguish resource/step/call-depth stop from a semantic trap and retain the stopped ledger | Source cancellation semantics or native enforcement of interpreter budgets |
| Cooperative cancellation | Execute checked task/queue transitions and initialized-field cleanup at supported boundaries | Arbitrary asynchronous cancellation, preemption or signal-safe unwinding |
| Recursive call / chain | Maintain the admitted Core ownership rules; finite analyses may refuse the program | Universal termination, arbitrary chain bounds, or native stack-byte bounds |
| Concurrent execution | Host adapters lock dispatch/state and require safe points and no conflicting state loans | A general language memory model for threads, shared mutable memory, atomics or MMIO |

An OS reclaiming memory after process termination is different from the
program proving that its owners were cleanly released. Likewise, a VM returning
a stopped resource ledger must not report those resources as normal-exit
cleanup. The existing rejection and differential tests explicitly exercise
these distinctions.

## Static resource bounds and runtime admission

A static budget is an opt-in analysis of an already verified Core program.
Its meaning is fixed by its particular schema and consumer. The implemented
analyses can bound requested live byte payload, selected allocator events,
VM ticks or synchronous call depth in reviewed finite profiles. Some payload
analyses admit narrowly checked scoped cycles; this does not bound cumulative
allocation work, termination or CPU time. Unknown extents, unreviewed opcodes,
recursive call graphs and unsupported resource boundaries must remain unknown
or rejected by the relevant analysis. They cannot become zero or an imported
caller promise.

Static payload accounting excludes allocator metadata, fragmentation, native
stack bytes, foreign allocations, the Python interpreter, compiler memory and
process RSS. A resource receipt is replayed against the actual Core and
numerical result; rehashing understated values does not make them authoritative.
The separately audited v8 consumers do not upgrade older receipt consumers.

Runtime admission is a different mechanism. The adaptive host caps its admitted
native images, in-progress preparations and unresolved native release debts.
The owned-state adapter has a finite state layout and bounded work queues.
These caps constrain host-managed capabilities. They are not a theorem that an
arbitrary native process stays within a fixed number of bytes, nor do they
convert a static estimate into a runtime memory quota.

When loader or descriptor release has an uncertain result, the implementation
revokes usable function references, records the uncertainty and keeps the debt
charged. It never retries a numerical descriptor or loader identity that might
already have been released and reused. Failure of one release must not prevent
attempting the independently owned resource. A release failure is not reported
as complete cleanup.

Prepared equivalence evidence is issued only by the trusted runtime after its
own proof/build/load operation. It has no receipt import API. It binds Core,
state, policy, implementation, artifact and the internal proof ancestry.
Selection still checks the actual sealed mapping and the safe-point generation.
An interruption before transactional publication retires the unpublished image;
an interruption after complete publication leaves that image owned by the
runtime rather than unloading a capability another thread may observe.

## Source/Core/native refinement and the trusted base

Three distinct questions must remain visible:

1. Does the source checker accept the source and does the adapter produce a
   well-formed, resource-valid Core program? This is implemented for the stated
   profiles. It does not itself prove source-to-Core behavioral equivalence.
2. Is an optimization equivalent under its explicit verifier profile? The
   existing scalar and guarded verifiers prove finite bitvector obligations,
   including first observable trap and prescribed resource/effect structure.
   Unknown, timeout or refuted obligations cannot authorize optimized builds.
   This does not prove every possible transformation or global optimality.
3. Does the emitted native code implement every Core behavior? Actual native
   comparisons and allocator observations provide finite evidence. A complete
   Core-to-LLVM-to-machine-code refinement theorem is not established.

The trusted base includes the Python parser/checker/elaborator and operational
code, proof encoders and pinned solver, LLVM emitter and Clang/LLVM/linker,
allocator/runtime/loader, OS and hardware, plus the trusted host's identity and
dispatch mechanisms. Independent Rust crosschecks reduce correlated
implementation risk in a finite domain; they do not remove this trusted base.
Artifact hashes establish which bytes were checked or loaded, not semantic
correctness by themselves.

C and C++ adapters additionally trust captured frontend semantics and declared
foreign obligations. Validated slice/record contracts must agree across
translation units by ABI argument position, including extent and initializer
bindings. A pointer's actual allocation provenance, size, initialization,
lifetime and concurrent foreign accesses are not all dynamically inferable.
Unsafe external code therefore remains outside the safe Core guarantee. ABI
interoperation is not a proof that arbitrary historical C/C++ is safe or can
be translated without review.

The checked-in matrix keeps whole-language soundness, source/Core/native
refinement, global instruction optimality, absolute resource safety, general
concurrent safety, process-memory bounds and Rust performance superiority
explicitly unproved. A passing regression run is not allowed to promote any
of those fields to true.
