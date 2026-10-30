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
HEPTA_RUN_ARTIFACT_SESSION=1 python tools/qualify_hia_safety_contract.py --output /tmp/hia-safety/report.json
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

Integrated qualification explicitly enables the mandatory Linux native
artifact-session regressions before starting its fresh test processes. Direct
CLI use and CI use the same requirement. Missing tools or a skipped selected
test cannot count as a passed gate. The configuration regression that checks
this activation does not itself execute a native workload.

The integrated qualifier separately binds its main working tree to the original
committed source. It enumerates all paths and regular-file modes from the exact
SHA-1 HEAD tree with Git replacement objects disabled. Each stable file read
computes both SHA-256 and the Git blob identity over its actual raw bytes; the
blob must equal that tree entry, and the owner's executable bit must match.
`assume-unchanged`, `skip-worktree`, a clean status, or `core.fileMode=false`
cannot substitute different bytes or modes. Missing files, nonregular tree or
working members, unsafe/duplicate paths and changes during an identity read
are rejected. Hints on unchanged bytes remain accepted. This is a source-input
identity check, not authentication of a hostile host or a refinement theorem.

The reviewed matrix also includes the finite filecheck research target and
native-failure boundaries. Its full-LTO IR retains the actual C frontend's CPU
and complete positive/negative feature attributes; a real masked-x86 emulator
checks the reproduced refusal and successful bound route. Differential and
maintenance workers preserve actual signal status and partial progress in a
failed parent qualification report. The linker and emulator identities are
recorded, and integrated qualification binds the emulator before and after.
These checks preserve all previous selectors and do not change production
admission or the `no_change` policy. See
[the detailed contract](HIA_FILECHECK_NATIVE_TARGET_AND_FAILURES.md).

The next explicit profiles add caller-derived borrowed extent bounds, checked
single-feedback scalar unfolding, actual native Linux C application hosts,
finite sealed execution contexts and a CRC study with static coalesced
controls. They retain every prior regression selector. Borrowed lengths remain
intervals rather than assumed successful allocation sizes. Loop trip counts
must be proved for all typed inputs before candidate equivalence is checked.
Native contexts consume a finite plan once, load only referenced images and
retain unresolved child/descriptor ownership instead of replaying work.
See [borrowed extents](HIA_BORROWED_EXTENT_HEAP.md),
[bounded unfolding and CRC](HIA_BOUNDED_UNROLL_AND_CRC.md), and
[actual C native hosts](HIA_CAPTURED_C_NATIVE_HOSTS.md). Passing these scoped
contracts does not close the universal safety, NDU incremental value or
whole-program performance claims below.

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
| Composite v4 | V3 operations plus primitive loan results from declared original parameter/record-field paths | Normalizes to primitive v8; only incoming loan-only parameters may anchor results; no borrowed aggregate results or loans retained by partial/task state |
| Hepta source | Finite checked scalar/record/Result profiles, concrete unit enums, local byte-view records and closed specialization; v1 by default or explicit v8 | Local views follow the lexical Resource IR profile; no stored returned borrows, general foreign calls or hidden Rust/C fallback |
| Independent Rust shadow | Separately closed scalar, byte-owner, returned-loan and owned-chain Machine profiles, with invocation-bound outcomes and stopped ledgers | Independent finite comparison; execution v2 binds root-inclusive depth 1–32, while legacy/v1 stay at 32; never production admission or deployment authority |
| Direct LLVM | Native code from immutable reverified HIA | Compiler, runtime and platform remain trusted; full Core-to-native refinement is not proved |

The JSON matrix includes the exact profile strings and features from
`hia_schema.py`. Public constructors of supposedly verified objects are not
trusted: consumers recheck their actual bytes. Source/compiler adapters also
preserve public-entry eligibility. Flattening a record into scalars does not
grant a new public scalar C ABI.

Source unit enums have 1–32 concrete payload-free variants and lower to existing
`u32` tags and CFG branches. Their original nominal signatures still restrict
public scalar entries. Local view records contain one direct byte-slice
reference and at most four scalar labels; view parameters, returns and nesting
remain excluded. These source additions do not reinterpret composite v3 or
replace composite v4's separately declared parameter-field return origins.
The invocation-bound Rust execution profiles compare the full outcomes and
stopped resource ledgers within their own finite budgets. They do not silently
replace the larger budgets accepted by the Python execution APIs.

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

The separate `hepta.hia.entry-payload-analysis.v1` profile accepts primitive v1
with a public scalar entry and checks every function against its closed opcode
inventory. It requires an acyclic call graph and preceding same-block constant
allocation sizes. CFG cycles may access resources only when their complete
call closure contains no allocator opcode. It conservatively adds allocation
sites across branches and syntactic call sites. Since the scalar entry has no
incoming private owners, cumulative requested payload also bounds live logical
payload on every finite trace prefix. This is not a tight peak, a termination
or cleanup theorem, or a bound on private incoming owners. It does not enlarge
the acceptance domain of any older budget or native admission consumer.

Static payload accounting excludes allocator metadata, fragmentation, native
stack bytes, foreign allocations, the Python interpreter, compiler memory and
process RSS. A resource receipt is replayed against the actual Core and
numerical result; rehashing understated values does not make them authoritative.
The separately audited v8 consumers do not upgrade older receipt consumers.

The separate `hepta.hia.finite-entry-live-heap-admission.v2` contract composes
already legal v8 owner transfers/returns with original-parameter returned loans
for one exact scalar invocation. It retains caller-owned payload while a callee
borrows it and reconnects each returned loan to the canonical actual argument.
Unknown external extents stay unknown inside the callee. CFG and call cycles,
chains and exhausted analysis limits remain refused. Legacy v7 invocation and
v8 local-summary profiles keep their original scopes. See
[the finite v8 contract](HIA_FINITE_V8_HEAP.md).

The round7 matrix retains all 146 prior selected regressions, adds 22 initial
selectors and three target-policy repair selectors, for 28 capabilities and
171 unique selectors. The additions cover
that finite v8 composition, captured C post-test loops and the separate two-u32
guarded native opportunity profile. Its native experiment recomputes Core and
selected LLVM proofs before compilation, binds the actual exported function
bytes and retains each finite child's result. Unknown proofs cannot become
economic negatives or admitted candidates. Neither a passing economic gate nor
the compiled code's different hash grants NDU execution/publication authority.
The predeclared demand is synthetic, and observed timing envelopes are not
statistical confidence intervals or evidence of application benefit.

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

The scalar multiversion dispatcher also preserves ownership across the bounded
publication and retirement interruptions in
[the publication contract](HIA_PUBLICATION_INTERRUPTION.md). Retirement retries
must finish detaching an unleased retired generation before releasing it. A
failed background worker closes admission and settles its accepted Futures;
an already committed publication remains owned by the runtime. These host
transitions do not establish arbitrary asynchronous language unwinding.

`PreparedArtifactSession` adds a separate finite research owner for internally
proved and built sealed images. Its supported entry is one nonrecursive
primitive v1–v7 `full_lifecycle(usize, u32) -> u64` checksum function on Linux
x86-64. Every invocation runs in a fresh child; no owner or loan persists across
invocations. Private proof ancestry, implementation, solver, policy, compiler
and sealed-image identity remain bound during reuse. Leases keep their image
and parent alive, failed transactional publication restores visibility and
accounting, and uncertain descriptor release remains charged without retrying
a potentially reused number. Its caps cover retained images and canonical
metadata; they exclude Python overhead, build temporaries and child process
memory. This profile does not admit foreign receipts, v8 resource-state
migration or arbitrary hot replacement.

The one-shot NDU bridge, persistent session and optional response cache use
[one versioned advisory response contract](HIA_NDU_RESPONSE_CONTRACT.md).
Malformed identities, typed request bindings, candidate partitions and path
records are refused consistently. A poisoned session is terminal and cache
hits are revalidated. This checks the response envelope and its declared
bindings; it does not recompute utility, establish globally optimal policy,
authenticate an input proof digest or authorize code admission. The cache
remains opt-in and downstream proof/build gates remain independent.

The prospective prepared-reuse comparison protocol separately checks equal
proof policies and runtime limits, full-cost accounting, admitted opportunity
controls and the exact candidate that was selected, built and observed. Actual
cell-specific timing feedback updates an additive finite allocation model;
the complete-DP control receives the same model and shared compile-credit
constraint. Internal proof reuse is available to all arms. Protocol regression
inputs are constructed controls, not fresh performance measurements. Prior
experiments retain their original source identities and negative outcomes;
historical controller build time cannot be relabeled as a newly measured cold
run. No NDU algorithm benefit or global instruction optimum follows from a
passing protocol check.

Scalar C migration additionally bounds source reads, public IR structure and
emitted parser depth and isolates source, output and report paths. Oversized
input prefixes are not represented as full source identities. These controls
do not infer foreign pointer obligations or expand the admitted C/C++ grammar.

The captured C project-view route lowers selected record/slice bodies with
explicit frozen contracts into the existing source checker and primitive Core.
It separately accounts for authored Hepta clients that own the storage and
call the migrated borrowed interfaces. Capture identity is rechecked after
lowering, and only the checked scalar public entries are exported. This route
does not compile a hidden Rust bridge, link the original C implementation into
the target, infer foreign obligations or preserve a foreign record/pointer ABI.
Its selected native application and failure-path comparisons remain finite
evidence on the host that actually executed them.

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
3. Does the emitted native code implement every Core behavior? The selected
   scalar lowering validator compares an actual internal LLVM body and its
   acyclic scalar call closure with the existing Core SMT encoder. Within its
   bounded instruction grammar, an `unsat` result establishes the encoded
   value/abort correspondence and absence of modeled LLVM poison. Unknown
   syntax, loops, recursion and solver uncertainty cannot inherit that result.
   This does not prove the encoders' own correspondence to their complete
   languages, public wrappers, C ABI or machine-code generation. Actual native
   comparisons and allocator observations provide additional finite evidence.
   A complete Core-to-LLVM-to-machine-code refinement theorem remains absent.

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

### Legacy IR PGO target-policy repair

The initial round-seven CI exposed a missing native feature binding in legacy
research overrides. The canonical matrix now includes the actual masked-CPU
legacy/IR-PGO/resource build control, bound-input/compiler drift refusal, and a
supervised SIGILL diagnostic without retry. These three selectors supplement the
initial 168 without removing any previous selector. All four native HIA research
compilation paths consume the separately recorded, freshly checked bound IR;
original Core and raw LLVM identities remain distinct. Compiler, runtime and
hardware trust boundaries still apply.

### Checked-source native receipt convergence

The round-eight host extension added `build_host` and
`cross_target_compilation` to the native producer's closed receipt. The older
checked-source bridge still expected its previous field set, so a valid owned
Hepta source could pass Rust checking and Clang compilation yet be refused at
the source/native boundary. The complete regression run exposed this mismatch;
the narrower optimization suite and canonical matrix did not yet select that
existing source-path regression.

The bridge now reobserves the actual host and checks every host field's exact
primitive type and value. The cross-target field must be an actual boolean
equal to the requested target's difference from the observed host target.
Missing, extra, forged or incorrectly typed fields are rejected together with
the existing Core, LLVM, compiler, artifact, export/import and publication
checks. The established object/shared-library and target restrictions remain
part of the same admission contract.

Rejected checked-source qualification retains a bounded, detached JSON snapshot
of the real builder diagnostics and exposes the first nested diagnostic in the
ordinary exception text. Malformed or oversized diagnostic data cannot replace
the original refusal. Diagnostic data grants no execution or publication
authority. The two existing source-reinspection and v6 differential modules
now participate in the verified regression and critical coverage group; their
16 methods also extend the canonical matrix from 250 to 266 selectors without
removing an earlier selector or capability. The actual owned-source path and
host/cross-target forgery controls are required alongside the producer tests.
