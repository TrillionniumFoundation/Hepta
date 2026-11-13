# HIA finite execution owner

This component interprets the complete admitted primitive Core instruction set in
HIA. It replaces the semantic work of the retained Python `_Machine` on an
explicitly selected execution path. It is **not** a claim that all verification,
normalization, compilation, Agent operation or packaging is HIA native.

## Selection and boundaries

The operator selects a trusted image through
`HEPTA_HIA_PROGRAM_EXECUTION_MANIFEST`. The manifest binds the checked
`examples/hia_bootstrap/program_execution.hiaasm` and immutable executable
bytes. A selected missing, stale or malformed manifest refuses; it never invokes
the Python machine as a fallback. An admitted image is kept fixed for one entire
invocation. Clearing or changing the selector after admission does not select a
different implementation partway through execution.

The public `execute_program` keeps its existing ordered outer admission:
verify/snapshot the program, validate exact evaluator-limit kinds, freeze the
argument list as a tuple, check public scalar-entry membership, and apply the
optional bounded-resource qualification and limit intersection. It then selects
the HIA execution owner. HIA performs the function/arity/capability/scalar checks
formerly performed after constructing `_Machine`.

The Agent's borrowed snapshot path retains export/ABI admission and
`buffer_bytes` materialization. Each independently owned snapshot becomes an
opaque storage handle and an initial HIA-owned owner/view pair. The HIA machine
checks the actual runtime view state and supplies the complete stopped ledger.
The outer snapshot adapter retains its read-only-byte check and computes the
existing buffer hashes and external-buffer metadata. No source byte buffer is
charged to the Core heap or to Core allocation attempts.

The private Python classes `_Machine`, `_Owner`, `_View`, `_Chain` and
`_ChainNode` remain independent reference APIs. This component does not promise
to accept arbitrary fabricated Python capability graphs, invoke monkeypatched
reference methods, or expose a new public capability ABI. `ExternalBuffer` is
a private representation of a snapshot already admitted by the Agent boundary;
it is not an input-controlled manifest or a wire capability.

Still outside this owner:

- `_decode`, Python-object snapshots and the selected/default verification route.
- `VerifiedProgram.as_dict()` materialization.
- Optional static bounded-resource analysis.
- Snapshot descriptor admission, byte materialization and final hashes.
- The native code loader, generic byte storage and report-object materialization.
- Native code generation, the service state machine and other existing owners.

## Complete semantic work in HIA

The checked source includes all 50 current opcodes and all four terminators.
The generator combines the main VM with the scalar and resource authoring
modules. These authoring modules are not imported by the installed execution
adapter.

HIA resolves functions, blocks, SSA names and formal loan origins. It maintains
an explicit data stack, not a native recursive call per Core call. Each frame
has its environment generation, original formal bindings, edge/call staging
area, and complete returned-value area. Edge values are captured before the
target environment generation changes. Original formal bindings remain separate
from renamed block parameters.

The compiler's own kernel profile remains unchanged: at most 128 functions,
1,536 blocks, 8,192 operations, 16 block parameters and three instruction
results. The current VM kernel fits those limits. User Core is data; its
parameter and returned-value inventories are not narrowed to the compiler
kernel's profile. The component controls include a real 4,097-parameter call
with 4,097 returned values, plus 4,097 repeated unit returns.

The scalar kernel implements canonical low-width words for the ten integer
types, bool and unit. It owns signed overflow, division and remainder,
MIN/-1, count-checked shifts, wrapping, casts, comparisons and selection.
Constants are parsed by the main HIA VM. The scalar subcomponent also has a
separate mathematical oracle, all 100 integer cast pairs in both modes,
30,704 actual machine entries and 74 independent VM comparisons in its retained
development evidence. Its separately qualified source is included verbatim;
that subcomponent evidence does not qualify the whole interpreter.

The HIA resource table gives every dynamic resource a monotonically increasing
identity. Physical record slots are recycled and the open-addressed identity
table is rehashed; a reused address does not resurrect an expired identity.
Owners, local and incoming views, chains and chain nodes have separate kinds.
HIA handles every allocation/ownership/loan transition, first stop and counter.

## Ordered observable behavior

The controls compare complete results and exception reports against the original
machine, including program/input identities, exact message text and ledger shape.

| Boundary | Preserved behavior |
|---|---|
| VM ticks | Increment first; a step stop reports exactly maximum plus one. |
| Calls | Root occupies frame one. A refused next frame has no entry tick. Owning actuals have already been consumed by the call instruction. |
| Zero allocation | A real empty owner, no allocator attempt, no injected failure. |
| Oversized allocation | Check the signed 64-bit object-size model before heap and attempt accounting. Optional allocation returns an empty owner and false. |
| Heap quota | Refuse before incrementing attempts, including optional allocation. |
| Allocator failure | Increment attempts before deterministic or actual raw-storage failure. HIA chooses trap versus optional empty owner. |
| Failure index | A positive arbitrary-precision Python integer is represented by sign-independent bit length and low 64 bits; no decimal conversion or new u64 restriction. |
| Byte operations | Resolve live owners and permissions; check every complete range before the first write, including zero-count boundary cases. |
| Copy and move | Distinct-owner copies remain distinct; in-place moves retain overlap semantics; swap captures both bytes before writing. |
| Chain nodes | The existing 24-byte storage participates in the same heap and failure sequence as payloads. |
| Chain push/pop | Preserve the original empty fallback-owner creation/drop and ownership-transfer counters. |
| Chain destruction | Consume the chain first, then tick per node before dropping payload and node storage. A stopped destruction retains its actual live-node/owner prefix. |
| Returned views | Resolve original formal origins after all function work. Forwarding creates a fresh child and increments loans; a direct child transfers without another increment. |
| Borrowed entry | Incoming roots/views are caller storage; local children are counted. Stopped writes remain visible in the exact final buffer hashes. |
| Report schema | v1–v6 omit chain counters; v7/v8 include them. Empty return lists, unit, bool and signed integers retain their original representation. |

HIA validates the complete execution ledger before exposing a returned/trapped/
budget result. This validation includes owner, allocation, loan and chain
conservation; live/peak payload; external backing; normal-return cleanup; and
the outcome-specific tick constraint. The bridge does not run a second Python
ledger-policy implementation.

## Fixed raw-storage protocol

The image uses the existing six-word foreign-call ABI:
source pointer/length, output pointer/length, and workspace pointer/length.
Initial typed metadata is copied into the private arena. The machine may then
request only these fixed storage actions:

1. Transport the already frozen arguments as exact-kind scalar words or opaque
   initial external-storage references.
2. Grow the private arena and copy its existing bytes without interpreting them.
3. Request one zeroed `bytearray(size)`; return an opaque handle or failure.
4. Release one held internal storage handle.
5. Map exact source/destination windows for the next HIA byte operation.

The host does not receive a Python opcode plan. HIA issues the operation, checks
permissions and bounds, mutates bytes and chooses the next continuation.
The adapter never decides whether an allocation is optional, whether a heap
quota is exceeded, whether a view is live, which block is next or which error
wins. The allocation callback catches only `MemoryError`/`OverflowError` from
the one requested raw allocation; the HIA machine chooses its semantic result.

Each actual issued frame is a frozen structure of exact built-in words and
tuples. The bridge binds the exact frame object and all typed fields before
consuming its permission. Permission is consumed before a callback can run.
A frame cannot be replayed after the callback or after interruption. Terminal
admission is also once-only. Frame decoding rejects noncanonical bool/unit
words, high bits outside a narrow integer representation, noncanonical chain
flags and a returned status carrying an error.

These are private continuation and materialization guarantees, not a sandbox
against arbitrary same-process mutation of executable memory or private arenas.

## Memory custody and physical failures

Private arenas are mmaps, so they can be explicitly closed even while the
original failure traceback is retained. During growth the context retains
both the newly allocated arena and the previous arena across every assignment
and close boundary. Revocation is permanent; cleanup remains retryable.

Closing a context first revokes all permissions and window references. It then
attempts every internal storage release and every arena close. A retained
external exported view can cause a real `bytearray.clear()` `BufferError`;
the context stays revoked, still closes its arenas, retains unreleased storage,
and can retry physical cleanup after that export is released. Cleanup never
replaces the original callback/foreign exception. Borrowed caller snapshots
are retained without clearing their bytes.

Physical cleanup does not rewrite the native stopped ledger: an aborted VM
can report live logical resources even after the disposable execution context
has released its implementation storage.

Two Python-only reference channels require precise qualification:

- The reference bulk fill/move helpers allocate bounded temporary Python
  scratch and translate its `MemoryError` into a `host_memory` budget stop.
  The HIA byte primitives do not allocate that temporary scratch. Monkeypatching
  the unused reference helper therefore does not induce a native VM stop.
- The reference recursive Python call implementation can hit ambient
  `RecursionError` before its Core frame quota under an unusually small Python
  recursion limit. The HIA implementation uses its explicit data frames and
  keeps the same declared Core frame quota.

The new owner does not invent either of those historical implementation failures
when the relevant allocation/host recursion does not occur. It does not broadly
catch foreign failures and fabricate a successful or budget report. Private
arena allocation errors, invalid storage windows, callback interruptions and
other transport failures preserve their real exception identity. A raw program
storage allocation failure follows the original HIA optional/trap policy.

## Private extent validation and the admitted public domain

The initial packet contains the already admitted Core tree, entry name,
argument count and fixed-size limit metadata. The evaluator keeps the original
public verifier and its exact ordering. Its historical Python object protocol
does not establish that every final canonical Core has at most 262,144 nodes:
a dict subclass with stateful metaclass equality can present an empty iterable
to the structure pass while the original JSON encoder reads its real dictionary
contents. The final byte check and semantic Core verification still run.

This is an actual admitted-domain case. With 262,145 `unit` return declarations
and matching repetitions of one unit SSA value, the original verifier accepts
the object and the original evaluator returns all values in three ticks. Its
canonical Core is 2,883,889 bytes in the preserved diagnostic. The frozen c6
native image also completed the operation, but its adapter refused the result
because it exceeded `MAX_RESULT_VALUES=262144`. That original failure is
retained separately. Ordinary submitted dicts and text still receive their
original structural limits; this correction does not change normalization.

The interpreter now has no fixed private wire, node, argument or return-count
quota. The typed representation adds a 16-byte header for each node and an
eight-byte count for a container. Its decoder derives the maximum represented
node count from `input_length // 16`, and the maximum immediate child count
from `(container_payload_bytes - 8) // 16`. A map count is doubled only after
this check. Every child header and payload must also fit the exact enclosing
container extent, and every container must finish at that extent. These are
representation validity checks on the actual packet, not a second source
admission. The initial arena is sized from the actual wire length. Terminal
values are accepted only when their complete 16-byte records fit the actual
workspace extent, with no independent count ceiling.

The decoder's 128-level scratch stack follows the verified Core grammar,
independently of the public structural traversal. Program, functions, blocks,
instructions, output parameter objects and their fixed private wrapper use at
most ten enclosing containers. Instruction attributes and declared types are
already verified scalar/flat forms, and no arbitrary nested extension object
survives Core verification. The separately requested argument packet uses only
three container levels. Scratch occupies bytes 4096 through 7191, below the
8192-byte arena base, even for malformed packets reaching the private limit.

Arguments are encoded only after HIA accepts the function and exact argument
count. Wrong-arity input is rejected before making an argument-row packet.
Each argument has a four-word representation; integer bit length and low bits
remain words regardless of the integer's magnitude. Each external snapshot
adds a three-word storage row and two native records, without copying its byte
payload into the typed packet. These inventories are represented in full;
their memory requirements follow the actual admitted invocation.

The arena has no additional fixed runtime quota. It grows on native request,
subject to real host allocation availability. Frames and resource records are
reused; old identities do not reappear. The arena chooses the smallest fitting
free block, preferring an exact extent, to avoid repeatedly splitting the
just-freed large callee frame when calls alternate between large and small
signatures. The original first-fit diagnostic retained a growth from 1 MiB
at ten iterations to 8 MiB at 512 iterations; it remains separate evidence
for this storage-reuse correction. The original semantic limits stay at
1–10,000,000 ticks, 0–1 GiB live Core bytes and 1–256 live Core frames.
No boundary is input-controlled through manifest fields.

## Evidence status and retained failures

This source is currently a development component built by the explicitly named
retained predecessor compiler, SHA
`0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`.
It has not inherited the predecessor's cold qualification.

The first whole-kernel compilation succeeded. Its first 27 differential
invocations exposed an incorrect relocation of the typed decoder's root count
from offset 136; the root stack base had already moved to 4096. Those original
rejections remain in the r1 evidence. The correction moves both the root frame
and count; r2's 27 complete observations match the independent reference.

The first complete 19-test run retained 17 passes and two fixture errors.
The allocation fault fixture accidentally faulted on an empty adapter buffer,
and the borrowed fixture declared u8 where the existing Agent ABI requires
one u32 return. Both were corrected explicitly. That first run also retained
774 complete differential observations, 3,612 native entries and two independent
VM full-workspace comparisons with unchanged inputs.

A separate actual native grow request plus controlled post-swap interruption
then demonstrated that the previous mmap remained live in a retained traceback.
The original false observation is preserved. The corrected context retains the
previous arena explicitly and its new controls interrupt all three swap/close
boundaries. An earlier untriggered opcode-injection attempt is labelled a
harness attempt, not a completed runtime finding.

The next complete component run passed **22/22** in **14.462 seconds**, with
775 complete reference differentials, 3,637 native entries and two independent
VM full-output/full-workspace comparisons. It includes all opcode families,
all terminators, 4,097-wide signatures/returns, borrowed stopped bytes, actual
allocator failure, actual arena-growth interruptions, a real exported-buffer
release failure and noncanonical terminal frame rejection. Source and build
inputs remained unchanged. The original failure logs are not relabelled.

The source, adapter and machine test classes are
`ProgramExecutionSourceTests`, `ProgramExecutionAdapterTests` and
`ProgramExecutionNativeTests`. Fixtures use
`HEPTA_HIA_PROGRAM_EXECUTION_COLD_REPORT` or
`HEPTA_HIA_PROGRAM_EXECUTION_DEVELOPMENT_COMPILER`, never both, and preserve
raw source/compiler/image/manifest identities. Production packaging/candidate
registration, a fresh matching whole-source cold run and the complete retained
repository qualification remain separate integration gates.


The selected existing public-runtime roster additionally passed 92/92 in
3.067921 seconds with 4,117 actual native entries, zero skips and unchanged
source/image/manifest inputs. This roster intentionally identifies the public
controls it executes; it is not the repository's full discovery suite. The
original Python-only fault-hook controls remain distinct reference tests.

The following complete run passed 25/25 in 24.201 seconds, including the
smallest-fitting arena reuse correction, a real 43,680-parameter invocation
near the public node limit, and mutation of the original argument list/selector
after actual native admission. A later actual private-frame negative control
then demonstrated that rich metaclass equality could satisfy the bridge's
\`type(value) in (int, bool)\` guard. Its original observation is retained:
the callback ran with a non-exact sequence object. The private frame guard now
uses identity comparisons, and its control requires rejection before any rich
comparison, index hook or callback executes. Public source normalization's
historical rich-comparison behavior is outside this correction.
