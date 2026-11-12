# Complete initializer P12 resource peer — development revision 2

This source replaces the six values requested by the existing initializer's
P12 phase 41. It is a new reconstructed development revision: the earlier
local-only draft became inaccessible before it was saved. No execution result
from that draft is inherited. The three HIA authoring modules, mechanical
integration harness and CI driver below have not yet been parsed, compiled or
executed by their new CI job.

## Semantic ownership

Operations 1 through 6 produce the complete values used by the original
HIAAgentService._profiles: schema_registry, WORKLOAD_SCHEMA, OBJECTIVE_SCHEMA,
COST_POLICY_SCHEMA, PLAN_SCHEMA and proof_contract_description. Their exact
reference expressions and the six discovery calls are checked while authoring.

The static values are finite source data. The compiler emits their exact Graph
pool, and the new HIA controller computes SHA-256 over the complete pool before
using it. The pool retains integer, binary64, Unicode, ordered mapping, tuple,
bytes and alias representations through the original Graph capture format.
Runtime Python does not construct a resource body.

Operation 1 calls the complete frozen native metadata owner with HIAPMC01
operation 3. The catalog hash is computed by that native owner. The P12 owner
checks every returned canonical registry byte, allowing only the designated
64-character lowercase hexadecimal digest to vary, and copies that actual
digest into the source-bound registry Graph. It does not embed a precomputed
catalog hash or call a Python schema registry in the native interval.

Every resource is imported by the actual existing registry and Graph-merge
kernels. The P12 owner constructs RESERVE/IMPORT commands, checks the actual
completed event, counts and handle, then compares every relocated right-hand
node, edge and scalar byte before producing the initializer's HIAWIR01 reply.
The existing registry validates the complete left and right merge and owns
value-handle issuance. P12 does not publish namespace objects or authorize file
or SQL effects.

## Caller and lifetime requirements

The entry is the retained R/W/W flat ABI. Its second argument is borrowed read
inside HIA, so the semantic inputs are R/R/W. The caller owns an immutable
current registry Graph, the actual initializer workspace/event, actual registry
results and actual metadata workspace. These are private issued views from
fixed source-bound images in one invocation.

Header equality and nonce values are correlation, not authentication of
arbitrary external memory. The pool hash binds only the finite source pool.
A fixed issuer must forward the actual peer output associated with the request,
keep it immutable while borrowed and preserve the original source lease during
GROW. Graph value handles confer no namespace authority.

One P12 lease serves exactly one resource request. Success and any private
refusal close it. A full workspace records permanent refusal. An advertised
workspace shorter than 8192 cannot reliably hold a poison flag: any BAD return
requires the outer coordinator to retire the lease without consulting a stale
event. No semantic producer is retried after completion.

## Command

The first argument is the current HIAGRF01 bytes. The second starts with sixteen
little-endian u64 words:

| Word | Field |
| --- | --- |
| 0 | HIAWRC01 |
| 1 | operation: 1 BEGIN, 2 reserved result, 3 metadata result, 4 imported result |
| 2–4 | initializer invocation, call, resource lease |
| 5 | previous resource event sequence |
| 6–7 | current Graph lease and complete byte length |
| 8 | exact following payload byte length |
| 9–11 | actual return, peer role, complete peer extent |
| 12–15 | zero for operations 2–4 |

BEGIN uses words 9–13 as actual initializer return 2304, complete initializer
workspace length, actual last registry return 768, registry event bytes 256,
and exact source pool bytes. Words 14–15 are zero. Its payload is the complete
actual initializer workspace, its last completed registry event, then the
complete source pool. The current Graph remains the first argument.

BEGIN verifies phase 41, P12, pending sequence, operation 1–6, every zero
argument/view field, the actual initializer event and current registry identity.
The first workspace is zero-initialized and at least 8192 bytes. If capacity is
insufficient, replay the same complete BEGIN bytes and same immutable inputs
with the preserved workspace grown to the requested size; BEGIN's wire sequence
remains zero. The resource event sequence still increases at every entry.

Operations 2 and 4 carry the exact 256-byte actual registry event and report
return 768, peer role 1 and extent 256. Operation 3 carries the complete actual
metadata workspace, actual return 128 or fffffffe, peer role 2 and its exact
extent. Other command sequences match the preceding resource event sequence.

## Event and actions

The return is 2816; the event occupies bytes 2560 through 2815. It contains
32 little-endian u64 words:

| Word | Field |
| --- | --- |
| 0 | HIAWRE01 |
| 1 | action |
| 2–5 | invocation, call, resource lease, event sequence |
| 6–7 | phase, refusal reason |
| 8–11 | initializer pending, resource operation, original source lease, digits |
| 12 | own workspace needed |
| 13–15 | actual peer role, command offset, command bytes |
| 16–17 | metadata workspace needed, first-call flag |
| 18–19 | Graph packet offset and bytes for IMPORT |
| 20 | reserved foreign Graph lease |
| 21–24 | current Graph lease, bytes, registry sequence, active command |
| 25–27 | initializer reply offset, reply bytes, result handle |
| 28–31 | zero |

Actions are 0 DONE, 1 own GROW, 2 registry RESERVE, 3 metadata CALL/GROW,
4 registry IMPORT and 6 private refusal. BAD fffffffd takes precedence over any
event. All offsets refer to the current resource workspace and are borrowed only
until its next entry.

For action 2, forward the native 128-byte registry command unchanged. For
action 4, forward the native 128-byte command plus the indicated complete Graph
packet. The existing registry/merge protocol performs all its own continuations;
only its actual final completed event and actual new Graph are returned to P12.

Metadata action 3 carries the exact 96-byte command
[HIAPMC01,1,resourceLease,initializerPending,3,0,0,0,0,0,0,0].
Its first source view is empty. Start with the indicated zero workspace on the
first call only. Preserve all state and repeat the same command on metadata
GROW; the source-derived exact needed capacity is 129420. Never zero a resumed
workspace or repeat completed metadata.

DONE provides the exact 256-byte HIAWIR01 success reply: same invocation/call,
same pending sequence, peer 12, kind 2 and the actual issued handle. Only then
resume the original initializer, preserving its full workspace while P12 ran.

## Validation planned in the independent CI job

The driver first rebuilds the original eight registry/pure/value/GraphWire
images, digest and SHA images, and Store method image. It then compiles the new
P12 owner and complete frozen metadata source, for thirteen fresh images total.
The exact historical development B3 remains 668608 bytes, SHA256
0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8.

Compiler limits remain 10 CPU seconds / 20 wall seconds / 256 MiB. The new owner
retains the 128 functions / 1536 blocks / 8192 instructions / 256 blocks per
function / 16 block parameters / SSA index below 2048 authoring gates.

Three independent groups retain 90 CPU seconds / 180 wall seconds / 1 GiB:
two full original constructor/original Store oracle cases; one full staged
capacity case; and one full constructor to obtain actual frames followed by
51 private malformed-frame, result, source, pool and permanent-refusal controls.
Every case retains full state, ordered call trace, partial attributes, exact
error and native buffer/canary evidence. The new groups are not a replacement
for the original outstanding eight-case aggregate-budget test.

The shared immutable-byte evidence cache changes only hashing/compression work:
a cache hit requires complete byte equality. Full inputs, outputs, pending rows,
completed rows, image/source pins and all native invocations remain recorded.
Both process-limit configuration and actual self/children CPU observations are
retained, and each runtime group separately requires aggregate child CPU below
90 seconds.

The complete old constructor and Store methods form the oracle before the
native interval. Runtime forwarding disables old initializer/value/Store/wire
owners and schema_registry/proof_contract_description while P12 executes.
The remaining eleven initializer peer IDs and physical namespace effects are
explicit foreign fixtures. No ordinary Worker, namespace, installed route or
whole-stack completion is claimed.
