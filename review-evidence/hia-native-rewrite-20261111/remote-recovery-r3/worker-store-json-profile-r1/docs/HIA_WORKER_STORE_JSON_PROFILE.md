# Worker initializer Store.json/profile invocation — new private component

Status: NEW, UNEXECUTED. The three authoring sources have exact Git text custody.
No AST, HIA generation, B3, VM or native execution is claimed for this revision.
The prior digest component is a separate executed dependency; its qualification
does not extend to these files.

## Scope and exact source

The source of behavior is 0ef AgentStore.json/profile, hepta/hia_agent_store.py
Git ce939c30102a16d0c0d9736774dca3c50d91f879, 20,250 bytes,
SHA256 fae25d48a6de7187ed465287c1491af74214ac8bf3eae2af921bd100a247b822.
The target callers are the unchanged complete initializer's peer 11 and peer 15.
These exact callers omit metadata (None). This is not an implementation of
arbitrary public Store.put/get/profile, Worker all eleven tools, or physical SQL.

For json(value, "discovery"), HIA requests the existing full GraphWire scan/emit
with max 8 MiB, ensure_ascii false, sort_keys true, original digits setting; only
on successful serialization does it issue pending Store.put(wire, kind, None).
It returns the exact issued reference handle from the actual put result.

For profile(identifier, value), HIA executes the same wire/put sequence with
kind "profile". After put succeeds it reads the issued reference's sha256 value,
constructs the profile value, serializes the full reference using a NEW private
GraphWire workspace, and then requests the fixed SQL operation:
INSERT OR IGNORE INTO profiles VALUES (?,?,?)
with ordered binds (identifier, ref["sha256"], wire(ref).decode()).
Only after actual SQL success does it publish the profile and exact reference.
There is no added BEGIN or COMMIT. Errors stop at their original stage.

The namespace ABI is verified from the exact 51,264-byte inventory, Git
2cb6092f730298252943830a38b2864fce2597cd,
SHA256 c15222c99cb04ef8bc6a7f13108a7e90adb0bc908876d663eb4329fd14563c04.
The generator verifies exact SQL uniqueness, operation 5, table 2, three binds
and the ordered columns id/sha256/artifact. It does not infer storage classes
from the TEXT declarations or coerce returned scalar values.

## Authority and current integration boundary

The component consumes the actual immutable initializer workspace, an actual
registry BORROW event/configuration, and the same registry Graph lease.
All headers are correlation checks. They do not authenticate arbitrary
caller-supplied copies, replacement Graphs, or fabricated native results.

The namespace request/result interface below is NEW and pending. Runtime's
ordinary high-level put/get/profile/31-SQL coordinator has not issued this
interface. A development fixture may supply it only with explicit foreign-peer
scope. A matching header, op2 ACK, or Graph ID is never evidence of a durable
namespace publication. The eventual fixed issuer must bind actual context,
call, action, live Store authority, operation, original byte views and the real
owned result/error lease, and preserve existing transaction semantics.

Existing Graph value handles are disjoint from namespace authority. Immutable
Graph source content and complete namespace result/exception custody are fixed
issuer obligations. No digest replaces the registry or namespace authority.

## Function ABI and workspace

The retained outer ABI is RWW, with its second buffer borrowed read-only by the
entry: first = current issued HIAGRF01, second = command and complete actual
payload, third = component workspace. Minimum workspace 16,384 bytes. All
large views are offsets, never retained pointers. Event is 256 bytes at offset
512, successful ABI return 768. BAD = 0xfffffffd.

Every BAD retires the component lease immediately. With a complete workspace
the component latches phase 99; terminal phase 90 also refuses reuse. A short
advertised workspace cannot persist poison and must still be retired by the
fixed caller. Natural u64 sequence/extent overflow is private ABI refusal,
not a new public semantic quota.

Each invocation serves one actual initializer peer request. Names are the exact
unchanged initializer literals: profile names or "discovery", currently at most
32 bytes. This is not a new public string-name limit.

## Command, 16 little-endian u64 words

0 HIAWSV01
1 operation
2 initializer invocation
3 initializer call
4 component lease
5 last component event sequence
6 current source Graph lease
7 current source exact extent
8 payload bytes, exactly total input minus 128
9 actual peer return
10 actual producer role
11 actual producer extent
12 auxiliary 0
13 auxiliary 1
14 last issued component action id
15 zero

Operations:
1 BEGIN: complete actual initializer workspace + actual BORROW event256 and
  configuration64. actual return2304, role1, producer extent=initializer workspace
  size, aux0=actual registry return768, aux1=0, previous seq/action0.
2 WIRE: full actual GraphWire workspace, actual return128, role1 scan or role2 emit.
3 NAMESPACE: complete actual pending interface result described below.
4 CONT: same immutable completed peer payload after own GROW. It never reexecutes
  GraphWire, put, SQL, or registry effects.
5 RESERVED: actual registry event256, actual return768, role5, extent256.
6 BOUND: actual completed registry IMPORT event256, actual return768, role5,
  extent256, first buffer the new actual merged registry Graph.

All other aux fields are zero. Source may change only at a successful put result
and completed actual registry IMPORT. Error and SQL success keep the same source.

## Event, 32 little-endian u64 words

0 HIAWSE01; 1 action; 2 invocation; 3 call; 4 component lease; 5 event sequence;
6 phase; 7 refusal reason; 8 initializer peer; 9 original pending sequence;
10 Store authority; 11 component action id; 12 own GROW need; 13 producer role;
14 producer workspace/receipt minimum; 15 request offset; 16 request bytes;
17 put wire offset; 18 put wire bytes; 19 put kind offset; 20 put kind bytes;
21 produced Graph offset; 22 produced Graph bytes; 23 selected Graph root;
24 produced Graph lease; 25 current source lease; 26 current source bytes;
27 final initializer reply offset; 28 reply bytes; 29 registry command sequence;
30 registry event sequence; 31 exact returned reference handle.

Actions:
0 DONE, with exact HIAWIR01 success.
1 continue the SAME GraphWire workspace, including scan/emit and peer GROW.
2 grow only this component; retry operation4 with the original completed input.
3 pending Store.put, only after full value wire success.
4 pending fixed SQL op5, only after put and full reference wire success.
5 semantic exception, with exact HIAWIR01 error and complete opaque payload.
6 actual registry RESERVE, forward complete generated128B command.
7 actual registry IMPORT, forward complete generated128B command plus native Graph.
8 private refusal; BAD return always takes precedence over any event.
9 START a NEW zeroed GraphWire workspace, even if another wire session finished.
  This explicit action forbids the executor from guessing resets from values.

For actions1/9 the request is the actual64B native registry-issued GraphWire config.
For3/4 it is HIAWNP01 below. For6/7 it is the complete native128B registry command.
All views are bounded by the actual current component workspace. SQL selects
root6; the eventual published profile selects root1. Native registry IMPORT
relocates all seven native Graph nodes, ordered edges and full scalar pool;
the component checks the actual translated right-hand content and event.

## Pending namespace request, 16 words at SV_NS_REQUEST

0 HIAWNP01; 1 operation (1 put, 2 fixed SQL); 2 invocation; 3 call;
4 live Store authority; 5 component lease; 6 action id; 7 kind owner;
8 kind offset; 9 kind bytes; 10 wire offset; 11 wire bytes;
12 Graph offset; 13 Graph bytes; 14 selected root; 15 SQL operation id.

For put, kind owner2 denotes this component workspace; wire/kind are exact
views, metadata is the precise omitted/None initializer call. Graph and SQL
fields are zero. For SQL, kind/wire fields are zero, root6 is the ordered native
three-bind list and SQL id is the source-verified5. The Graph is a value view,
not a storage capability. The complete returned result includes an exact copy
of these128 request bytes.

## Pending namespace result

A 256-byte fixed header is followed by the result payload. The first16 words:
0 HIAWNR01; 1 operation1/2; 2 invocation; 3 call; 4 Store authority;
5 component lease; 6 action id; 7 status0success/1exception;
8 result reference handle; 9 result current Graph lease; 10 result Graph extent;
11 error lease; 12 error bytes; 13 actual namespace call generation;
14 actual namespace action generation; 15 complete result extent.
The next128 bytes are the exact original HIAWNP01 request.

Call/action generations must be nonzero, but are correlation only. The future
actual namespace issuer must supply their real generations; txseq alone is
insufficient and a clean COMMIT may retire prior leases.

Put success: trailing actual BORROW256 + config64, total576 bytes. The first
buffer is the same actual current registry Graph containing the issued ref.
Registry sequence/command must advance, old handles remain valid, full source
shape is checked, and the exact returned reference is retained.
SQL success: no trailing bytes, result fields and error fields zero, total256.
Exception: result fields zero, nonzero error lease, exact trailing opaque error
bytes; no exception-class or message reinterpretation occurs. The full result
is frozen across own GROW. Error payloads have no new overall size quota.

The command prefix for this result is outside the256-byte namespace frame:
actual return256, role3put or4SQL, actual extent=full result bytes; both aux zero.

## Bounds and publication

The first wire is copied only after complete GraphWire validation. The second
reference wire is subject to its own original8MiB gate. Component allocation is
derived from actual sizes; there is no new aggregate Graph or command quota.
The temporary profile/bind Graph has seven nodes, seven edges, and a pool of
8 + identifier bytes + sha scalar payload bytes + reference wire bytes.
Its exact extent is568+pool. Scalar kind, integer sign and binary64 bits remain
unchanged. Key order is id then sha256; SQL argument order is exact.

Namespace exceptions can grow a full256B HIAWIR wrapper plus the original
payload and are forwarded once. GROW cannot repeat put or SQL. Final success
is HIAWIR kind2 for json, or kind9(profilehandle, originalrefhandle) for profile.
An actual namespace error after put preserves its effects; this component does
not roll them back, commit them, or retry them.

## Qualification plan

Fresh exact f50 B30e09 compilation keeps10CPU/20wall/256MiB. Actual groups keep
90CPU/180wall/1GiB. Independent reference methods run before native intervals.
The tests will disable old Store.json/profile/wire during actual routing,
predeclare foreign namespace results, preserve full source/image receipts,
canaries, before/after inputs and every native entry, and compare all wire,
ordered SQL binds, returned values, first errors and initializer continuation.
Protocol controls include poisoned replay, cross-request/cross-role frames,
full namespace request correlation, actual registry relocation, both distinct
wire sessions, one-short own GROW and no duplicated namespace operation.
PhysicalStore and ordinaryWorker stay OPEN until the actual namespace and fixed
ordinary executor are joined and independently exercised.
