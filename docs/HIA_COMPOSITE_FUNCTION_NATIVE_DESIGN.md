# Complete native composite function owner

This is an explicitly selected development candidate for the complete
`_Elaborator.function` owner. It is not a cold-qualified release, an all-input
equivalence proof, or whole-language/whole-stack closure. The constructor and
outer `lower` still own their original hosted semantics. No old owner is removed.

This document was reconstructed after the workspace restart. Its text is a new
revision. The five semantic kernel sources/images and the bridge, codec,
diagnostics, authoring bodies, ordinary wrapper, and terminator tests were
recovered byte for byte from the independently frozen terminator evidence
archive. The restored builder also matches its recorded pre-restart SHA.

## Scope and ownership

The retained function body contains 441 lines, 392 Python AST statements, 85
conditionals, 23 loops and 56 explicit rejection sites. Its normalized original
body is 27,110 bytes with SHA-256
`b7336fb540911f220fef676d082c1a365d4712703ba5f08faeff3ac985913972`.
Only its method name changes to `_reference_function`; the default path still
uses that body. Selecting `HEPTA_HIA_COMPOSITE_FUNCTIONS_MANIFEST` requires the
complete five-image bundle plus source-matching native types and task helpers.
A selected native failure never falls back to hosted lowering.

HIA owns both passes, declaration order, block/SSA maps, value consumption and
external-loan flags, exact nominal type-ID comparisons, every record/enum/task/
call/primitive operation, every terminator and match arm, generated names,
value-slot accounting, helper-cache decisions, and the complete returned Core
function. The adapter transports exact trees, forwards fixed native service
requests, materializes generic output tokens and mirrors HIA-issued state. It
does not inspect source instructions to plan or compute their lowering.

The preserved entry contract is the ordinary verifier's bounded detached
document and complete `lower()` path. The private `session.function(fn)` accepts
only unchanged members of that document: it compares the full typed packet with
the stored snapshot before sending native NEXT. A replacement object or mutation
poisons the session. This custody check does not interpret types, SSA or CFG.
Arbitrary private replacement dictionaries are therefore explicitly outside the
compatibility claim. Direct private float-valued inputs are also outside it;
the public snapshot gate rejects floats before this owner is reached.

## Preserved order and state

1. Each block is admitted for inventory, shape, name and duplicate status before
   its parameters. Widths are reserved as a complete sum before flat names are
   generated. Instructions then receive their original shape/profile/argument/
   output-parameter checks.
2. SSA names enter the global definition set only after that block's complete
   first pass. A duplicate earlier in a block cannot hide a later type error.
   All source blocks finish before entry/signature equality is checked.
3. Pass two looks up all arguments before admitting the declared outputs.
   Repeated `parameters` and `resolve` calls occur in their original order,
   including the second primitive resolution in enum.tag and task.state.
4. `reserve_values` updates the entire sum before testing 32,768. `fresh` tests
   8,192 before incrementing. Partial counters remain observable on refusal.
5. Match carries preserve environment insertion order, scalar-name alias
   deduplication and the first occurrence's type. Case validation precedes
   exhaustiveness, then variants lower in declaration order with original
   edge/arm/drop/constant/decision/fresh sequencing.
6. Helper-cache hits precede task-protocol checks. On a miss, the helper name
   enters the cache after its first successful fresh allocation even if later
   generation fails. Only a successful complete helper is appended.
7. Every source function finishes before outer expanded inventories and final
   primitive Core admission. The function owner does not move those gates.

The session persists counters and numeric helper-cache identities across source
functions. Per-function maps/IR are reset only after the complete stream and
final state report. Types are borrowed read-only under the native types session
lock; the function kernel cannot write the descriptor state. The same-session
descriptor identity is checked at every bridge boundary.

## Typed continuations and generic output

The only semantic services are parameters, resolution, partial-record creation,
task-protocol checking and complete task-helper generation. HIA emits each
request with a monotonic sequence, fixed kind and resume phase. The adapter
returns actual native results. Malformed framing, kind/sequence mismatch,
replay, unissued IDs and invalid transport state poison the session; source
semantic refusals preserve their original partial state.

The private control frame is `HIAFAD01`; first-pass responses are `HIAFRS01`,
later typed responses are `HIAFLR01`. Native function selection uses `HIAFNX01`,
the final metadata request/report use `HIAFMQ01`/`HIAFMD01`, and generic stream
chunks use `HIAFNC01`. Generic tokens express only source references, strings,
integers, booleans, nulls, lists and dictionaries. The host never receives an
instruction-generation plan. The decoder permanently refuses after its first
protocol error.

Compact native arrays use views over existing primitive vectors. The renderer
expands those views into 64 KiB chunks without an eventual output-size quota.
Detached source references preserve exact arbitrary admitted attribute values.
Repeated generated strings share a bounded allocation cache; failure to cache
does not reject a value or change language admission.

### Why an early output quota would be incorrect

A 14,333-byte nominal document with a 512-slot scalar record parameter and 1,000
repeated return references produces an **11,194,841-byte** complete function.
Both expanded return lists have 512,000 slots, while fresh and value-slot counts
are only 512. Alone, final primitive Core admission rejects with
`E_HIA_LIMIT: caller-owned tree exceeds queued-node budget`. With a later source
function whose block inventory is invalid, the earlier result must be
`E_HIA_CFG: invalid nominal block inventory` from that later function.

The actual native bundle and the retained whole hosted function produced the
same large object and the same later-error precedence. No 8 MiB/262,144-node
per-function output gate has been added.

## Unchanged compiler limits and exact artifacts

All five images were actually compiled with the retained B3 native compiler at
the original 10-second CPU, 20-second wall and 256 MiB compiler-child bounds.
The original 1 MiB source/output/workspace, 128 functions, 1,536 total blocks,
8,192 instructions, 256 blocks per function, 2,048 SSA values per function and
16 function/block parameters remain unchanged. The largest individual function
has 181 blocks.

| Kernel | Revision | Functions | Blocks | Instructions | Source bytes | Image bytes |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| admit | r3 | 57 | 791 | 3003 | 178792 | 243813 |
| records | r3 | 103 | 1035 | 3923 | 233291 | 326089 |
| advanced | r3 | 91 | 910 | 3354 | 202332 | 283900 |
| terms | r1 | 107 | 945 | 3727 | 221724 | 310584 |
| render | r2 | 8 | 71 | 402 | 21063 | 28278 |

The 507-byte complete bundle has SHA-256
`e53401a5ac973993c3e97ceb71ac1843f4668f866f075d4b904431b4cc5eb819`.
It binds native types source
`8fec677e2a7be2292241a4ecf51c0e4c807a63f945928dd3c8eb03a79a42d749`
and task-helper source
`1f0a38ab1235de3ffc35ca3ca01ac327bbea3ceadac99a995d3b550b630790cd`.
Component manifests bind each exact source/image/compiler hash. Development
images do not acquire cold qualification from this metadata.

The formal builder `tools/build_hia_composite_functions.py` admits all five
sources and both dependency sources against the current full cold contract
before creating output. Each component passes the existing strict candidate
builder. Compiler, report, source, manifest and image bytes are checked again
before the complete bundle is published. It does not activate production.
Development manifests and a cold test report are mutually exclusive.

## Resource bounds

Let `N <= 262144` be the original public structural node count, excluding
dictionary keys, and `B <= 8388608` the admitted canonical JSON byte length.
Generic transport adds a 16-byte header to each value/key and 8 bytes to each
container. There are at most `2N-1` value/key nodes; payload is bounded by `B`.
Thus `40N+B` bounds the document transport.

The signature and origin registries have the same separate bound. Parameter
objects become `[name, ID]`, return references become IDs at most 144, and
origins become null or `[formal, offset]` with checked offsets at most 511.
Source type/annotation strings and framing pay for these scalar payloads; the
original required function fields pay for row/list framing. Absent annotations
add one payload-free null for each existing return reference.

The outer seven-element list contributes exactly 92 bytes on the public
constructor path: a 24-byte list and four 17-byte scalar nodes for zero counters,
the boolean flag and zero index. The packet is therefore at most **56,623,196
bytes**, below 64 MiB. The internal bounded counter initializer adds at most 11
bytes. Counting required function/parameter/return projection shapes gives at
most `3N+7 = 786439` raw typed nodes, below the private validator's 1,048,576.
Public depth adds one outer level and remains below its 128-level capacity.

For arena allocation let `V <= 32768` be admitted source value widths and
`F <= 8192` successful fresh names. A failed reserve updates its full observable
counter but does not allocate that rejected inventory's flat values. The
conservative static allocation accounting is:

| Allocation | Bound | Maximum bytes |
| --- | ---: | ---: |
| Source records, service framing, ordinary Core nodes and views | `256N` | 67,108,864 |
| Value vectors, parameter objects and match carries | `256V` | 8,388,608 |
| Fresh names and generated operations/blocks | `1024F` | 8,388,608 |
| Unique mapped vectors across at most 32 variants | `32*V*8` | 8,388,608 |
| Peak temporary transfer/case table | `64N+16` | 16,777,232 |
| Flat primitive-vector cache | `144*512*8` | 589,824 |
| Block and definition maps | `(8192+262144)*16` | 4,325,376 |
| One failing expected-signature vector | `8N` | 2,097,152 |
| Fixed literals/null vector/partial-construction slack | `65536` | 65,536 |
| **Total** | | **116,129,808** |

The 192 MiB workspace leaves 134,152,192 bytes after its 64 MiB input region and
64 KiB fixed state, leaving 18,022,384 bytes beyond this accounting. Zero-width
values are charged to source nodes, not to `V`. Required instruction skeletons
pay for fixed control framing; parameter, type-reference and argument nodes pay
their own records/response IDs/views. A copied partial-field name uses at most
192 bytes and corresponds to an explicit initialized-field node on a successful
operation; one failed construction is covered by fixed slack.

Independent terminator review confirmed carry allocation below `88C`, with
summed carry capacities bounded by `V`; each source case argument contributes at
most `96A` bytes of map cache/views. Repeated arguments do not multiply mapped
vectors. Transfer/case temporary tables restore their arena mark. Inactive owner
slots cannot alias under preceding consuming rules, so their generated drops
are charged to the corresponding arm's fresh carry names. Return arrays and
origin arrays retain views, without copying each expanded slot.

This is implementation resource accounting, not a machine-checked all-input
equivalence theorem. The shallow generated graph uses a 128-frame renderer
stack; a deep source object is one detached-reference token. The whole runtime
also contains separate types buffers and Python objects and is not claimed to
fit the compiler child's 256 MiB address-space limit.

## Evidence, retained failures and restart custody

The surviving independently frozen terms archive is 417,600 bytes, SHA-256
`b3e7a42225eb1f7f1fdec03d7b0b4a3ddcac5f749f23e28686d08a9c4874d859`.
Its 213 members contain 72,881,684 uncompressed bytes; extraction and every
member's readback were verified before the restart. After restart, 41 frozen
source/image/manifest members were extracted and independently read back again.
The actual semantic source/image bytes and bridge SHA remained unchanged.

The surviving terminator evidence records eight passing tests: **183 complete
function outcomes**, 40 accepts and 143 refusals, with 4,259 actual kernel
entries. Coverage includes all terminators, scalar aliases, ownership, 32 empty
variants, a 512-slot enum, repeated wide/zero-width arguments, returned origins,
fresh-budget and persistent failures, actual Core execution, and the 11.2 MiB
output/later-error witness. Original test-prefix assertion mistakes and a
subsequent exit 137 remain in that archive; they are not relabeled passes.

Before restart, the complete-owner suite was observed passing eight tests in
31.614 seconds: 23 real public/profile inputs with hosted semantic owners
disabled, installed-wheel isolation, all five source missing/changed controls,
a corrupted disposable image, absent dependencies, exact source reproduction,
private custody/poisoning, and a cold-builder refusal before artifact creation.
The raw suite log was in temporary storage and did not survive. Reconstructed
tests are a new revision and require a fresh run; the earlier observed result is
not their acceptance receipt. The 13-fixture full-Core probe and root's earlier
134-input/153-reached-function audit are likewise reported historical results,
not reconstructed raw logs. In that root audit, nine constructor diagnostic
texts differed under the existing native types policy; no function was entered
for those nine. Only 125/134 observations matched complete text. Existing types
guarantees are diagnostic category/order; new local function errors target
complete text too.

An earlier actual r1 protocol defect allowed malformed responses to be followed
by valid resumption. The full-buffer ABI and decoder poison fixes were tested
with seven passing r2 controls. Their original raw temporary evidence did not
survive the restart. An attempted r3 rerun later ended with exit 137 before the
first native workspace; a control importing no HIA code was also killed while
allocating a 192 MiB ctypes buffer. The exact killer was not established. No
quota was changed and these attempts were never counted as passes.

## Remaining acceptance work

Recover/rebuild the missing tests and integration files with explicit revision
identity; rerun the raw protocol/admission/codec gates against actual restored
images; complete the independent function/CFG mutation panel; integrate the
full source contract/profile/runner; then obtain fresh exact-source cold
qualification. The formal builder has only a negative qualification-gate result
so far. The default remains unchanged, and no constructor, outer-lower,
compiler/runtime/installation, or whole-stack closure is implied by this owner.
