# Native function frame and staging plan

## Scope and authority

This development leaf implements the complete deterministic per-function layout
performed by exact 0ef hepta/hia_program_native.py::_Function.__init__, together
with entry-parameter, edge, returning-call and return staging records. The
original file is Git blob
1d0e0344f8300b11b5dd505cbea655170aba5be1, 46,917 bytes, SHA256
bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c.

Its source is a private immutable Graph containing
[admitted_core_document, checked_machine_plan_or_null]. A fixed native caller
must retain the actual Core and machine-plan issuers and their custody. A graph
header, lease number or successful frame-planner call is not Core admission,
machine-plan validation, an arbitrary graph authentication mechanism, or
authorization to execute generated code.

The planner implements allocation order, type widths, canonical stack slots,
block and value lookup, checked register realization, staging maxima, saved
callee registers, frame alignment, the original 64 KiB frame rejection and its
complete original message, the trap label and parent serial update. It computes
the complete source/destination word order needed by the later emitter. It does
not emit machine code, select an optimization, validate a new plan, enforce
exports, link objects, or publish an installed backend.

All functions and blocks in the original Core domain remain usable. In
particular, the input has no 128-function restriction; that bound belongs to the
separately compiled implementation image. Original Core admission still enforces
its own 1,024 functions, 4,096 blocks per function, byte, node and depth policies.

## Three-buffer ABI

The generated entry is f0(readbuf, mutbuf, mutbuf)->u32, with its entire second
operand borrowed read-only to an internal readbuf. Actual invocation uses
physically read-only first and second mappings and private writable workspace.

| Operand | Content | Lifetime |
| --- | --- | --- |
| First | Complete private Graph of the actual Core and checked plan | Same immutable bytes throughout GROW and downstream plan use |
| Second | Exact 96-byte HIAPFC01 command | Same immutable bytes throughout GROW |
| Third | Workspace, at least 4,096 bytes | Private to this call; no concurrent mutation |

The Graph uses the existing HIAGRF01 64-byte header, 64-byte nodes, one-based node
identifiers, u64 edges and absolute scalar offsets. Plain null, bool, minimal
integer magnitude, binary64, surrogatepass UTF-8 string, list and ordered dict
nodes retain their original kind. Only the actual fields needed by this leaf are
read. Zero integer payloads still use a valid scalar-pool cursor. The kernel is
not a replacement general Graph validator; the issuer must already own the
complete admitted document and checked plan.

The command is twelve little-endian u64 words:

| Word | Meaning |
| --- | --- |
| 0 | ASCII HIAPFC01 |
| 1 | Version 1 |
| 2 | Nonzero private Graph lease; must match Graph word 1 |
| 3 | Nonzero logical request |
| 4 | Original document function index, not render-order index |
| 5 | Parent label serial before constructing this function |
| 6 | Graph root identifier; must equal Graph word 3 |
| 7–11 | Zero |

The workspace is a pure recomputation target. A retry can discard its old
contents and allocate exactly the required extent. GROW does not commit a
function or consume a parent serial. The fixed caller must retry with the same
actual immutable inputs; matching headers alone do not establish this identity.
A distinct legitimately issued graph with the same numeric header is a distinct
input. The pure leaf intentionally does not claim to detect such an issuer
replacement.

No 128-operations-per-block restriction is introduced. The local generated
authoring partitions some constant writes into helpers, but no failure was
observed for the earlier unsplit 237-operation block. Actual B3 acceptance and the
original compiler's function/value/block/parameter and total instruction limits
remain authoritative.

## Result event

For workspace shorter than 4,096 bytes, return FD (0xfffffffd) without an event
or state write. For adequate workspace, the first 128 bytes are sixteen
little-endian u64 words:

| Word | Meaning |
| --- | --- |
| 0–1 | HIAPFE01, version 1 |
| 2 | Action: 0 success, 1 GROW, 2 original semantic rejection, 3 private ABI rejection |
| 3–5 | Graph lease, logical request, original function index |
| 6 | Semantic error ID: 1 for original frame-size rejection, otherwise zero |
| 7 | Required workspace extent |
| 8–9 | Successful plan offset 4,096 and full plan bytes; zero otherwise |
| 10 | Calculated aligned frame bytes, if calculated |
| 11 | Parent label serial after success, or unchanged input serial |
| 12–13 | Complete semantic UTF-8 error offset and length; empty otherwise |
| 14 | Graph root identifier |
| 15 | First private ABI rejection reason; zero for other actions |

Success and semantic rejection return 128. GROW returns FE (0xfffffffe).
Private ABI rejection returns FD. A fixed driver must reject/discard the lease on
FD and must not consume stale output after a short workspace. Diagnostics are
numeric private failure points, not new public language exceptions.

The only public semantic error produced here is the exact original:

E_HIA_PROGRAM_LIMIT: function stack frame exceeds 64 KiB: <function_name>

All definitions and staging areas, including saved registers, contribute before
this comparison. The original constructor does not increment its parent label
serial on this error, and neither does this leaf. A u64 serial overflow is a
private ABI rejection; admitted finite emitter executions never approach it.

## Plan header and borrowed views

A successful plan begins at workspace offset 4,096. Its 512-byte header is 64
u64 words. Every nonzero record/view offset below is absolute within the current
workspace. Source identifiers refer to the unchanged first Graph. No raw
pointer, workspace offset or Graph identifier may be reused across a different
workspace/Graph lease.

| Words | Meaning |
| --- | --- |
| 0–4 | HIAPFN01, version 1, lease, request, original function index |
| 5–6 | Actual function node, function-name node |
| 7–11 | Aligned frame, unaligned cursor, input serial, next serial, scalar-select mode (0 branch / 1 cmov_scalar) |
| 12–17 | Allocation-record, block, call, edge, return, move counts |
| 18–23 | Corresponding six record-array offsets |
| 24–27 | Private value-table offset/capacity and block-table offset/capacity |
| 28–29 | Render-order u64 array and entry block record |
| 30–32 | Maximum edge, call-argument and call-result word counts |
| 33–36 | Edge, call, result and four-word temporary stack offsets, encoded modulo 2^64 |
| 37–38 | Saved-register count and 16-byte record array |
| 39–40 | Entry-parameter moves and count |
| 41–42 | Complete trap-label ASCII span |
| 43–46 | Full plan bytes, actual source Graph bytes, source root, full function count |
| 47–48 | Distinct value-name count and checked register-map count |
| 49–63 | Zero |

Negative stack offsets are two's-complement i64. Scalar widths are one word;
buffer, readbuf and mutbuf are two. Chain and unit retain their original
one-word representation. Every original definition consumes stack space in
original block/operation order, even if its selected register avoids a spill.
The lookup table preserves the original dictionary's last-definition behavior;
that is a private constructor pressure control, not permission to bypass Core
uniqueness rules.

### Record layouts

* Value (64 bytes, eight words): name node, type node, width, negative stack
  offset, register code, original definition node, original block ordinal,
  allocation ordinal.
* Block (64 bytes): original block node, name node, params node, operations node,
  terminator node, parameter words, original block ordinal, zero.
* Call (96 bytes): block ordinal, operation ordinal, original instruction node,
  argument list node, output list node, argument words, result words,
  argument-move offset, result-move offset, callee-name node, zero, zero.
* Edge (96 bytes): block ordinal, side (0 jump / 1 then / 2 else), original edge
  node, target-name node, argument-list node, word count, source-move offset,
  destination-move offset, target block record, zero, zero, zero.
* Return (64 bytes): block ordinal, original terminator node, value-list node,
  word count, move offset, zero, zero, zero.
* Move (32 bytes): actual value-record offset, word index, final canonical stack
  offset plus word displacement, selected register code.
* Saved register (16 bytes): register code, negative canonical stack slot.

Register codes are 0 stack, 1 rbx, 2 r12, 3 r13, 4 r14, 5 r15, 6 r8, 7 r9.
The saved-register list always follows rbx/r12/r13/r14/r15 order. Checked leaf
r8/r9 values are not saved. Multiword values cannot be registered by the checked
plan issuer. All canonical slots remain reserved regardless of register use.

Edge source moves must all complete into the disjoint edge area before any
destination move. Calls first stage all arguments, then point rdi/rsi to call and
result areas, call the original callee, then consume all result words. Returns
load the saved output pointer, publish value words in original order, restore
saved registers, leave and return. Entry parameters are staged in original
parameter/word order. These records do not authorize a fixed mechanical host to
perform semantic lowering; the subsequent HIA emitter owns these operations and
their calls to the actual x64 encoder.

## Development evidence and limits

The first local build uses the unchanged 669,556-byte 35ee B3 compiler and exact
original 0ef disposable child under 10 CPU seconds / 20 wall seconds / 256 MiB.
The child was restored at an independent development path, with its exact bytes
and SHA pinned; no shared reference file was modified. Reference imports in the
builder compile the once-captured source bytes, with complete originals and
before/after source checks retained.

The generated image is development-only. The original _Function class and
needed original methods are used only as independent test oracles. Native inputs
are the original document/plan Graph; Python does not precompute native slots,
staging records, frames or code. Complete before/after mappings, readonly
inputs, boundary canaries, return values, original error text and native clocks
are stored using lossless 4 KiB CAS pages with full reconstruction and final
decompression/hash readback.

The corpus separates actual admitted Core cases from private constructor
pressure and malformed private protocol controls. It includes all sixteen
types, original 1,024-function and 4,096-block inventories, changed render order,
edge permutations, complete mixed/multiword call and return staging,
callee-saved and leaf registers, exact 64 KiB boundaries caused independently by
definitions, edge staging, call staging and saved registers, parent serials,
short extents and GROW. Each process retains 90 CPU / 180 wall / 1 GiB limits.

The first smoke run's reference fixture omitted the mandatory explicit trap
code. It failed after one completed case/two native entries, before that invalid
fixture reached the leaf. The complete failure and exact test source remain
separate; the fixture correction does not change production source. This work
does not claim whole emitter, plan validator, native object/shared-library
build, installed entry or cold qualification closure.
