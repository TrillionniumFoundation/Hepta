# Complete HIA outer lowering owner candidate

This isolated candidate follows the completed constructor development panel.
It does not change the frozen constructor, five function kernels or task-helper
kernel. No current-source cold/default/whole-stack qualification is implied.

## Complete ownership

HIA controls source-function order, helper append order, the final Core
function/block inventory gate, primitive scalar export eligibility, ASCII
export sorting and schema/module/program-envelope construction. All source
functions run before the final inventory check. A large completed function
does not create an earlier 8 MiB refusal; a later function error retains its
original priority. Public primitive verification remains independent.

The ordinary contract is `verify -> detached constructor -> one lower`.
Arbitrary mutation of private owner state or untracked calls before lowering
do not silently become another admitted entry point. The HIA initializer
requires the ordinary fresh counters/helper inventories and fails closed when
they are absent. Repeated private lower sessions require a separately designed
issued-object history protocol, not loss of prior helpers.

## Opaque complete Core objects

The existing native function and helper owners already return complete Core
objects. Re-encoding those potentially huge objects into a fixed-size input
packet is unnecessary and can change error order. The bridge instead retains
them under opaque identities issued by the new HIA owner. The final HIA IR
contains the exact ordered function/helper references. The generic token
decoder only substitutes the issued objects; it interprets no semantic plan.

Opaque references use a disjoint high integer range in the generic source
reference namespace. Ordinary packet offsets remain below 64 MiB. HIA issues
each identity once and requires an exact acknowledgement before continuing.
The bridge cannot replace an issued object or bind an unrelated request.

## Borrowed native metadata, without changing existing kernels

The new HIA owner reads the existing function workspace only while its same
session lock is held. It checks the frozen function workspace magic, phase,
input/source identity and selected function index. A completed function must
have phase 2000, completed object stream, no semantic error, no pending typed
request, and its final-state publication flag at `S+728 == 1`. The complete
blocks IR remains at `S+392`; HIA reads its list arity. The per-function list
of successful helper request identities remains at `S+720`.

Before a real helper call, a per-session proxy lends that same function
workspace to HIA. HIA requires phase 212, pending service kind 6, and a fresh
request identity; it records the exact starting serial and issues one helper
workspace lease. After the real helper image returns, HIA reads the borrowed
2 MiB helper workspace. `S+40` is the actual native block count used by its
renderer, `S+56` its first generated name, `S+8` its error, and `S` its final
serial. A failure creates no Core-object identity. A success creates one,
then requires binding acknowledgement after the original helper bridge has
decoded and validated its full result.

Revision 2 adds a separate phase 22 after reading the workspace. The bridge
forwards the exact 64-byte output header, actual returned extent and actual
output capacity. HIA compares the magic, exact error, final serial, first name,
payload extent and all reserved fields against the borrowed workspace before
it issues either a successful object identity or a semantic refusal. The
original helper bridge still validates the complete payload and input readback
before the successful object acknowledgement. The five function kernels and
the helper kernel retain their original bytes and protocols.

The function completion observer compares its native successful-helper list
with exactly those observed in that function's leases. Cached helpers create
no new lease or append. Function/helper inventories are collected without
applying the final semantic limit early. The original function session still
mirrors serial/value slots/helper cache and append state on ordinary failures.

The proxy belongs only to the selected function session and is restored on
exit. It never globally patches a cached helper image. Host code does not read
workspace offsets to count blocks or decide a semantic branch. It forwards
borrowed buffers and maps native-issued handles. Every borrow has strict
phase, source/ABI, session and one-use correlation.

## Separate transport and renderer

Use two new source-bound HIA images: the complete outer state machine and its
generic renderer. The initial packet contains the admitted document, native
type registry, existing counters and helper inventories. Public inputs bound
it below the existing 64 MiB source region. The outer workspace can use an
80 MiB allocation: it stores at most 1024 source-function identities, 720
helper identities, sorted export pointers and small request/IR nodes, never
expanded Core function bodies.

The primitive scalar predicate reads issued native descriptors: primitive
kind and the first twelve primitive identities (including bool and unit,
excluding owner/borrow/chain resources). Schema mapping is exactly composite
v1 -> primitive v6, v2/v3 -> v7, v4 -> v8. These decisions stay in HIA.

All malformed frames, borrowed-workspace mismatches, unknown/replayed leases,
unissued object acknowledgements and changed source/image bytes refuse. The
original compiler child limits and bootstrap grammar limits remain unchanged.
Both native and bridge protocol refusals are permanent for that invocation.
Owned buffers are released on normal completion, refusal and partial buffer
allocation failure. Public cleanup of the committed function/type sessions is
a separate integration requirement; these temporary owners do not discard
private elaborator partial state.
An unpublished constructor type session closes if transport fails before its
identity has been transferred to the owner. The outer bridge also drops its
borrowed function-workspace reference on exit and half-initialization failure,
so holding its exception cannot defeat the public session close operation.

## Recorded development revisions

The exact stage2/r1 sources, B3 compile inputs/images/receipts and two successful
smoke cases were preserved before changes. Its first complete six-group run
made 21 exact old/new comparisons, but two later-error fixtures raised an
authoring `IndexError` before reaching the tested owner; that run is not a
complete pass. An actual helper-image fault control showed that changing only
the output header serial by one could be accepted by r1. A separate transport
probe showed a valid frame could follow an earlier bridge refusal. Revision 2
closes those two protocol gaps and fixes the authoring fixtures, without
relabeling the original evidence. A controlled second-allocation failure also
identified the half-constructed buffer lifetime case; the probe used a small
buffer stand-in and made no large-RSS claim.
Separate actual-image controls subsequently confirmed retained unpublished
type buffers after a corrupted post-init frame, and a borrowed function buffer
after a public late-function rejection followed by explicit session close.
Their original snapshots and held-error results precede the final lifecycle
fix; the isolated baseline's old public wrapper was not mislabeled as already
containing the later v63 cleanup integration.

## Required evidence

Compare full program Core/errors and mutable owner state against retained
lowering, with the same native constructor/function/type/helper dependencies.
Poison retained lower and all older semantic methods on the selected path.
Exercise ordinary v1--v4/legacy programs, all five task helpers, cached helpers,
export ordering and exclusion, empty-width nominal returns, late errors after
large completed functions, final function/block limits, every lease/handle
refusal and source/input readback. Run actual public Core execution and a real
installed wheel before claiming the owner is complete. No old owner is removed
by this candidate.
