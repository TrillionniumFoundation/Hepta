# Complete outer owner: finite transport and arena bounds

These bounds apply to the ordinary public path: the existing structural
verifier has detached a bounded source tree, the complete constructor has
admitted it, and a fresh elaborator invokes outer lowering once. They do not
grant execution authority or introduce a new source-language quota. The final
primitive verifier retains its own full admission.

Let `N <= 262144` be the existing source-node bound, `B <= 8388608` the existing
source JSON byte bound, and `F <= 1024` the admitted source-function count.
Native types issue at most 144 identities; the five task-helper operations are
cached by issued nominal type and operation, so at most `H <= 720` successful
helpers can be created. A failed helper creates no object handle. Every source
occurrence is charged independently, including repeated names and references.

## Initial packet

The constructor's independent transport proof gives `40*N + B` for the complete
document. The outer packet additionally carries an ordered registry with
function names, parameter names/type IDs and return type IDs. It carries no
expanded primitive slots or complete Core functions.

An encoded registry function row has at most `88 + name_bytes` fixed framing;
a parameter row at most `59 + name_bytes`; and a return identity at most 19
bytes, since a decimal issued identity has at most three digits. Rounding these
to 128 bytes per function occurrence, 80 per parameter occurrence and 32 per
return occurrence is conservative. Those are disjoint original source nodes.
Their copied name bytes are already charged within `B`. The registry outer
list adds 24 bytes. Thus `registry <= 128*N + B + 24`.

The six-item packet's surrounding list, zero serial, zero value count and two
empty helper lists contribute 106 bytes. The complete bound is therefore
`168*N + 2*B + 130 = 60817538` bytes, below the existing 64 MiB source region
(`67108864`). This deliberately loose bound includes every repeated parameter
or return; it does not assume shared strings or memoized admission.

The initial HIA gate rejects non-fresh private owner histories. That private
restriction is explicit; the ordinary public constructor produces exactly the
fresh counters and empty helper inventories required here.

## Native arena

The 80 MiB workspace reserves the first 64 MiB plus 64 KiB for source and fixed
state, leaving 16711680 bytes for arena allocations. Complete Core objects are
held as opaque references outside this arena; HIA chooses their identities and
the generic decoder substitutes only those issued objects.

The source allocates a 17280-byte helper lease table, an `8*F` export pointer
vector, two 32-byte lists, at most 160 bytes per function request, and 64 bytes
per completed function reference. Exports add at most `64*F` bytes. A successful
helper uses a 64-byte reference/list segment and a further 32-byte segment when
appended to the final function list. The four-field envelope, short literal
strings, schema choice and fixed lists fit within 1024 bytes. Header validation
uses fixed state fields and allocates no arena nodes.

The rounded charge `320*F + 128*H + 32768 <= 452608` bytes is therefore above all
actual arena allocations and far below the available 16711680 bytes. Failed
native continuations stop the same finite loops and allocate no unbounded retry
history. The stream stack sees only the small envelope, lists and opaque leaf
references, not the depths of expanded Core objects.

## Late gates and large outputs

HIA records each completed function's actual native block-list count, observes
every helper's real metadata and exact output header, and waits for all source
functions to complete. Only then does it apply the original 1024-function and
4096-block final inventory gates. A later function error retains priority over
an earlier function's excessive generated block count or a huge completed Core
object. No intermediate 8 MiB limit is introduced.

Successful complete Core objects are not serialized back through this fixed
input packet. The final token stream contains their opaque identities in HIA's
chosen order. The existing primitive verifier performs the final expanded
program byte/node/type/control-flow admission after lowering finishes.

These are source/arena bounds, not measured process RSS or a cold qualification.
The borrowed 192 MiB function, 128 MiB type and 2 MiB helper buffers remain owned
by their existing sessions. The temporary 80 MiB outer arena and 192 MiB
constructor arena release on completion, refusal and partial allocation
failure; the ordinary public boundary separately closes committed sessions.
