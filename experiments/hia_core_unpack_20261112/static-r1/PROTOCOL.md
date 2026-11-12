# UNPACK experimental control owner, revision 1

Status: STATIC, UNEXECUTED. The author, bridge, fixed primitive image and this
protocol are an independent experiment based on exact d0e110. They neither
activate an ordinary selector nor change the admitted resource/contract list.
The existing 39 Core sources and earlier 116 observations are untouched.

## Ownership boundary

HIA chooses every normal step: obtaining an iterator; classification of an
acquisition error; n successful values and exactly one further exhaustion
probe; short/exact/long classification; the complete error format; version
specific container-size observation; tuple allocation and each transfer; and
release order. The Python adapter may transport packets, expose a raw object
fact, and execute one selected leaf. It has no complete unpack operation and
no Python iterator/cardinality loop. Its run loop only advances HIA effects.

The following are still hosted CPython mechanisms: object representation,
reference counting, iterator acquisition/one next call, allocation, exception
construction from a HIA-provided format, subtype/sequence/slot facts, and
raised-error transfer. The transaction primitive is transitional. It does not
close the Python object runtime or the other eighteen Core primitives. It is
not a new C implementation of unpack. No release/policy loop is in its bytes.

The existing outer opcode 14 has one observation permission. The later
ordinary composition must consume it once before entering this owner and
register only the final results. No intermediate item may enter Core's
invocation-long strong reference registry. The explicit composition and its
116 installed/original-caller verification are subsequent work, not claimed
by these files.

## Runtime ABI

Initial experiment profiles are CPython 3.12.14 and 3.14.4, Linux x86-64 LP64,
GIL enabled, no Py_TRACE_REFS. Other versions fail admission. The bridge
checks the common object/type prefix on builtin objects before foreign work.
Raw source/type facts use the object prefix at offset 8 and tp_name at 24.
PyType_GetSlot uses stable slot 62. C APIs are resolved by fixed symbol name;
the caller cannot supply a new C function address or arbitrary format string.

The shim frame is fourteen u64 words. Words 0..6 are the selected leaf and up
to six raw arguments; word 7 is reserved; word 8 transfers one owned raised
exception; words 9/10 pin SetRaised/GetRaised; words 11/12 are the raw result
and newly owned raised exception; word 13 is a progress marker. It saves rbx,
aligns the System V stack, sets AL=0 for integer-only variadic Format, calls
one leaf and returns with a cleared error indicator. Marker 4 proves both
result and error were saved. The companion four-byte load-word leaf reports
one selected object/type word. Neither entry has a loop or semantic branch.

Both shim and HIA entry use PYFUNCTYPE so a native transition does not release
the GIL. The error API transfers owned references without an extra synthetic
raise. Actual controls must verify ambient sys.exception(), context/cause,
exception identity, finalizer order and GIL ownership. Source reasoning is
not a substitute for those controls.

## Protocol

Magic is the little endian u64 for HIAUNP01. Input is exactly 128 bytes, output
at least 256, workspace at least 256, initially entirely zero. Words are u64.
Return 1 requests one effect; return 0 has one successful result permission;
return 2 is a private infrastructure-abort completion; 0xfffffffd refuses.

Initial input: magic, kind=0, seq=0, arity, profile, exact tuple/list/dict type
addresses, then eight zero words. Arity is 1..4. Normal ACK: magic, kind=1,
sequence, opcode, raw result, has-raised-error, then ten zero words. An ACK
must match both pending sequence and opcode. The private abort input has
kind=2, current sequence, mechanical owned-cell mask and has-error; remaining
words are zero. It does not manufacture a semantic PASS/error outcome.

Requests are magic, sequence, opcode, destination, a, b, c, nine zero words.
For FORMAT only, bytes 128..255 contain the complete HIA-authored NUL-terminated
ASCII format. Sequence cannot wrap. The terminal state rejects another step.

| Opcode | Single primitive | Result/ownership |
| --- | --- | --- |
| 1 | PyObject_GetIter | new owned iterator or raised error |
| 2 | PyIter_Next | one new owned item, exhaustion, or raised error |
| 3 | PyErr_GivenExceptionMatches | raw TypeError subtype fact |
| 4 | selected Py_TYPE word | borrowed type address |
| 5 | PyType_GetSlot(..., 62) | iterator-slot presence |
| 6 | PySequence_Check | raw sequence fact |
| 7 | selected tp_name word | borrowed name pointer |
| 8 | PyErr_Format | HIA supplies exception ID, text and arguments |
| 9 | Py_DecRef | consume exactly one HIA-selected owned cell |
| 10 | exact tuple/list/dict size | HIA selects the exact builtin API |
| 11 | PyTuple_New | new private tuple |
| 12 | PyTuple_SetItem | consume one item reference, including failure |
| 13 | py_object O_get | one new Python reference to the private tuple |
| 14 | PyErr_SetRaisedException | final one-shot error transfer; must raise |
| 15 | Py_DecRef without restored error | private abort error-cell release |

Cells: 1 is source borrowed from a strong Python reference; 2 iterator;
3..6 items; 7 excess; 8 private tuple; 9 raised exception. Cells 2..9 each own
exactly one reference when nonzero. Transfer bookkeeping consumes a cell
before a callback and reconciles the C frame even if a post-entry Python
exception occurs. Pointer identities are not reusable Core object handles.

## Required semantic sequence

Failed GetIter is rewritten only when the actual raised error matches
TypeError, actual tp_iter is null, and PySequence_Check is false, in that
short-circuit order. HIA reads tp_name only on the rewrite path. PyErr_Format
itself clears the old error before formatting, matching the original C API.

Each successful value is held privately. Early exhaustion chooses the short
ValueError. After n successes, a single extra PyIter_Next must exhaust. If it
produces a value, HIA releases that value before the length observation/error.
CPython 3.14.4 exact list/tuple/dict reports got=size only if that size exceeds
n; 3.12.14 uses the older expected-only message. Other iterator types retain
the expected-only message. No length hint or user len() is called.

On failure, release fetched values in reverse acquisition order, then the
iterator, with the raised error restored at each leaf. The caller's handled
exception is not changed by a synthetic Python except/raise. On success,
release the iterator before constructing the returned tuple; HIA transfers
items and releases its owned tuple reference after exporting a Python ref.

## Limits and explicit unclosed work

The parent Core ABI, 116 original IDs, default complete one-owner 180+3,
20-wall/10-CPU per compile, 1MiB compiler output and source/compiler caps are
unchanged. New finite controls are additional evidence, not replacements.

This source has not yet been parsed, rendered, compiled or executed. It does
not claim exact traceback frames, allocation/refcount inspection, hostile C
extensions returning non-null with a pending error, private cell/function
mutation, interpreter shutdown, arbitrary thread scheduling, or resource
failure equivalence. Python packet/ledger allocation can introduce GC and
asynchronous interruption points. These are explicit runtime boundaries,
not a reason to call the entire object runtime native.

The private abort path asks HIA to release the bridge's actual owned-cell
mask. If the native entry itself refuses/corrupts that recovery, the bridge
retains abort_failure rather than replacing it with a host release strategy.
Such paths require a resource/failure design and actual controls before any
broader release guarantee. Normal success/failure and one-shot lifecycle
must pass their real-image controls before ordinary integration.

Primary source inputs are pinned separately, particularly ceval.c unpack,
errors.c transfer/format, cfield.c O_get, bytecodes.c adaptive UNPACK, and
typeslots.h. The retained Python oracle is independent of the new adapter.
