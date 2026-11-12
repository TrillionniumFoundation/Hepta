# Native x86-64 Code composition

## Boundary

This candidate composes the three explicitly selected HIA owners for the existing
mutable `Code` object: 37 machine-byte commands, six state operations, and 41
instruction operations. It retains the original `Code` implementation and its
complete immutable reference fixture. Ordinary unselected calls and subclasses
keep their existing route. A selected complete route refuses missing required
owners; it does not fall back to a hosted operand, state, or instruction policy.

This is a Code component. `_Function`, `_Emitter`, frame layout, machine-plan
selection, ELF construction, system linking, and the rest of the general backend
are separate owners. This document does not claim whole-backend, whole-product,
or every possible Python introspection equivalence. The default route and legacy
deletion decision remain unchanged.

## Explicit selection and custody

The selectors are:

| Owner | Selector | Checked HIA source |
| --- | --- | --- |
| Byte encoding | `HEPTA_HIA_MACHINE_ENCODING_MANIFEST` | `examples/hia_bootstrap/machine_encoding.hiaasm` |
| State | `HEPTA_HIA_MACHINE_STATE_MANIFEST` | `examples/hia_bootstrap/machine_state.hiaasm` |
| Instructions | `HEPTA_HIA_MACHINE_INSTRUCTIONS_MANIFEST` | `examples/hia_bootstrap/machine_instructions.hiaasm` |

State requires byte encoding; instructions require both state and encoding.
The three standalone builders admit a completed matching-source cold report
before creating their candidate output. Explicit development fixtures use their
own manifest or bundle variables and refuse simultaneous cold and development
inputs. A retained compiler is a development input, not current-source cold
qualification.

The mapped image exposes read-only `admitted_source_sha256`. Its loader binds the
already admitted source digest to the executable mapping. Binding a different
digest is refused. Existing pinned-image hooks and JSON diagnostic behavior are
preserved. The backend implementation identity includes the added owners and
their selected image/source identities, and still includes the existing
`checker_digest()`.

`native_encoding_scope` pins all three owners, including explicit unselection.
Restoration encloses each actual ContextVar publication, so loss of a returned
token cannot leave a partially selected context. The original backend body is
inside this scope; it has not been moved into an alternate semantic emitter.

## HIA policy and foreign representation

HIA decides operand admission, instruction choice, byte construction, branch and
relocation ordering, label/fixup validation, mutable-state effects, and the order
of requested primitive observations. The bridges perform the particular foreign
operation requested by the machine: Python object lookup, call, equality, truth,
iteration, arithmetic, assignment, bytes boxing, or the selected byte encoder.

The public objects remain the real `data`, `labels`, `fixups`, `relocations`,
and option objects. There is no duplicate host-side labels map or precomputed
instruction plan. A complete selected operation cannot use the retained Python
Code methods as a semantic fallback.

Each private handle is one owning operand slot, not an interned object identity.
Two slots may own the same object. HIA supplies before/after release actions at
the original observation boundaries; the bridge empties a slot before decrement
can run a foreign destructor. Handles are recycled only after release. Ignored
foreign call results are released at their original discarded-result point.
Reentrant public Code calls from these destructors use independent sessions.

The fixed workspace is 2,048 bytes; requests and acknowledgements are 80 bytes
and the result is an eight-byte handle. Each request has at most 16 before and
16 after release slots. Those capacities describe the fixed primitive request
shape. They impose no new count or byte limit on the user's Code buffers,
labels, fixups, relocation inventories, or Python integers. The original Code
limits remain in the HIA policy.

HIA also selects opaque module-constant slots for the original constant emitted
byte objects. The bridge keeps the actual HIA-produced bytes in those slots,
just as a code object retains its constants. It does not choose instructions or
supply their bytes. Dynamic byte sequences are not interned. Public Python call
wrappers retain the original argument signatures and `Code.method` diagnostic
names.

## One-shot private continuation

A session binds each machine-issued request to the complete workspace bytes,
output bytes, and exact acknowledgement packet. Before any foreign action,
including reference release, it checks this binding and consumes the issued
permission. Reply publication and acknowledgement state are inside the abort
boundary. A propagated BaseException makes the captured session terminal.

A terminal value is likewise tied to the actual issued frame and can be consumed
once. Explicit malformed or unacknowledged packets are retained only for
diagnostic ABI refusal controls; they cannot publish a foreign-action
permission. These controls establish private transport correctness. They are
not a sandbox against an adversary able to modify arbitrary process memory.

Successful calls release their private owning slots. On a foreign exception, a fixed catcher first exits its Python exception
handler. HIA-authorized temporary operand slots are then released with the
caller's original handled-exception context active. A fixed HIA-emitted,
held-GIL mechanism calls the public CPython `Py_IncRef` and
`PyErr_SetRaisedException` APIs to deliver the exact captured exception. This
avoids Python generator conversion of `StopIteration`. The temporary error
local is cleared during propagation; real traceback-local objects remain under
the existing exception's custody. This interpreter mechanism is an explicit
foreign dependency, admitted for CPython 3.12+ on Linux x86-64 LP64, with actual
version-specific qualification still required.

## Regression controls and original observations

The three original component modules retain all 33 methods. The original
instruction caller qualifier retains all 51 tests in its five caller modules.
Their fixtures and original semantic assertions remain present. The wheel
controls include all five actual resource groups and run installed code with
isolated imports and no authoring tools.

The added `tests.test_hia_machine_code_composition` module contains two source
controls and nine actual-image methods. It checks:

- five concrete temporary-reference and destructor/reentry differences against
  the complete immutable original Code fixture;
- three alias cases where foreign equality/getattr/call return an operand
  object already owned elsewhere;
- constant byte identity, shared branch/call zero constants, and independent
  dynamic conditional-branch bytes;
- eight original public Python parameter-binding errors;
- alteration of an actual issued GETATTR frame into a different effect;
- KeyboardInterrupt at the actual acknowledgement STORE_ATTR, retaining the
  original exception and refusing captured-session replay;
- interruption after each of the three actual ContextVar set calls, restoring
  all prior owner values;
- temporary operand destruction after a real builtin-call refusal, with no
  outer handler and with a retained outer exception;
- delivery of the original foreign `StopIteration`, including its identity,
  explicit cause, suppression flag, and notes.

The original developmental failures are kept separately: five lifetime
differences, the accepted mutated private request, an actual acknowledgement
store interruption that resumed effects, three lost ContextVar publication
results, and the later constant-identity and diagnostic-name differences. A subsequent R3 actual control found that
retirement in a Python `finally` exposed the new `TypeError` rather than the
original outer handled-exception state to a temporary object's destructor.
That original observation remains separate from the R3 completed gates. The
R4 delivery integration is a new revision and must receive its own actual
controls and complete retained caller gate. The
initial unarmed tracing attempt is recorded as a harness failure, not evidence
that the interruption control passed.

Predecessor R2 development observations included all 33 component methods and
all 51 original callers passing. They do not qualify a later source revision.
Final source and image digests, complete test IDs, logs, installed-wheel
observations, and before/after input identities belong to the corresponding
external gate report. Current-source cold and complete product qualification
must be run after integration; no old report is inherited by this document.
