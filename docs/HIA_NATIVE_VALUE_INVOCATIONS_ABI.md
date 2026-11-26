# Native Value invocation ABI

## Qualified scope

This component uses the single Value arena and the native source-bound code
owner to compile HIA function bodies, create real function and bound-method
objects, execute generic Value calls, propagate actual exception objects, and
retire code, continuations, temporary capabilities, and call mappings.
The corresponding exact construction and gate evidence is in
HIA_NATIVE_VALUE_INVOCATIONS_COMPONENT.json. The canonical current Value
construction is HIA_NATIVE_VALUE_RESOURCE_QUALIFICATION.json.

The component gate invokes the entry captured by the actual native sidecar
initializer. It does not install a host handler, write an entry pointer or
support mask, execute continuations in Python, or poll a production finalizer.
The enclosing public owner's new whitelist is a separate integration gate.
Custom Python protocols and arbitrary iterable dataclass construction remain
explicit follow-on work; this component does not claim them.

## Construction

HIABVP08 contains 15 roles in this exact order:

1. owner
2. core
3. import
4. export
5. capture
6. format
7. number
8. dict_iterator
9. classes
10. class_mro
11. records
12. resources
13. protocols
14. callables
15. invocations

The existing HIABVP07/14-role packer is unchanged. The new frame is 144 bytes
before its concatenated role bodies: magic at 0, count 15 at 8, fifteen lengths
at 16, and output mode at 136. Mode 1 emits a flat image; mode 0 emits the ELF
object. The constructor retains the existing 4 MiB per-role and 16 MiB text
bounds. The complete Value flat additionally remains below 4 MiB for use as
one enclosing assembly role.

The original compiler executes each of the sixteen HIA modules twice,
including the new packer. Both outputs must match. The actual HIA packer output
must match an independent reference byte for byte. The enclosing candidate
uses the actual HIA 56-role packer and linker and contains one Value image.

## Public Value calls

All requests use HIABVQ05 and the standard 128-byte Value header. Offset 8 is
the operation, 16 is reserved zero, A is the three words at 24, B at 48, and C
at 72. Tail length is at 96, argument zero at 104, and 112/120 are reserved.
Except the compile source tail, invocation requests have no tail or scalar
arguments. No request contains a function pointer or code-entry address.

| Operation | A | B | C | Tail |
|---|---|---|---|---|
| 68 | Optional actual environment, or zero triple | Optional exact string name, or zero triple for f0 | Zero | Actual canonical HIA source |
| 69 | Actual native function or method resource | Actual non-None receiver | Zero | Empty |
| 70 | Actual native function or method resource | Actual tuple, including supported real tuple subclasses | Actual dictionary, or zero for no keywords | Empty |

Operation 68 compiles and captures actual executable code before publishing a
real function Value. Operation 69 clones real code custody and keeps strong
edges to the receiver, environment, and previous callable. Operation 70 checks
the actual resource class and binding, validates all keyword keys as strings,
snapshots arguments and keywords under the Value mutex, and then executes
outside that mutex. Nested bound methods prepend receivers in the original
MethodType order.

The current public capture paths create resource kinds 3 and 4. The code-owner
mechanism also accepts the reserved kind 5 domain, but a complete public
builtin-function factory is not qualified by these gates.

### Reply and independent cleanup facts

The reply is HIABVR01 and remains at least 128 bytes.

| Offset | Meaning |
|---|---|
| 8 | Primary operation status |
| 16 | Actual returned Value kind |
| 24, 32, 40 | Delivered strong Value capability |
| 48 | Actual value size |
| 64 | Disposition: 1 return, 2 raise |
| 80 | Union of actual pending retirement domains |
| 88 | Known ownership fact |
| 96 | Actual primary capability delivered |
| 104 | Cleanup status, independent of the primary result |

A successful body result is cloned into a caller-owned strong capability
before internal call state is retired. Raise disposition requires an actual
BaseException subclass object; a name or dictionary tag is not sufficient.
The same exception object is propagated with a strong reference.

A delivered primary capability remains delivered if later cleanup fails.
Consumers must preserve it independently of pending or cleanup status and
must release it using the real Value release protocol. A malformed or unknown
receipt must retain custody rather than guessing that no capability exists.
Pre-publication validation errors publish no result. Converting every
pre-publication wire error into a public Python exception is an enclosing API
responsibility and is not declared complete here.

## Native code-body contract

The code owner admits the fixed HIA entry signature
f0(readbuf, mutbuf, mutbuf) -> u32 with the declared native effects.
The native function receives a 128-byte HIACIN01 frame, version 1 at offset 8,
and a borrowed actual call-frame capability at offsets 24 through 40.

The actual call frame is a six-element tuple:

1. Original callable.
2. Captured environment.
3. Bound receiver, or None.
4. Prepared argument tuple.
5. Detached keyword dictionary.
6. Captured name.

The body may not consume the borrowed frame capability. It can read its
contents using the ordinary Value operations. Its own temporary return
capabilities are tracked separately.

Return code 1 yields HIACVA01: request length at 8 and a complete allowed Value
request at 128. The fixed driver invokes the same captured Value entry and
puts its response at offset 524288 of the code-owned response buffer. Resume
writes the child return code at offset 112. Actual continuation mappings and
code capabilities remain owned during every nested Value call.

Return code 0 completes with HIACBR01, disposition at 8 and an actual
capability at 24 through 40. Other header fields must be zero. The native
driver validates this receipt and clones the primary result. A function may
make another actual operation 70 call through the same Value entry.

The body whitelist excludes all lifecycle, binding, managed-edge, private
deferred, queue-claim and internal invocation operations. Only fixed native
bridges select the code and Value entry addresses.

## Custody, concurrency and retry

Before releasing the original Value mutex, the graph role constructs strong
roots for the callable, environment, receiver, arguments and keywords. It
publishes an actual arena token and a native invocation ledger. The native
call-record mapping and code continuation are owned by that token until
actual retirement.

Every body-produced capability, including all rows from dictionary
enumeration and all descriptor result capabilities, is adopted into the
current invocation's managed list. Private operation 89 performs the actual
atomic adoption under the Value mutex. Operation 90 consumes only the current
scope's temporary capabilities. It cannot consume a borrowed frame or a
capability belonging to another scope.

A failed adoption does not discard the produced capability. The actual
continuation output retains it, and the native call record records the next
required phase. Retrying adoption is idempotent. A real futex EIO gate holds
the Value mutex in another native operation, denies the actual waiting
syscall, and verifies that one later native operation 56 adopts and retires
the preserved result without host intervention.

Private operations 94 through 96 claim a pending call record, preserve failed
retirement, and acknowledge actual unmapping. They do not invoke another
finalizer while holding an internal mutex. Cleanup retires scoped caps, real
code continuations, code ownership when applicable, temporary strong roots,
the native call-record mapping, and its actual arena token. Successful
consumption is never inferred solely from a return code.

Context offset 184 mirrors the actual pending native-call ledger.
The ordinary Value release and operation 56 drain it outside the Value mutex.
Q02 pending facts include this domain as well as arena and native-resource
retirement. A true munmap failure keeps the mapping and its token alive until
the real syscall succeeds.

A live native-callable count in the arena makes last-external-reference
collection inspect actual function/environment cycles even while the native
sidecar's context token remains live. It is incremented only after true
publication and decremented only after true native-resource acknowledgement.

## Qualification

The frozen product passed:

- All six original component gates.
- All six original campaigns with the original 300/660-second budgets.
- 31 record, 17 resource, 17 VerifiedProgram, 18 exception-capture and 10
  default hash/equality protocol groups.
- Seven existing actual Runtime-owner managed-edge groups.
- Five native packer groups, including 55 malformed frames and unchanged
  workspace and text bounds.
- Fifteen actual invocation groups, including reentrant calls, nested bound
  methods, real exception propagation, cycles, multiple returned capabilities,
  and eight threads making 64 actual calls.
- Eight actual kernel-failure and concurrency groups, including Value/code
  allocation and random failures, code and call-record unmap failures,
  reference removal while code is paused, and adoption lock failure.

The failed first cycle attempt and all earlier artifacts remain identified in
the construction receipt. No original assertion, compiler profile or test
time limit was weakened.

## Remaining integration

The public owner whitelist, final Future callback adapter, custom
__bool__/__len__/__fspath__/iteration dispatch, arbitrary iterable dataclass
construction, full Python exception constructor/formatting/traceback behavior,
and the whole public runtime remain separately tracked. Their completion
cannot be inferred from this component qualification.
