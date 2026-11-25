# Native Future Iterable observers

This component supplies the native Iterable/iterator capture and lazy generator
owner for wait and as_completed. It calls the qualified captured-array observer
and the actual public Future/value entries in the same global context. Its
implementation, callbacks used by qualification, arithmetic, allocation and
notification are native. No host-language effect dispatcher implements these
operations.

This is a qualified native component. The final public typed dispatcher,
inherited Future setters/running, external CLI signal integration, background
controller, release construction and installation remain separate gates. It
does not claim compatibility with arbitrary live Python interpreter objects.

## Source and construction

The two runtime HIA sources are
examples/hia_bootstrap/background_optimizer_future_public_observers_iterable.hepta
and background_optimizer_future_public_observers_iterable_packer.hepta.
The readable mechanical binding is
tools/hia_background_optimizer_future_public_observers_iterable_bridge.S.

The fixed native HIA packer consumes HIABFAPK + owner_length Q +
array_length Q + zero Q + actual owner flat + actual complete array flat.
Each component must be nonempty and at most 4 MiB. Its complete output is the
fixed mechanical effects prefix with checked relative calls, then both actual
input bodies. No assembler or linker executes in this production binding.
The separate array image is built by HIABFOPK from its HIA owner and HIA
binary64 arithmetic. The existing notify leaf remains the first fixed
completion callback.

The final qualified adapter image is 510065 bytes, SHA-256
6929c9ff8dc5c51afc83d5359d71136ebb815917674745625591dce8041cdf44.
The companion JSON records actual source, compiler, dependency, build and
qualification pins, including two byte-identical native source builds and
actual execution of the HIA packer.

## Fixed six-word adapter

S contains HIABFA01, a 192-byte header and, only for the built-in list profile,
48-byte actual Future rows. O is at least 262144 bytes; W is the actual shared
256-byte public Future global. Views must be nonnull when nonempty, have
nonoverflowing extents and be pairwise disjoint. There is no additional S/O
alignment restriction. The complete entry performs its native effects loop
and returns zero with a 128-byte HIABFAR1 reply. It does not return an action
for a host dispatcher.

| Header field | Meaning |
| --- | --- |
| 8 | Operation: 0 wait, 1 as_create, 2 next, 3 close, 4 built-in list wait, 5 built-in list as_create |
| 16 | For generic 0/1, fixed captured HIA callable entry; for 2/3, lazy node |
| 24/32/40 | For generic 0/1, actual owned-value closure environment capability |
| 48/56/64 | For 0/1/4/5, actual timeout value capability or all zero for None |
| 72 | Internal captured return condition: 0 FIRST_COMPLETED, 1 FIRST_EXCEPTION, 2 ALL_COMPLETED, 3 invalid; as_create requires zero |
| 80 | Built-in list row count; zero for generic 0/1 |
| 192 onward | Only operations 4/5: factory3Q then actual Futurecap3Q for each row |

Operations 2/3 instead carry node/tag0/tag1 at 16/24/32 and require the remaining
header bytes to be zero. Generic operations require an actual fixed callable;
list operations require zero callable/environment fields. Reserved fields are
zero and extents must match exactly. These are private capture formats, not
public truth flags or permission to execute a user-supplied arbitrary pointer.
The final typed constructor must capture the source-bound HIA entry in the
global executable lifetime and provide a real owned value environment.

The reply uses status8/kind16 and retains the array observer's normal fields:
kind1 is an owned wait-result array capability24/32/40 with done48/pending56/
total64; kind2 is a lazy adapter capability24/32/40; kind3 transfers an
independent Future with factory24..40 and cap48..64; kind4 is exhausted;
kind0 is successful close. A wait result is consumed through the array
owner's take/close operations, not the lazy adapter's close.

Errors preserve the actual upstream status and kind. Built-in classes are
kind100..107; scalar96 is detail, never the class. Kind200 carries an owned
actual exception value capability72/80/88. A private closed-allocator failure
is status3/kind103; an actual callback's status1/kind103 is kept unchanged.
Unfinished and total counts remain at96/104 when supplied by the array.

Offset112 is the input adapter capability's consumption flag. It is one after
a claimed next terminates or close succeeds, and zero for a yield, invalid
lookup or busy refusal. Reentrant next/close returns kind105/detail2 without
consuming the live generator. Offset120 separately records cleanup failure.
A malformed six-word view or request returns 0xfffffffd before mutating the
global. A stale private capability is not a public Python exception model.

## Actual native callable protocol

The callable receives the same fixed six-word shape, with S 192 HIABFIQ1,
operation 0 iter or operation 1 next at 8, and an actual borrowed environment
capability 16/24/32. O is 8192 and W is the same actual global. It returns zero
with a 128-byte HIABFIR1.

| Reply status/kind | Ownership and meaning |
| --- | --- |
| 0/1, from iter | Owned iterator environment capability24/32/40 |
| 0/2, from next | Owned Future: factory24/32/40 and cap48/56/64 |
| 1 or 2 / 200 | Owned actual Exception or BaseException value24/32/40 |
| 1 / 100..107 | Actual built-in error without allocated exception value; cap fields zero |
| 3, from next | Normal StopIteration exhaustion, no owned return |
| 4 / 200 | Actual StopIteration-family exception with owned original object24/32/40 |

Status4 is produced by the actual native callable's exception path. No class
string is used to infer an inheritance relationship. The public callable
carrier must preserve that distinction. From next, status4 is consumed as
normal iteration termination and its owned object is released. From iter,
wait propagates the original object. From iter during as_completed, the
adapter implements generator semantics by constructing an actual RuntimeError
value with message "generator raised StopIteration", __cause__ and __context__
both referencing the same original exception, and __suppress_context__ True.
Every temporary key, value, partial dictionary and original owned exception
is released if construction fails.

The adapter retains the closure environment and timeout at creation.
as_create performs no iter/next call or timeout arithmetic. At the first next
it first asks the array owner to construct an actual empty iterator carrying
the original binary64 deadline. Only then does it call iter and repeatedly
call next. Once enumeration finishes, HIABFO02 adopts that live deadline
capability under the shared lock. It accepts neither a raw supplied deadline
nor a caller-supplied finished/verified marker. The temporary clock capability
is closed on success and every failure path.

Every successful next transfers ownership even for duplicate Futures.
The adapter retains all raw inputs until the array owner has made its own
independent identity-deduplicated captures, then drops every raw reference,
including duplicates. Collected vectors grow by checked native allocation,
without a 128-element ceiling. The built-in native list profile independently
retains its actual input Futures at list capture, so its lifetime does not
depend on the original caller's Future references.

## Registry, ordering and cleanup

Lazy nodes use the same HIABFOB1 registry at W48, with type144=2 and active96=0.
They occupy 512 bytes. The first 256 bytes retain the established notify/registry
shape; only after matching a live type2 capability may the adapter read the
extra 256 bytes. Other array APIs reject this type. Notify skips inactive nodes
without interpreting their array fields.

Lookup, busy claims, registration, unlink and release of busy state synchronize
on W32. Persisting an active generator writes only its private tail and busy
word, preserving concurrent changes to its linked-list next pointer. The
entry never calls user/native iteration or the array observer while holding
that shared lock. Actual array subscribers retain the existing sticky futex
word and serialized completion queue; lazy adapters do not manufacture a
completion order.

Close and terminal errors unlink the adapter before closing inner array and
clock capabilities, dropping any temporary Future, every collected Future,
iterator/closure/timeout values and partial exception-wrapper values, and
unmapping the exact owned allocations. A linked lazy node prevents global
destroy. Cancellation of ordinary futex waits is not inferred from EINTR:
the original retry behavior is kept until an actual external interrupt
source is supplied by the final public dispatcher.

## Qualification and limits of the claim

The final adapter and public Future v5 were used together. The actual native
iterator fixture is itself HIA compiled by the pinned native source builder.
It mutates an actual native value environment, retains actual public Futures,
performs real nanosleep, returns actual typed values, and produces iteration
events without a host callback or policy dispatcher.

The original-semantics matrix includes empty/duplicate native iterables,
actual iter/next counts, ordinary and BaseException identity, built-in
MemoryError, first-next arithmetic ordering, wait's original empty-set bypass,
real enumeration against a preexisting deadline,648 owned yields collapsing
to 259 unique Futures, caller-reference release, and partial generator close.
It recorded 325 adapter calls and 1744 public Future calls.

Lifecycle checks include StopIteration and a subclass, class-name lookalikes,
shared cause/context identity including cyclic values, actual concurrent
busy next/close,64 lazy nodes and four concurrent close threads during real
Future notifications. Three separate child processes used kernel seccomp
ENOMEM at exact mmap extents: first collected item, ninth item/vector growth,
and downstream array allocation after21 next calls. All references were
reclaimed and the actual global/value owners destroyed successfully.

Fourteen additional native protocol fault injections target every partial
PEP479 allocation/set boundary. These delegate other calls to the unchanged
native value image and return its documented MemoryError at the selected
boundary. They are reported as protocol fault injection, distinct from the
three actual kernel ENOMEM tests.

Private controls cover forged/stale/cross-kind capabilities, eight view and
eight shape refusals, accepted unaligned S/O canaries, eleven atomic packer
rejections, five short-output refusals and actual native packed-byte equality.
The reports retain early fixture-generation and syntax failures separately.
None of these component results is transferred to a different source tree,
final release installation, full background controller or the still separate
inherited Future setter/running surface.
