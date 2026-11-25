# Native inherited Future methods

## Qualified scope

This checkpoint supplies the four inherited methods that remain callable on the original
`_OptimizationFuture`: `set_result`, `set_exception`,
`set_running_or_notify_cancel`, and `running`. It also connects their actual state
transitions to the existing native callback, `wait`, `as_completed`, and Iterable
owners. The reference is the frozen project class together with the installed Python
3.14 `concurrent.futures.Future`; the qualification records their source hashes.

The runtime implements this behavior with HIA policies and the fixed mechanical bridges.
Its final public, array, and Iterable products are made by actual native HIA packers.
The qualification uses Python only as the independent original oracle and development
driver. The implementation does not invoke a host-language semantic dispatcher.

The checkpoint covers this component. It does not claim that the final unified typed
dispatcher, whole BackgroundOptimizer, installation, activation, or whole final source
tree has passed merely because these components passed. Existing historical documents
and their old image pins remain evidence for those historical products.

## Original semantics retained

A Future that is pending can become running, cancelled, or finished. Running is a separate
real field; the existing observed state values remain 0 pending, 1 cancelled, and 2
finished. Both strict setters can complete a running Future. They reject cancelled and
finished Futures with an actual `InvalidStateError` value. The internal `_complete`
entry retains its previous early-ignore behavior when completion has already happened.

The original cancellation order matters: `_OptimizationFuture.cancel()` first attempts
to cancel the publication token, then invokes the Future state transition. A running
Future therefore returns false from `cancel()` while its publication token has become
cancelled. The native implementation preserves that sequence.

The original Python 3.14 `result()` checks whether the stored exception is **not None**.
It does not use truthiness. Consequently:

- `set_exception(None)` makes `result()` return None.
- `set_exception(False)`, zero, an empty container, an empty string, and other ordinary
  nonexception values make `result()` raise
  `TypeError("exceptions must derive from BaseException")`.
- `exception()` returns the actual stored value, including an owned None object.
- A typed Exception or BaseException is retained and returned with the same native value
  identity and original classification.

Truthiness is used separately when rendering the original Future representation in
`InvalidStateError`. Mutable list and dictionary truthiness is read afresh; it is not
cached at completion. An ordinary dictionary containing a key named `class` is still
an ordinary dictionary. Exception classification comes from the actual typed carrier,
not a spelling in a user dictionary.

The message uses the native Future's stable actual kernel identity. It preserves the
original message format, state, and type name without pretending that a native object
has the old Python object's address. The differential oracle substitutes only those
two actual identities. Class names are not truncated to a new fixed limit; the tests
include a real 70,004-byte class name.

`set_running_or_notify_cancel()` succeeds exactly once for a pending Future. A
cancelled Future can become cancelled-and-notified exactly once and return false.
Unexpected repeated, running, or finished states produce the original critical log and
`RuntimeError("Future in unexpected state")`. The first internal cancellation callback
still runs before user callbacks and performs the cancelled-to-notified transition.

## Versioned private protocols

These are internal, source-bound interfaces. The public typed dispatcher must obtain
the value and callable classification from the actual native typed carrier. These
packets are not an alternative way to submit user assertions about object identity or
finished state.

All existing protocol versions retain their previous operation ranges and reserved-field
refusals. A new version does not authorize a new operation under an old magic.

| Role | New magic | New operations |
| --- | --- | --- |
| Kernel | `HIAMVFQ2` | 11 strict result; 12 strict exception; 13 running transition; 14 running query; 15 detail; 16 internal cancellation notification |
| Cell | `HIABFQ03` | 15 strict result; 16 strict exception; 17 running transition; 18 running query; 19 retained detail |
| Public owner | `HIABFP02` | 22 `set_result`; 23 `set_exception`; 24 `set_running_or_notify_cancel`; 25 `running` |

The public request remains 192 bytes, output 65,536 bytes, global context 256 bytes.
Factory identity occupies request 16/24/32; Future capability 40/48/56. Setter value
capability is 64/72/80, with classification at 96: 1 ordinary value, 2 actual Exception,
3 actual BaseException. Other fields are reserved for these four operations.

The reply remains `HIABFRP1`. Normal booleans are at 96. Dynamic original exceptions
are status 1 or 2, kind 200, with an owned value capability at 72/80/88.
An allocation failure returns the established status 1/kind 103 with no invented error
object. Other established builtin classes remain in the kind field, not the scalar field.

The kernel still uses 64-byte input, 512-byte output and 512-byte state. Its new
persistent fields are running at 96, cancelled-notified at 104, and completion mode at
112. Completion mode 1 denotes result and 2 exception; existing state and token fields
are unchanged. New detail replies add running at 72, notified at 80 and mode at 88.

The cell still uses 128-byte input, output at least 16,384 bytes, and a 256-byte private
context. Its new detail reply fields are running 128, notified 136, mode 144, and typed
classification 152. Cell capability input stays at 24/32/40. Setters use value
48/56/64 and classification 80. Strict terminal-state checking happens before retaining
the new supplied value; the kernel checks again when committing to close the race.

## Callback and observer integration

The public bridge captures two additional fixed entries in the existing global context:

| Offset | Fixed entry |
| --- | --- |
| 184 | Direct native notify entry |
| 192 | Small native critical-logger entry |

Neither is selected from public input. The old captured kernel, cell, value, owner,
callback, timeout, and logger slots remain unchanged.

The notify role retains `HIABFN01` as the original queue-only protocol. Its fixed
first-kernel-callback profile is `HIABFN02`; `HIABFN03` performs notification after a
successful public cancelled-to-notified transition. Input remains 64 bytes, output
8,192 bytes, global context 256 bytes. These two profiles receive the actual strongly
held kernel pointer from the fixed native caller. They do not accept a public
caller-supplied declaration of a valid pointer.

The first callback reads actual kernel state and mode. It performs the internal
cancellation transition where required, then records observer completions before user
callbacks. An already-notified internal cancellation callback emits the critical and
caught RuntimeError logs and continues according to the original Exception behavior.
The new callback-status output is at 32; the old queue-only protocol still leaves it zero.

The existing observer registry mutex, retained vectors, sticky ready words, and
completion queues are retained. No allocation is needed when a Future completes.
Array node offset 208 records whether an actual pending subscription received an
exception completion. This preserves the original distinction for `FIRST_EXCEPTION`:

- At initial inspection, an already-finished Future counts only if
  `exception() is not None`.
- While the waiter is registered, the real `set_exception` completion mode invokes
  the exception notification, including `set_exception(None)`.

The new array product and the unchanged Iterable policy are actually repacked together.
The Iterable owner still captures its deadline on first next, obtains Future references
through real native iter/next calls, retains/deduplicates actual identities, preserves
typed errors and PEP 479 cause/context identity, and releases partial collections.
No fixed 128-element cap is introduced.

## Ownership, failure, and race behavior

Strict setter candidates keep the original Future and supplied values alive through
commit and callbacks. Callback reentry, dropping the last external Future/factory
references, normal returns, Exception logging, and BaseException propagation are tested
against the original behavior. Completed result and exception values remain independently
owned. Each temporary cap, diagnostic string allocation, callback frame, and rejected
candidate is released exactly once.

The final test set contains actual closed-allocator mmap and value-arena mremap failures.
The child has a real address-space limit; ptrace changes only the relevant allocation
length, and the kernel returns actual ENOMEM. No product instruction, provider response,
or return register is replaced. Tests restore the limit and retry, check value reference
counts and terminal state, and check that newly created native mappings are reclaimed.

One such test found a real candidate defect: a failed retained-detail allocation while
constructing InvalidStateError was classified as an internal error. The final owner uses
the existing cell error mapping and returns MemoryError. The failed candidate and its
actual ENOMEM record remain in the evidence ledger.

The concurrent tests include 8 competing setters on each Future, mixed result/exception
setters, exactly one winning completion and one callback invocation, and 96 actual
running/cancel races. Both running-wins and cancel-wins histories were observed. Separate
old concurrency and quarantine-retry gates are rerun with the final image.

## Actual construction and qualification

The JSON companion records every exact runtime source hash, source compiler capture,
native flat, bridge, packer input, final product, and report hash. The qualified compiler
was captured once into a sealed descriptor; both source builds matched byte for byte.
No original profile limit, workspace limit, or method acceptance domain was raised to
compile the changes.

The final component run has **27 successful groups**. These include:

- 372 original inherited-method pairs and the prior 17-case smoke;
- 19 initial/in-flight waiter and callback-notification cases;
- 7 new callback, logging, and concurrency groups;
- 275 new version, reserved-field, capability and view controls;
- 20 new strict-setter real mmap ENOMEM cases;
- 5 new real value-arena mremap ENOMEM cases;
- all seven old public smoke/concurrency/private/cleanup/allocation/packer groups;
- the complete old array, Iterable, and queue-only notify groups.

The old array comparison contains 1,534 actual array calls and 5,536 public calls.
The Iterable rerun includes actual compiled HIA iterator callbacks, partial ownership
cleanup, 259 unique Futures from 648 yielded references, real allocation failure, and
PEP 479 identity checks. These are real executions; prior successful reports are not
substituted for them.

## Preserved corrections and limits of the evidence

The initial False-to-None hypothesis is explicitly withdrawn. The old candidate and
`truth-diagnostic-v1` show the mismatch with the actual Python 3.14 oracle; the final
candidate uses `is not None`. The corrected behavior is included in the final matrix.

Development-only fixture errors are kept separately: an invalid Python source spelling,
a class name that Python itself refuses, and a failed author invocation that left the
previous generated source unchanged. The unchanged-source construction is not described
as a fixed product. Only the final regenerated source and final native image receive
this qualification.

The independent numeric timeout leaf and value core keep their already-qualified pins.
This checkpoint does not invent asynchronous KeyboardInterrupt from a futex EINTR.
Signal-to-typed-exception delivery belongs to the final unified public dispatcher.
Its actual callback/iterator BaseException paths remain owned, explicit, and qualified.

