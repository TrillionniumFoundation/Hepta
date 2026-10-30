# Finite, proof-gated native u32 trace contexts

`hepta/hia_finite_context.py` adds a separate, bounded execution-context profile.
It addresses a narrower gap than general hot replacement: several predeclared
requests can execute inside one owned child, using already admitted immutable
native images. Every requested version change occurs after the preceding
request has returned. There is no online policy callback inside the child, no
background compiler, and no persistent HIA owner or loan shared across versions.

The old guarded-denominator opportunity protocol, its negative observations,
`PreparedArtifactSession`, and its `full_lifecycle(usize,u32)->u64` ABI remain
unchanged. This API has its own `hepta.hia.finite-u32-fold-context.v1` profile and
the exact `calculate(u32,u32)->u32` C ABI on Linux x86-64.

## Admission and what is proved

`build_bank(baseline, candidates, directory, clang=..., cases=..., oracle=...)`
accepts Core source documents, an empty build directory, and a trusted,
independently implemented host step oracle. It does not import DSOs or admission
receipts. The bounded candidate dictionary includes the exact baseline. Each
candidate independently passes:

1. The canonical Core verifier and the selected, acyclic scalar profile. There
   must be exactly one public `calculate(u32,u32)->u32` function, at most 32
   blocks and 512 operations, and no effects except an optional specified trap.
   Memory operations, resource values, calls, loops, FFI, and concurrency are
   outside this profile.
2. A fresh, all-input translation check against the baseline, preserving return
   values and the first specified trap. Unknown, timeout, or counterexample
   prevents LLVM emission/compilation for that candidate. The uniform solver
   timeout is 10 seconds.
3. The existing check of that exact candidate's generated LLVM, with exact Core
   and LLVM digests and the same 10-second solver timeout.
4. Compilation by the existing native backend, exact artifact digest binding,
   finite independent-oracle/Core checks, and finite actual Core/native
   differential execution on the supplied corpus of at most 64 input pairs.
5. Sealing of the internally built artifact bytes in a held memfd. Later
   replacement of the original output pathname cannot replace the admitted
   executable bytes.

The factory also builds and seals one fixed C driver. Before each trace it
rechecks the held descriptors' identities, required kernel seals and bytes,
and the implementation digest, including the bounded-capture implementation.
The bank is an in-process owner; copying and serialization are rejected.
Returned JSON reports and close snapshots are copies, never execution or
resource-release authority.

The translation and selected LLVM checks are distinct from the finite native
observations. They do not constitute a machine-checked proof of the Python
encoder, Z3, LLVM, linker, libc, loader, final machine code, host oracle, or the
whole language. A native abort on a tested Core trap is not an independent proof
of the abort's exact root cause. Exported-code hashes are reported; different
candidate labels do not imply different code. The checked-shift correctness
fixture currently illustrates this: Clang can merge the guarded variants into
identical function code.

## A closed request grammar

Call `bank.prepare_trace(requests)`, then `bank.run(trace, report=...)` once.
Requests have unique exact u32 IDs within a trace and name an admitted candidate.
There are two explicit modes:

```python
{
    "id": 1,
    "candidate": "baseline",
    "seed": 7,
    "mode": "fold",
    "values": [1, 2, 3],
}
```

`fold` evaluates `state = calculate(state, value)` for each listed u32 value.

```python
{
    "id": 2,
    "candidate": "guarded_polynomial",
    "seed": 0xffffffff,
    "mode": "xor_fold",
    "parameter": 0xedb88320,
    "values": [97, 98, 99],
}
```

`xor_fold` accepts byte values only. It evaluates
`state = calculate(state ^ byte, parameter)` with the explicitly fixed u32
parameter. This supports a separately qualified CRC byte-update kernel without
adding arbitrary callbacks or expressions to the native driver. The byte
sequence and polynomial are inputs, not inferred optimization assumptions.

Preparation snapshots the IDs, modes, parameters, seeds and values into
immutable tuples. Later mutation of the caller's dictionaries or lists cannot
alter the plan. The independent step oracle derives a final state and a
wrapping u64 rolling checksum for each request. A trace digest binds all these
values, the complete bank identity, and the exact selected image inventory.

Only images actually referenced by this trace are passed to and loaded by the
child. The driver uses dense local slots; the report binds each slot back to
the bank index, candidate label and artifact digest. A static policy therefore
loads one image. A two-version dispatch trace loads two images, with no implicit
baseline fallback. This prevents an unneeded multi-image load penalty from
being assigned to static controls. `planned_load_inventory`, `loaded_inventory`
and `ready_inventory` distinguish the plan from the observed acquisition and
symbol-resolution prefix after a failure.

The full plan is parsed before any `dlopen`. The driver then emits canonical,
flushed JSON lines for actual resource-limit readback, image acquisition and
readiness, each request's start and completion, and reverse-order close attempts.
Every event names the trace digest. Results additionally bind sequence, request
ID, image slot, mode, fixed parameter, seed, call count, final state and checksum.
The parent requires the exact event ordering, primitive types and raw canonical
bytes. Duplicate JSON keys, CRLF rewriting, a wrong image/ID/checksum, a boolean
where an integer was expected, reordered events, and trailing output cannot
turn an incomplete execution into success.

## Finite budgets and ownership

| Scope | Bound |
| --- | --- |
| Admitted images in one bank | 8, each at most 1 MiB |
| Prepared trace instances per bank, including consumed/cancelled instances | 4,096 |
| Simultaneously pending encoded request input | 1 MiB |
| Requests in one child context | 256 |
| Kernel calls summed across one context | 65,536 |
| Encoded input for one context | 1 MiB |
| Captured stdout / stderr | 128 KiB / 4 KiB |
| Child CPU / address-space / core-file limits | 3 CPU seconds / 256 MiB / 0 bytes |
| Child regular-file size limit | 128 KiB |
| Capture execution deadline | 5 wall seconds |
| Existing capture's final direct-child reap wait | Up to 3 additional seconds |

The 5-second capture deadline is not a hard real-time bound on the complete
Python call: parent checks, oracle work, process creation, scheduling, cleanup
and result validation have their own costs. CPU and address-space limits apply
to the native child, not the parent's Python object storage. The pending-byte
quota counts encoded input owned by the bank; it is not a claim about Python
resident memory or data still retained separately by a caller. Compilation and
proof preparation use their existing independent limits, and are not covered
by the native execution deadline.

Consuming or cancelling a trace releases its pending payload registration while
retaining its consumed nonce in the bank's finite inventory. `bank.cancel(trace)`
is permitted only before that trace is consumed. It starts no child, grants no
replay permission, and cannot replenish the per-bank trace cap. Closing a bank
cancels all unstarted plans. Successful repeats must be explicit new prepared
instances; an identical input digest is not a durable exactly-once service key.

A launch or execution failure poisons the bank and cancels its other pending
plans. The failed trace is never replayed automatically. Exact captured bytes,
stream totals and the validated completed-request prefix remain in the report.
A `start` without its matching `result` marks an unfinished request; its tail
is not assumed to have had no effect and is not a restart cursor. A source-level
trap, child signal, timeout, malformed output or uncertain cleanup cannot be
reported as an ordinary successful trace.

If loading fails partway, the fixed driver attempts to close each acquired
library exactly once, in reverse order. If a trap or signal prevents explicit
`dlclose`, confirmed child exit/reap reclaims that child's mappings; this is
reported separately from a successful sequence of explicit close events.
Parent memfds remain held through the bounded-capture operation.

If process ownership or cleanup is uncertain, the parent must not close and
reuse proc-fd numbers that a possibly live child could still resolve. The bank
therefore retains those pins as visible ownership debt, attaches its actual
owner to the exception, and reports `close().complete == False`. It offers no
numeric PID retry or cleanup-recovery shortcut. Likewise, a descriptor close
whose result is unknown is attempted once, retained as debt, and never retried.

## Loader environment and trusted host boundary

The context child receives an explicit environment containing only
`PATH=os.defpath`, `LANG=C`, and `LC_ALL=C`. It does not inherit `LD_PRELOAD`,
`LD_AUDIT`, `LD_LIBRARY_PATH`, `GLIBC_TUNABLES` or other parent environment entries.
This happens before `exec`, so a foreign constructor cannot run before the
driver's limits and then be incorrectly accepted as a sealed-image execution.
The regression first confirms a harmless real preload constructor can write a
marker in a control child, then confirms that the same configured parent cannot
inject it into a successful finite-context child.

`clang_capture.run_bounded` has a new optional `env` keyword for this qualified
Linux direct-Popen path. Its default is still unchanged environment inheritance.
An explicit environment must be an ordinary dictionary of exact strings, at
most 256 keys and 128 KiB encoded bytes, with no empty key, `=`, NUL or malformed
UTF-8. The dictionary is copied and validated before launch. Explicit
environments on the existing Darwin guardian or Windows Job Object paths are
refused, rather than silently ignored. Compiler and C-capture invocations keep
their existing toolchain environment; the caller's global `os.environ` is not
changed by production context execution.

This is still a trusted-host native execution profile. Toolchain preparation,
the system loader and its configured system libraries, the host OS, and the
trusted Python caller remain in the computing base. Explicit child environment
selection is not a general sandbox against arbitrary machine code, privileged
host actors, or filesystem modification. There is no FFI memory-safety theorem
or general native state-migration guarantee here.

## Correctness evidence and future economic comparisons

`tests/test_hia_finite_context.py` covers real, freshly checked/compiled/sealed
images, both fold modes, exact image selection, path replacement, limit readback,
real partial load cleanup, a real bounded-output refusal, and a real native trap
after an already completed request. Counterexamples cover forged output,
unknown proofs, one-shot consumption, input mutation, cancellation, pending-byte
exhaustion, uncertain descriptor close and uncertain child cleanup.
`tests/test_clang_capture_environment.py` separately tests environment rejection,
snapshotting and preservation of default inheritance. These are short
correctness runs, not a preregistered performance campaign.

This mechanism makes no claim that NDU is useful or that execution-context
reuse is profitable. A subsequent experiment must register its inputs, policies,
sample denominator, budgets and accounting before observing performance. At
minimum it must separate fresh-child baseline, coalesced static baseline and
coalesced multiversion execution, with single-image static-specialization
controls where appropriate. All policies get the same allowed reuse and exact
load-inventory rules. The complete cost includes preparation/proofs/builds,
oracle/input work, context creation, loading, all requests, verification,
unloading, owned-child cleanup, and final descriptor release. Kernel-only or
warm-only timing cannot establish net benefit; a batching benefit cannot be
attributed to NDU. Unsuccessful or incomplete runs and previous negative studies
must remain in the evidence.
