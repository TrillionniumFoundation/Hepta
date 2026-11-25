# Native multiversion runtime and lease references

This component owns the lifetime of the existing HIA preparation, native loading,
calling, publication, rollback and retirement composition. It is not the complete
public runtime: typed public snapshots and errors, and the fixed BackgroundOptimizer
provider, still require integration. whole_native_runtime remains false.

## Actual construction and qualification

The HIA policy is compiled by the captured v95 source compiler. A pure HIA packer
writes the closed ELF object, and the existing pure HIA five-import linker creates
the shared image. The resulting 44-role image is 7,377,680 bytes, SHA256
a82a236b9110f34e39520ff3005db167f32c9d5322331288e7c377bdf1214cf5.
Its only dynamic imports are dlopen, dlsym, dlclose, malloc and free.
The mechanical adapter supplies syscall/atomic/copy facts and fixed entry calls;
all registry, lifetime, lock and release decisions are HIA.

The accompanying JSON contains complete actual records and source/flat/object/image
pins. Current gates passed: 7 lifecycle checks / 24 actual calls; 6 concurrency
groups / 3,446 actual calls; 25 real allocation controls and injected failures;
127 native pack/link boundaries; 106 private framing guards plus 5 lifecycle and
retirement checks; and 17 original runtime state comparisons / 47 native effect
calls. Original runtime uses the independently recovered exact Z3 4.15.4 library
only as a QA oracle. The HIA product does not depend on Z3 or Python.

Concurrency checks exercise independent retained references, sixteen callers
dropping the same reference, a last lease reference dropped during actual native
call, and a last runtime reference dropped during actual publication. The operation
completes before its internal pin is released. Stale, forged, foreign-context and
forked references fail. Same-context recovery after malformed construction and
every constructor/acquire allocation failure preserves actual FD, artifact and
allocation ownership.

A real extra file in the private artifact directory prevents final directory
removal. Dropping the last reference then retains the owner, refuses context
destruction, and records the failed finalizer. Moving that QA-owned obstruction
out of the directory permits explicit retry to complete. No fake destructor
acknowledgement is used.

## Private six-word interface

hia_mv_runtime_handles(source, source_bytes, output, output_bytes, context,
context_bytes) uses a 256-byte zero-initialized persistent context and a disjoint,
exclusive 96 MiB continuation/output area per invocation. Source is immutable and
does not alias either view. Successful structural completion returns zero.
Malformed private frames or inadequate views return 0xfffffffd.

The 128-byte request is HIAMVHQ1, followed by little-endian u64 fields:
operation at 8; capability node/tag0/tag1 at 24/32/40; tail byte count at 72.
Other fields are zero. The complete tail is an actual HIAMVEX1 frame for
operations 1 and 4, at most 20 MiB. No caller-supplied success fact is accepted.

| Operation | Meaning |
| --- | --- |
| 0 | Initialize context once |
| 1 | Construct actual runtime and return owned reference |
| 2 | Retain runtime or lease as new independent reference |
| 3 | Drop exactly this reference |
| 4 | Execute allowed actual runtime or lease operation |
| 5 | Destroy empty context |
| 6 | Validate reference and return kind, without pointer escape |
| 7 | Retry one retained failed finalizer |

The 128-byte reply is HIAMVHR1: status at 8, kind at 16 (runtime 1, lease 2),
new capability at 24/32/40, actual child status at 48, child reply offset/extent
at 56/64, retained flag at 72, finalizer status at 80 and PID at 88.
Status 1 is invalid capability, 3 forbidden command, 4 allocation failure,
5 lifecycle refusal, 6 OS/nonce failure and 9 internal or retained cleanup
failure. Child diagnostics retain the existing owned-FD contract: receiving
owner closes each transferred FD exactly once.

Runtime references may invoke publication, conditional publication, lease,
rollback, close, cleanup, snapshot and cancellation. Lease references may invoke
call, close and info. The fixed adapter substitutes actual private lease identity;
a caller cannot submit an arbitrary private lease pointer.

## Lifetime and locking

Every retain allocates its own 96-byte reference node with a fresh 128-bit nonce.
Registry lookup scans owned nodes before dereferencing a caller candidate.
A lease object holds an additional internal strong runtime reference. In-flight
operations register a linked pin in their exclusive continuation before releasing
the registry lock; no finite reference counter is used.

Last-reference cleanup runs outside the registry mutex. The object remains on a
retiring list throughout cleanup. After the fixed finalizer returns, the owner
reacquires the mutex and reads the object's current neighbours before unlinking,
so reentrant or concurrent release cannot invalidate saved links. Context
destruction refuses both active and retiring resources. Failed cleanup keeps the
same object and ownership until explicit retry.

## Two fixes exposed by actual carrier gates

The preparation intake's structured rejection returns its status as wrapper
return value. The generation adapter previously checked return zero before
taking the rejection's two owned diagnostic FDs. It now checks reply magic and
returned status agree, then transfers exact FDs before releasing generation
memory. The actual malformed-constructor gate checks FD equality.

The artifact name now includes both o and n in generation-<decimal>.so.
The previous development writer omitted o. Actual baseline and publication
paths, plus original runtime comparison, verify the corrected name.

Earlier failed reports and original development build metadata remain available.
A separately named reconciled build record binds the actual object and all 44
component files; inherited v2 top-level object metadata is not a qualification pin.
