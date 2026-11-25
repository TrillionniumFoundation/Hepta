# Native BackgroundOptimizer Job and Future ownership

This component owns a heap Job, its actual native Future, immutable input bytes,
and eight independently owned immutable-payload slots. It is a lifetime component.
The complete BackgroundOptimizer and its rank/runtime business path remain unqualified.

The public module owns the Job context, payload context, fixed Future image and
fixed payload image until their exclusive destruction succeeds. Each retain
creates an independent nonce node. A public method keeps one such node across
callbacks and native subprocesses. User-held settled Futures survive coordinator
shutdown and pending-queue removal.

## Product boundary

The HIA policy implements registry validation, nonce identity, object/reference
links, allocation rollback, slot transfer and retirement. Its readable mechanical
adapter implements fixed syscalls, futex-word atomics, malloc/free, byte copying,
and captured six-word provider calls. The provider return is truncated to the
specified u32 ABI. No verified program fact is accepted from a caller.

The object embeds the existing native Future rather than recreating its token,
callback or cancellation semantics. Final release unlinks the last reference,
publishes the object in a retiring-object list, releases the Job mutex, and then
destroys the Future and drops all owned payloads. Callback reentry can release
other objects. The Job mutex is reacquired and the retirement links are reread
before final free. Context destruction refuses both live references and in-flight
retirement. An impossible trusted-provider destructor failure quarantines the
object; it never frees storage whose cleanup is incomplete.

## Six-word ABI

hia_mv_background_jobs(input, input_bytes, output, output_bytes, context, context_bytes)
requires disjoint input, output and context, output >= 2048 and context >= 256.
Private frame refusal returns 0xfffffffd without changing the owner context.
Other returns are zero with a HIABJOR1 reply. Only the trusted fixed composition
may use borrowed pointers; they are not public capabilities.

The input is a 128-byte HIABJO01 header, followed only for create by immutable
input bytes. Word 8 is the operation. Words not listed for that operation must be
zero.

| Operation | Input fields |
|---|---|
| 0 initialize | Future function @24, payload function @32, payload context @40, context extent @48 |
| 1 create | input byte count @72, exact bytes @128 |
| 2 retain, 3 drop, 6 borrow | Job capability node/nonce/nonce @24/32/40 |
| 4 copy input | Job capability @24/32/40, offset @48, count @56 |
| 5 destroy context | no fields |
| 7 transfer payload slot | Job capability @24/32/40, owned payload capability @48/56/64, slot @80 |
| 8 retain payload slot | Job capability @24/32/40, slot @80 |

The slot index is 0..7. An all-zero incoming payload capability clears a slot.
An accepted nonzero capability transfers that exact independently owned reference;
the caller must not reuse or drop it. Replacing a slot drops its prior reference
after releasing the Job mutex. A duplicate node already owned by any slot is
refused. Slot reads return a new, independently owned payload reference.

Reply fields: status @8; returned capability @16/24/32; byte count @40; copied
count @48; PID @56; borrowed Future/metadata/input pointers @64/72/80; metadata
extent 64 @88; Future extent 512 @96; capability kind @104 (0 Job, 1 payload);
slot-transfer flag @112. Other header fields are zero. Copied input begins @2048.

Status: 0 success, 1 invalid/stale/foreign capability, 3 invalid range or duplicate
owned slot, 4 allocation failure, 5 lifecycle/PID refusal, 6 syscall failure,
7 insufficient copy output, 9 internal invariant/provider failure. The transfer
flag remains authoritative if cleanup of an already-replaced slot fails; callers
must not replay the effect.

The object allocation is 864 + actual input length, with checked u64 arithmetic
and real allocation failure. This carrier adds no 8 MiB or 64 MiB input limit.
BackgroundOptimizer's separate original submission structure budget is still
required at the business boundary.

## Qualification

Actual native Future and payload owners were composed with the native Job image.
Ten behavior groups passed, with 6177 Job calls and 2558 external payload calls.
They cover retained Futures after queue release, exact eight-slot cleanup,
reentrant nested final releases, dropping the final user reference inside a
completion callback while a method guard remains, 12 overlapping retirements,
800 concurrent reference/read cycles, 100 concurrent result replacements, stale
allocator reuse, a complete 8 MiB + 1 byte opaque input, PID/foreign/ABI refusals
and upper-register u32 provider behavior.

Seven real allocation controls and 24 native packer/source-prefix controls passed.
The allocator test observes actual call sites: failed object/reference allocations
leave the owner unchanged, 1001 individual Job references plus one object produce
1002 allocations and 1002 frees, and a payload-retain allocation failure leaves
the field unchanged before a successful retry.

The first unqualified image failed creation because freshly allocated Future
storage was not initialized before calling its initializer. The v2 policy clears
the entire embedded Future and metadata/slot region before the first call. The
v1 failure and v2 reports are preserved separately. This component does not claim
a complete public Future object adapter, rank caller, runtime provider, optimizer
cost ledger, or whole-background qualification.
