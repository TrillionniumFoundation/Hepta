# Native cold allocator contract

This component retains both independent reference arms required by the original
owned/chain cold groups: the complete HIA resource VM and an independent native
resource backend using actual libc allocation. It does not replace native
allocation with simulated VM state, an expected byte file, or a successor image.
The independent backend is `seed_owned_backend.hepta`; its 39 owned and 69 chain
original programs were compared with the original general Core backend before
this allocator layer was added.

## Ownership and physical calls

`cold_allocator_witness.hepta` owns the original 16 counters, first-free live
records, monotonic logical identities, NULL injection, event records, allocation
and free accounting. Its closed 64-byte `HIACAW01` protocol has operations begin,
before calloc, before malloc, remember actual result and before free. The
mechanical bridge calls actual libc only when this policy returns the matching
action. Node allocation remains malloc for the independent backend and calloc
for the target compiler. Neither route changes the process-wide allocator.
The original C witness is an independent development comparator only.

The output span is the original 128-byte counter header followed by 32,768
32-byte events. Private state holds 16,384 live records. Failure does not
simulate destruction after an abort or illegal-instruction signal. The bridge
retains the output mapping so the supervising process observes actual writes.

## Pure HIA construction

All seven HIA components are assembled, projected and compiled by the published
independent assembly/projector/div-seed roots. The generic HIA filter packer
constructs their executable filters. No target compiler, cc, GNU ld or Python
child is used by that construction or its resulting observer processes.
Authoring Python and assembly files explain the checked-in HIA source; final
native reproduction reads those HIA sources and the declared mechanical bytes.

1. `cold_allocator_bundle.hepta` accepts `HIACAWP1`, policy length, fixture object
   length, policy flat and ET_REL fixture. It validates the bounded section,
   symbol and relocation records and emits a new general-layout ET_REL. The
   fixture's calloc/malloc/free call sites resolve to the private mechanical
   bridge; bridge libc calls remain real dynamic imports. The only imports are
   abort/calloc/malloc/free/memset/memcpy/memmove.
2. The independently built `elf_shared_linker.hepta` links that object.
3. `cold_allocator_bind.hepta` validates the actual shared-object segments and
   mechanical prefix, adds one private zeroed RW page after the RELRO page, and
   patches the single context-cell address. Existing RELRO protection remains.
4. `cold_allocator_observer_packer.hepta` accepts the raw observer policy flat,
   emits its mechanical loader ET_REL, and `cold_observer_linker.hepta` links it
   to a complete dynamic executable. This linker is a separately named finite
   extension of the shared-linker algorithm: one `_start` export at offset zero,
   exactly the five imports `__libc_start_main`, `dlopen`, `dlsym`, `dlerror`,
   `exit`, and explicit PHDR, interpreter, non-executable stack and RELRO.
   It accepts the original observer packer's relocation flags 0 or INFO_LINK
   and undefined NOTYPE or FUNC tags. No existing linker profile is broadened.

## Observer ABI

Standard input is four little-endian words followed by the complete bound SO:

| Offset | Meaning |
| --- | --- |
| 0 | eight bytes `HIACAO01` |
| 8 | image length, 1 through 4 MiB |
| 16 | allocation failure index, 0 through 10,000 |
| 24 | explicit inherited auxiliary FD, 3 through INT_MAX |
| 32 | SO image bytes |

The auxiliary regular file must have **exactly 1,048,712 bytes**. Offsets 0..7 are
the program's original eight output bytes; offsets 8..135 are the original
16 counters; offsets 136 onward contain all 32,768 event slots. The observer
initializes output to A5 and the counter/event region to zero. The observed
program still receives input length zero, output length eight and workspace
length zero. Its ABI and primary-output budget are unchanged.

The observer seals its image memfd before dlopen, resolves f0 and hia_test_begin,
then uses the original resource limits: CPU 10 s, address space 256 MiB, stack
8 MiB, file size 16 MiB, 32 FDs and no core dump. Normal stdout is 32 bytes:
`HIAOBR03`, raw 64-bit return, elapsed nanoseconds, and the eight output bytes.
A trap retains the real SIGABRT (independent general route) or SIGILL (target
route), empty stdout, and all actual auxiliary writes. The caller enforces the
original 20-second invocation wall limit and outer cold deadline.

The native driver owns this FD as an exact-size class-4 auxiliary resource, not
as primary shared output. After termination, including a signal, it snapshots
and seals the entire auxiliary object before event validation and archival.

## Native event validation

`cold_allocator_validate.hepta` reads an 80-byte contract header plus the full
auxiliary object. Header words are `HIACAV01`, exact auxiliary length, expected
attempts, successful allocations, frees, failure index, forced failures,
normal-return flag, expected failed allocator (0 none, 1 calloc, 2 malloc), and
the expected eight output bytes. These facts come from the original fixture
contract, not from the target result.

It replays every recorded event, checks unique nonzero allocation identities,
matching live free identities and sizes, failure position and allocator,
counts, zero forbidden counters, live-byte conservation and peak bytes. All
16 header fields and every event slot remain in the immutable artifact. On
success it emits the 136-byte actual output-plus-counter prefix. Refusals do not
write any output. Unused event slots are retained and are not treated as extra
semantic events.

## Evidence and remaining integration boundary

The provenance JSON records source and executable pins and exact evidence paths.
The original seven allocator programs passed 35 development native arms. Each
new HIA-witness arm was byte-identical to its corresponding C-witness counter
and complete 32,768-slot event file. The 5,000-node control made 10,000 actual
allocations and 10,000 actual frees with 20,000 events; HIA witnessing used
approximately 0.6 seconds under the unchanged 10-second CPU limit.

The complete native observer then passed all 14 independent/target arms with
one execve, no execveat descendants, no Python and no cc/ld. Eleven malformed
observer invocations were rejected. Fifty additional linker, binder and event
validator refusals preserve transactional output. The actual HIA event gate
accepted all 14 complete auxiliary files. A fresh independent complete HIA VM
executed all seven original sources with 10,000,000 steps, 256 frames, 16 MiB
heap and each original failure index; the largest used 70,019 steps.

An early executable-link experiment lacked PT_PHDR and faulted before main;
its failed artifact and debugger trace are retained separately. The final
linker supplies the load-bias-bearing PHDR and passed actual processes. This is
a new native cold component boundary, not a claim that the old Python-isolated
v1 cold proof has automatically passed or that the whole 19-group campaign is
already complete. The outer native master and original/modified phase plans
must still compose and check these actual artifacts.
