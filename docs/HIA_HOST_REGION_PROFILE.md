# Host-owned external regions: bounded memory and recovery profile

`hepta/hia_host_region.py` implements a Linux x86-64 host boundary for fixed
RAM regions used by reviewed synchronous C functions. It executes real memfd,
mmap, mprotect, threads, loader admission, C ABI calls, and retirement. It does
not add an unsafe foreign-pointer export to Core or claim a theorem for a
concurrent Hepta language.

## Ownership and kernel authority

`HostRegion(length)` creates its own anonymous memfd and shared mapping. It
accepts neither a caller-supplied raw address nor a caller-supplied descriptor.
The logical extent is 1 byte to 1 MiB; the actual mapping rounds up to a page.
The process registry retains at most 16 region owners, including quarantined
and unresolved-close owners. Forgetting an owner does not reclaim its memory
under a possible native call. Registry bounds cover region mappings and owned
capability counts, not all Python/native memory, OS thread stacks or process
RSS.

The kernel must accept and read back all four seals:

| Seal | Purpose |
| --- | --- |
| `F_SEAL_SHRINK` | A region's extent cannot shrink beneath a borrowed range |
| `F_SEAL_GROW` | The registered extent cannot silently expand |
| `F_SEAL_FUTURE_WRITE` | After creating the retained mapping, descriptor writes and future writable mappings are forbidden |
| `F_SEAL_SEAL` | The seal inventory cannot subsequently change |

Existing mapping writes remain possible under the exclusive-write lease.
Actual `mprotect` transitions grant `PROT_READ` to shared readers,
`PROT_READ|PROT_WRITE` to the unique writer, and `PROT_NONE` when no lease
remains. Executable permissions are never requested for data. Permissions
apply to the complete region, so even disjoint writes are conservatively
exclusive. Snapshots read the actual kernel mapping permission string; they do
not disclose a raw address or data fd.

Each lease is registered by object identity and generation. Read operations
return immutable copies. Host writes require an exact immutable `bytes` object
matching the leased extent. A copied, forged, foreign, closed or stale lease
does not acquire authority. Releasing an old lease is allowed so quarantine
can drain existing holders; using that lease after generation revocation is
not allowed.

## Native integration and the trusted FFI contract

`NativeRegionLibrary` takes an explicitly reviewed artifact hash and an exact
`TrustedRegionContract`. It reuses the production HIA native boundary:

1. `_pin_native_artifact` reads the original regular file under identity checks
   and copies its exact bytes into a fully sealed executable memfd.
2. `verify_loaded_symbols` checks that actual resolved entry addresses map the
   held sealed file in nonwritable executable mappings. A pathname or claimed
   hash alone does not identify loaded code. The check runs again at call
   admission.
3. `_NativeRelease` retires the held loader reference and code descriptor at
   most once. Uncertain loader/descriptor release is retained as ownership
   debt; a numeric descriptor is never retried after possible reuse.

The admitted function ABI is:

```c
int entry(uint8_t *region, size_t length, uint64_t argument, uint64_t *result);
```

Each reviewed entry declares `read` or `write`. A read declaration may use
`const uint8_t *` in its C source. The implementation must honor the declared
permission and extent, use the output pointer only during the call, and retain
neither pointer after returning. It must not start detached work using those
pointers. Unknown pointer retention is rejected before loading. This contract
is a trusted host assertion about reviewed native code; a hash or Python
dataclass cannot prove arbitrary C safe. Arbitrary constructors, global data
races, out-of-range accesses and falsely declared permissions are outside this
profile.

The qualifier's C bridge links `benchmarks/hia_host_region/scalars.hepta`,
compiled through the existing verified Core-to-LLVM native path. Real C buffer
reads and writes call the resulting `hia_region_fold` and `hia_region_byte`
scalar exports. Thus the exercise composes the hosted resource boundary with
actual HIA native code. Core itself still exposes only its supported scalar
foreign ABI; this profile does not import raw pointer ownership into its
static verifier.

## Limited memory model

This is a threads-in-one-process model for ordinary coherent x86-64 RAM.
It assumes CPython's owned thread start/join and mutex synchronization, the
Linux memory/loader interfaces, the native compiler, and the reviewed C ABI.

| Operation | Ordering and permission |
| --- | --- |
| Borrow admission | The owner mutex checks the exact generation, state, bounds, lease budget and reader/writer conflict before issuing a capability |
| Multiple reads | Multiple native readers can execute simultaneously; their region contents remain stable because no writer can acquire a lease |
| Write | One host/native writer excludes every other region lease; host-copy operations also hold the owner mutex |
| Native completion | Only the actual retained worker's completed join releases its internal lease and code-use count |
| Subsequent admission | Admission after that release sees the completed prior writer, under the owner synchronization and trusted thread-join implementation |
| Quarantine | Generation revocation blocks all new work and old-capability use, while in-flight worker memory/code remain retained |
| Recovery | All native workers must be joined and all external leases released; reset happens under exclusive host control before a new generation is issued |

No atomics or lock-free data structures are added to Core. The qualifier uses
C11 atomics solely for its private native-reader overlap counter. No ordering
claim extends to arbitrary shared global state, forked processes, volatile I/O,
MMIO, DMA, accelerator queues or devices. There is no capability to turn a
device address into an ordinary region in this API.

## Uncertainty and recovery

Each native invocation has an owned worker, an internal region lease and a
held code-use count. The ordinary call waits for the actual thread to finish.
A timeout, interrupted join, nonzero native status, callback exception or
revoked generation does not commit a result. It moves the region to
quarantine and preserves the capabilities that the worker may still use.
The runtime does not forcibly terminate a thread or revoke a running worker's
pages and then pretend it returned normally.

`recover(timeout=...)` has a bounded wait. It joins actual recorded workers,
requires confirmed completion, and then requires every external lease to be
released. A report, elapsed timeout, caller-supplied token or generation number
cannot substitute for those observations. The trusted no-escape FFI contract
is what makes worker return/join sufficient to rule out retained native
pointer users. An unreturned function continues to deny reuse; liveness is not
promised.

Successful recovery clears the entire mapping to zero, revokes access again,
and publishes a fresh generation. It discards partial region writes; it does
not restore the previous application value, replay a failed call or undo
external effects. Old callers whose workers were retired by recovery cannot
commit late results or revoke the already recovered generation.

If worker launch itself has an uncertain outcome, the profile permanently
denies reuse and retains the region/code ownership debt. If `munmap`/close or
native retirement is uncertain, the corresponding numeric resource is not
retried. All such debt continues to consume bounded registry capacity. There
is no unsafe automatic fallback from permanent denial to a recycled pointer.

A C signal or abort can terminate the host process. This API is not a sandbox
for untrusted native code. The read-permission violation in the qualifier is
therefore deliberately executed in a separate disposable process: the actual
kernel protection must produce `SIGSEGV`, and the parent records that failure.
It is not described as successful in-process recovery from arbitrary native
memory corruption.

## Executed qualification and reproduction

The native qualifier covers successful HIA/C calls and exact subranges, real
read/write/no-access kernel permissions, fd write seals, two overlapping native
readers, exclusive-write denial, active-code/region-retirement denial, stale
generations, timeout quarantine, early-recovery denial, joined recovery,
partial-write failure, and recovery blocked by a retained external lease.
An independent negative process attempts a write under a read contract and
must exit with `-SIGSEGV`.

Additional unit controls cover forged/copied leases, finite ownership budgets,
fd resize refusal, unknown retention contracts, digest mismatch, changed
publication paths after executable pinning, uncertain close after the real fd
was already closed, and a worker-start exception after the real thread was
already started. The two latter controls are isolated so their intentionally
permanent ownership debt does not pollute the test runner.

```bash
python -m unittest tests.test_hia_host_region -v
python tools/qualify_hia_host_region.py --output /absolute/new/evidence/directory --clang /absolute/clang
```

The qualifier retains the source combination, Core/native compilation receipt,
actual compiler streams and argv, shared artifact hash, loaded-mapping
identities, kernel observations, fault-child stdout/stderr and exit status,
and final resource-retirement records. A final integrated run must use the
same frozen source combination as the other project qualifications.
