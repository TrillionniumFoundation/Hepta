# Native Linux host interface qualification

This finite profile exercises actual Linux `eventfd` handles and pthread
workers around Hepta's existing scalar C ABI. The host owns the handles,
threads, queue and cancellation flag. The callback owns a private byte buffer.
It adds no foreign syscall opcode or unrestricted shared-memory concurrency to
the Hepta Core language.

## Two explicit cohorts

```sh
python tools/qualify_hia_linux_interfaces.py --mode host-reference \
  --native-host x86_64 --output /tmp/hepta-linux-host-reference

python tools/qualify_hia_linux_interfaces.py --mode hepta --clang clang-20 \
  --native-host x86_64 --output /tmp/hepta-linux-host-native
```

Run the same commands with `--native-host aarch64` only on an actual supported
AArch64 Linux host. The requested cohort must match the independently measured
executing machine and the compiled C ABI probe. Cross-compilation does not
grant execution qualification.

The **host-reference** cohort compiles an independent C callback with the real
GNU C compiler. It qualifies this host harness and its real interfaces, while
`hepta_native_abi_qualified` stays false. The **hepta** cohort lowers the checked
Hepta source through the existing Core-to-LLVM backend, builds a target object
with actual supported Clang, and links that object to the same GNU C host
harness. It excludes `reference.c` from the linked implementation. Missing
Clang or unsupported lowering fails this cohort; it does not substitute C.

The executable's actual ELF machine is checked against the host. Execution
uses inherited sealed memfd bytes rather than the mutable output pathname.
The fixed harness creates threads and no child processes; timeout kills the
owned process and its threads. CPU, address-space, descriptor and regular-file
output limits bound the run. This is not an arbitrary hostile-code sandbox.

## Executed cases

Each batch has three real workers and sixteen jobs. A first-job pthread barrier
requires all three workers to participate and establishes overlapping job
lifetimes. This is concurrency evidence, not a parallel-speedup claim.

Eleven primary cases cover normal operation, allocation refusal at attempts one
and three, failure to acquire either eventfd, failure to create the first or
second worker, a retryable read interruption, a retryable completion-write
interruption, a nonretryable completion-write error, and cooperative
cancellation after one completed job. Each of the ten nonbaseline cases is
followed by a complete recovery batch in the same process: **21 batches total**.

The startup and I/O failure results above are explicitly injected at the host
wrapper. Separately, a real eventfd receives an empty read, an invalid
`UINT64_MAX` write, and a write beyond its saturated counter. The observed
kernel `EAGAIN`/`EINVAL` results and the drained counter are checked.

The independent Python checker validates the exact case inventory, scalar
results, actual worker identities, completion and cancellation counts,
injection counts, acquired/closed handles, created/joined threads, process FD
and thread counts before/after each batch, allocation attempts/refusals/frees,
and zero live callback owners/bytes. A C harness leak terminates the process;
resetting its counters cannot hide a leak from the following recovery batch.

After joining, Linux procfs may briefly retain an exiting task directory. The
harness retains the first post-join task count and the number of one-millisecond
polls needed to observe one remaining task. More than 1000 polls, an invalid
count, or a remaining task fails the batch. This finite quiescence observation
does not replace the independent requirement that every created thread was
successfully joined.

The allocation meter wraps direct linked component `malloc`/`calloc`/`free`
calls and records requested payload bytes. It excludes libc/pthread internal
allocations, allocator metadata, stacks and RSS. Its peak is a measured value
for these finite jobs, not a general resource-bound theorem. Exceptions are
failure-as-value or cooperative stop: no asynchronous pthread cancellation or
destructor cleanup after abort is claimed.

## Retained evidence and limits

`REPORT.json` records source/compiler/artifact hashes, native host and compiled
ABI, actual link inputs, sealed execution status, checked case observations and
explicit claims. The complete Python package source set is hashed before and
after execution, and Hepta mode additionally binds Core, LLVM, implementation,
toolchain and object bytes to the native receipt. `RAW.jsonl`, build logs, the precise source copies and the
native artifact are retained beside it. Unknown, malformed, duplicated,
truncated or inconsistent observations cannot grant qualification.

This profile does not qualify physical devices, DMA, MMIO, hardware interrupts,
kernel drivers, RV64/QEMU execution, arbitrary concurrent Hepta programs,
backend refinement, universal resource safety, or performance superiority.
Those claims remain false in both cohorts. Actual Hepta native qualification
belongs only to a successful **hepta** run on its recorded architecture.
