# HIA-emitted native byte-ABI observer (bounded qualification transport)

This is **not** whole-stack retirement, a production backend activation, a
security sandbox, or a proof for arbitrary machine images. Host supervision,
oracles, B0, shared-library loading, linking and release tooling remain outside
HIA. The fixed ISA adapter is authored as literal Linux x86-64 instructions; its
transparent assembly reference is `tools/hia_native_observer_template.S`.
Neither assembling that reference nor host construction of its ELF is part of
the actual native observer build.

## Actual build and trust boundary

`examples/hia_bootstrap/native_observer_packer.hiaasm` is executable HIA. Before
B0, independent Core VM executions of that exact packer observe disjoint output
windows and compare **every** ELF byte against a separate header/adapter oracle.
The bounded Core return-list limit is retained. After B3 has been generated,
that real HIA compiler compiles the packer. Executing the resulting flat HIA
image writes the complete static ELF; the result must equal the VM observation.
There is no cached native observer or host compiler fallback.

A phase request explicitly binds the observer's content alongside the compiler,
source and independent references. Each ordinary flat-ABI invocation execs a
fresh, sealed memfd containing those exact ELF bytes. The resulting child has
no ELF interpreter, libc, Python runtime, payload parser, verifier, compiler or
linker. It maps only the supplied image RW, copies it, changes that mapping to
RX, calls the six-argument SysV byte ABI and exits. It never reuses a child.
B1/B2/B3, M1/M2/M3 and baseline controls retain the independent stdlib loader.
Shared/seed ELF calls retain that loader. Custom output preimages and real
post-trap captures now use parent-owned, size-sealed shared memfds, mapped
MAP_SHARED by each fresh native observer. The parent reads the actual mapping
after the child has terminated, independently of the stdout return protocol.

## Binary protocol and unchanged limits

Input is `HIAOBS02` followed by six little-endian u64 words: flat-image bytes,
source bytes, output capacity, workspace bytes, workspace fill byte and output
file descriptor (`2**64-1` for private A5 output; otherwise an explicitly passed
descriptor >=3 and <=2**31-1). Exact image
and source bytes follow. Image length is 1..4 MiB; source/output/workspace retain
the existing 0..1 MiB limits; fill is 0..255. The adapter rejects truncated,
extra, oversized and overflow-valued frames without execution or output.

On normal return, stdout is `HIAOBR02`, full u64 return, native monotonic elapsed
nanoseconds, actual source bytes after the call, complete output, and workspace.
The parent compares actual source bytes, all output bytes and actual workspace
header values, never assumes source immutability from an identity hash. Output
starts as A5; workspace starts with the requested fill, including poisoned fills.
Unexpected stdout/stderr or response length fails closed and retains exact raw
failure bytes. Actual source mutations also retain the changed source bytes.
Signals remain kernel signals; no trap is caught or converted into success.
Shared output extents are sealed against shrink/growth before exec, while their
actual bytes remain writable. A real SIGILL retains all prior writes in that
mapping; no handler, crash emulator or predicted-output substitution is used.
Returned stdout output must agree with the actual shared bytes. Descriptor
ownership is scoped even if prelaunch storage fails.

The adapter installs and checks the same resource bounds as the retained loader:
10 CPU seconds, 256 MiB address space, 8 MiB stack, zero core limit plus actual
non-dumpable state, 16 MiB file size and 32 file descriptors. The parent retains
the 20-second per-call timeout; the outer cold gate remains 180 seconds plus its
separate 3-second cleanup bound. No compiler capacity or qualification witness
is removed. The two host-oracle workers remain two.

## Reviewable finite controls

Tests execute the actual HIA-emitted ELF and compare with the independent
legacy loader: full 64-bit returns, all captured output and workspace headers,
zero/varied capacities and workspace fills, actual compiler success/refusal,
source mutation, real SIGILL, prior writes retained after SIGILL via native shared
mapping and independently compared with the legacy loader, observed kernel CPU limits/non-dumpability, malformed frames, injected
native stdout, actual memfd extent seals and prelaunch ENOSPC cleanup. This is finite evidence, not all-input equivalence or a complete
production runtime replacement. Old CI timeouts remain failures; local timing
observations do not establish a remote performance guarantee.


## Standalone JSON CLI execution composition

The combined development continuation compiles an actual JSON Core byte program
with the standalone HIA CLI, then invokes the resulting flat image through this
fresh observer while the legacy child helper is disabled. Three actual inputs
retain the independent checksum and output observations. A separate real
syscall trace checks the full returned source/output/workspace frame: the sample
deliberately writes both mutable views, not just stdout. The observed syscall
set is execve/prctl/prlimit64/mmap/mprotect/clock_gettime/read/write/exit, with one
initial exec and one RW-to-RX transition, no runtime interpreter/libc/file
dependency. Parent supervision and all stated trust boundaries remain unchanged.

Independent VM observations of every observer ELF byte occur before that test
builds B0; actual HIA compilation/emission produces the observer used. Initial
development incorrectly expected an unchanged workspace fill; source review
confirmed two explicit stores, and both resulting bytes are now checked. The
failed oracle attempt remains retained. These finite development observations
require fresh committed combined qualification; older independent receipts are
not promoted to that source.
