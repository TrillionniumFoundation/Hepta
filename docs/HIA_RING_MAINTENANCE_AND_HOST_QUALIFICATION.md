# Existing-project maintenance and bounded host qualification

This track exercises an existing upstream C project through its original build
and public interface, then measures a separately frozen strong-baseline
comparison. The implementation route is **Clang AST → checked Hepta → Rust
reference backend → C ABI library**. These observations do not extend the
standalone HIA Core proof or establish general C/C++ translation correctness.

## Actual upstream maintenance cycle

The upstream is [AndersKaloer/Ring-Buffer](https://github.com/AndersKaloer/Ring-Buffer).
Both complete source trees are retained as content-addressed blobs under
`tests/fixtures/c_migration/ring_buffer_maintenance`. The verifier reconstructs
the entire Git tree, including executable file modes, and checks the pinned
commit, tree, blob, SHA-256, byte length and complete file inventory.

| Revision | Immutable commit | Complete Git tree |
| --- | --- | --- |
| Before | `1468e24fc55986d7c432d1d26115e3b28f985fe0` | `bcf333c0428cb28cd6b2296a7fc24d9d9b21b177` |
| After | `8de8fff55a0baee4fef2a1c6a82d258a27c3c0ba` | `c65911bc45ec4914cff55f5fd422bad7c5694270` |

The actual upstream change is [PR 17](https://github.com/AndersKaloer/Ring-Buffer/pull/17):
`examples/tail.c` stores `getchar()` in `int` and uses a separate `char` for the
dequeued byte. On the observed signed-char host, the old caller mistakes byte
`0xff` for EOF. Its output for input `61 ff 62` is `61`; the updated caller
outputs `61 ff 62`. The qualification requires both behaviors in their proper
revision. It does not silently fix the historical program before testing it.

Each tree contains 12 regular files. Only `examples/tail.c` changes between
these revisions. `ringbuffer.c`, `ringbuffer.h`, `examples/Makefile`, the other
client, license and project files remain byte-identical. The pinned revisions
are actual commits; they are not described as tagged releases.

### Build and migration boundary

For each revision the harness materializes two complete upstream trees and
runs the unchanged `make all tail` build. The original build uses its own GCC,
`-Wall -g -O2 -std=c99` settings, Makefile and clients. The migrated build uses
the same Makefile and flags with a narrow `CC` integration wrapper. That wrapper
substitutes the generated implementation library for exactly the expected
`ringbuffer.c` argument. It preserves the original client sources, output names,
header and remaining arguments, records the compiler invocation, and refuses
changed compiler/source/library identities or multiple implementation inputs.

The actual module migration covers nine function definitions and the complete
22-declaration active inventory. Six bodies originate in `ringbuffer.c`; three
are inline helpers in the public header. No `ringbuffer.c` implementation body
is linked behind the migrated entry points. The unchanged C example clients
may still inline the three original header helpers. The dynamic qualification
host uses `dlsym` for all nine APIs, so those measurements actually enter the
selected implementation for every operation.

The two original clients remain C. The Rust code is emitted from checked Hepta
and includes generated C ABI wrappers. This is implementation migration of the
ring module with a boundary adapter; it is not a rewrite of all original project
code, a C++ bridge-upgrade result, or a standalone HIA aggregate-ABI result.

The source capture explicitly uses C11, `NDEBUG` and `-funsigned-char`. The
original clients retain their original C99 signed-char configuration. The
common low-byte calling behavior is exercised on the measured x86_64 SysV ABI,
including every possible one-byte input; no cross-target ABI theorem is inferred.
The caller-authored record/view contracts remain necessary for pointer validity,
extent, lifetime and synchronization. They were not inferred from foreign code.

### Finite maintenance observations

The frozen protocol is
`experiments/ring_maintenance/PROTOCOL_20261030.json`.

- Both original `simple` programs and both migrated `simple` programs execute
  with their original assertions enabled and byte-equal output per revision.
- The original `tail` client and the migrated implementation execute 327 inputs
  per revision, including all 256 individual byte values, the historical `0xff`
  regression, empty inputs, wraparound inputs and 64 seeded additional inputs.
  That is 1,308 actual `tail` processes across both routes and revisions.
- Each revision executes 2,048 state transitions over capacities
  1, 2, 4, 8, 16, 32, 64 and 256. The independent deque oracle also checks returns,
  all scalar state, every backing byte, output sentinels, input preservation and
  backing-pointer identity. There are 8,200 paired API observations and 16,400
  native entry invocations per revision.
- Migration runs freshly for both revisions. The emitted Hepta bodies and ABI
  bridge must remain identical because the upstream module itself is unchanged.
  The real upgrade affects the retained original caller. A future upstream
  implementation or ABI change remains a separate maintenance qualification.

`manual_migrated_body_edits: 0` describes the generated bodies. Human contract
authoring, review and maintenance hours remain `null` / not measured. Actual
machine wall time, coordinator CPU time, completed child CPU time and native
commands are recorded by stage. Machine timings are not converted to human
hours or claimed labor savings.

## Actual host, concurrency, resource and recovery scope

The admitted profile is the actual Linux x86_64 little-endian LP64 host. C and
Rust probes compare the record size, alignment and four field offsets. The
native host separately records pointer width, `size_t` width, signed `char`,
byte width and endianness. Foreign readable extents and lifetimes remain caller
obligations, even when an address passes the wrapper's local checks.

| Profile | Ownership and synchronization | Actual operation |
| --- | --- | --- |
| One thread | One caller-owned record and buffer | Original nine-function C ABI |
| Four disjoint records | One independent record/buffer per pthread | Concurrent calls into the same loaded implementation |
| Four serialized threads | One record/buffer under a host `pthread_mutex` | Mutex wait plus complete queue/dequeue transactions |
| Invalid boundary | A separate child for each invalid call | Native `SIGABRT`, parent `waitpid`, then a valid parent roundtrip |
| Owned storage failure | Separately authored Hepta `Buffer` client | Actual allocator refusal, early return and zero live allocations |

The shared-record profile requires the external mutex. It does not establish
lock-free safety or unsynchronized shared mutation. The forked failure tests
establish recovery by process isolation, not in-process recovery from an aborted
Rust ABI call. The nine cases are null/misaligned record, record/storage overlap,
input/storage overlap, output/storage overlap, extent overflow, invalid index,
null storage and zero capacity. Invalid original C calls are not executed as a
purported safety baseline.

The upstream ring module owns no heap allocation. Allocation-failure evidence
belongs to the explicitly separate owned-storage client. All six native owner
calls require zero live allocations after success, early exit or refusal.

### RSS and latency measurement

For each of three concurrency profiles, seven paired fresh processes per arm
execute 128 batches per thread and 128 transactions per batch. Every transaction
has an independent byte/sentinel oracle. A small native fork/exec supervisor
obtains the child's actual `wait4` peak RSS and retains supervisor and child
pre-exec memory floors; Python coordinator RSS is not substituted for child RSS.

The retained `batch_ns` values use `CLOCK_MONOTONIC_RAW`. Reported batch p99 is
the p99 of complete 128-transaction batches, including mutex wait where relevant.
It is not per-instruction latency or a worst-case bound. Whole-run timing also
includes pthread creation/join and synchronization cleanup. The host is shared,
has no exclusive CPU reservation, and no statistical significance or universal
performance claim is made from these descriptive samples.

Device evidence is limited to the host C ABI, pthreads, processes, signals and
memory observations actually exercised. No physical board, GPU, MMIO, DMA, ISR,
AArch64, RISC-V or WCET qualification is claimed.

## Strong static comparison on newly frozen traces

`experiments/ring_optimization/PROTOCOL_20261030.json` is a separate prospective
protocol. It freshly migrates the same real upstream implementation, then builds:

| Arm | Fixed build |
| --- | --- |
| Clang native LTO | `-O3 -march=native -flto`, Unix LLD, no semantic interposition |
| Clang native IR-PGO + LTO | Same flags, actual IR instrumentation, training and profile use |
| GCC native LTO | `-O3 -march=native -flto`, no semantic interposition |
| Hepta → Rust native LTO | Same newly emitted Rust body, `opt-level=3`, native CPU, fat LTO, overflow checks and aborting panic |

The three authored API trace profiles are small transfers, bursts, and transfers
near capacity. Each trace has 4,096 records. Training uses seed `1708132849` and
four passes. After all final candidate identities are frozen, held-out generation
uses seed `2097394567` and sixteen passes. All four arms execute the same held-out
bytes and independent byte/sentinel/checksum oracle. Five rotated/reversed paired
groups produce 60 actual held-out processes and 983,040 transactions per arm.

The traces are new and not executed or timed during candidate construction.
They are authored workloads of a real library, not a production traffic capture
or an independently blinded external workload. No candidate or flags are tuned
after observing these results. LLVM profiles must contain positive real IR
counters for all nine named APIs; stale/unprofiled-profile diagnostics are fatal.
Held-out data is never used for PGO training.

The strongest single static C arm is selected by the preregistered minimum sum
of per-profile median process wall times. All candidate and baseline observations
remain in the report. The cost ledger then subtracts the entire measured
non-held-out campaign cost from actual matched-group process-wall savings.
Preparation, fresh translation, checking, native builds, baseline builds,
training, profile validation, observation, selection and named scratch cleanup
are charged once. Every process includes actual input loading, `dlopen`,
output consumption, free, `dlclose`, supervisor and output-capture costs.

The ledger reports a **net-benefit upper bound** over the workload actually run.
Additional human effort, unavailable end-to-end refinement proof and final
artifact publication costs are unknown and remain explicit. If that upper bound
is nonpositive, those additional costs cannot turn the run into a net benefit.
No unexecuted future call horizon is counted as an achieved saving. A negative
result leaves the requested net-optimization gate open.

## Guarantee boundary

| Boundary | Evidence supplied here | Remaining trust or exclusion |
| --- | --- | --- |
| Upstream identity | Two complete reconstructed Git trees and immutable blobs | Trust in the pinned upstream provenance |
| C → Hepta | Complete declaration inventory and finite state/byte oracles | Translator and caller-authored contracts; no equivalence theorem |
| Hepta ownership | Source checker and actual Rust compilation; owner fault observations | Checker and Rust toolchain implementations |
| Standalone HIA Core | No new proof claim from this track | Rust reference route does not inherit a standalone-Core theorem |
| C ABI | Actual layout and native original-header callers on this host | Foreign pointer lifetime/extent and target-specific ABI |
| Native execution | Retained commands, artifact hashes, child signals, RSS and timing | Compiler/linker/runtime/OS/hardware trusted; finite observations |
| Concurrency | Disjoint ownership or external mutex, exercised pthreads | No unsynchronized shared-state or device-concurrency proof |

## Reproduction and retained evidence

Use a fresh output pathname for every run. The tools reserve that pathname,
retain failed attempts, and reject source changes during execution. For published
evidence pass the exact committed source SHA with `--source-sha`.

```sh
python3 -m unittest tests.test_ring_maintenance_qualification tests.test_ring_optimization_qualification -v

python3 tools/qualify_ring_maintenance.py \
  --output /tmp/ring-maintenance-new-run/qualification.json \
  --clang /usr/lib/llvm-20/bin/clang \
  --rustc /path/to/rust-1.90.0/bin/rustc \
  --source-sha COMMITTED_SOURCE_SHA

python3 tools/qualify_ring_optimization.py \
  --output /tmp/ring-optimization-new-run/qualification.json \
  --clang /usr/lib/llvm-20/bin/clang \
  --rustc /path/to/rust-1.90.0/bin/rustc \
  --profdata /usr/lib/llvm-20/bin/llvm-profdata \
  --linker /usr/lib/llvm-20/bin/ld.lld \
  --source-sha COMMITTED_SOURCE_SHA
```

The Unix LLD invocation basename is retained: `ld.lld` is a flavor-selecting
driver, so replacing its invocation path with the resolved `lld` filename changes
its behavior. Tool bytes are hashed without rewriting that invocation identity.

`tools/export_ring_qualification_evidence.py` validates every retained artifact
against the completed run before creating a compact archive. It preserves the
complete original report, all actual commands, exact stdout/stderr bytes, full
state/resource observations and generated text. Executables, trace files and
binary profiles are omitted with explicit names, sizes and hashes; deterministic
traces are reproducible from their protocol and seeds. The short result JSON
binds the archive hash and exact source commit.

Published machine summaries and full receipt archives belong beside their
respective protocols under `experiments/ring_maintenance` and
`experiments/ring_optimization`. Their `ok` field means that the registered
qualification completed. The separate `claims` and cost ledger determine which
engineering claims the observations support.
