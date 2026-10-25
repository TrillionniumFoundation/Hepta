# Owned application costs and request latency

`tools/benchmark_applications.py` compiles and executes two bounded, deterministic
application workloads. It records allocation/cleanup costs and every measured
request latency through three native implementations:

| Implementation | Application source | Native code |
| --- | --- | --- |
| `hepta_rust` | `benchmarks/applications.hepta` | Checked Hepta → Rust → pinned rustc |
| `hepta_c` | The same Hepta module | Independent ownership-checked Hepta → C11 → GCC |
| `rust` | Separately handwritten `benchmarks/applications.rs` | The same pinned rustc as Hepta/Rust |

These are three compiled implementations and **two independently authored
application source implementations**. The two Hepta builds share their source
semantics. The independent Rust program uses fallible `Vec` allocation,
iterators, slices and normal RAII cleanup. None of the application bodies is
replaced with an oracle or a generated timing fixture.

## Workloads and ownership

### Framed packet ingestion

Each request creates an owned wire buffer containing fixed-size frames and an
owned 256-byte histogram workspace. Frames contain a little-endian payload
length, a kind, a checksum and 60 payload bytes. The application generates the
deterministic input, parses all headers, verifies each payload checksum,
aggregates counts by kind and computes a content hash. It destroys both owners
before returning its scalar result.

The frozen request schedule contains five successful requests and three
malformed requests per group of eight. The malformed requests respectively
change a middle frame's length, payload checksum or kind. Early errors report
the processed prefix and its hash and still release both buffers. Two distinct
allocation-refusal phases test failed wire allocation and failed histogram
allocation after wire ownership has been acquired.

### Chunked transform and hashing

Each request creates an owned input buffer with a four-byte format header.
After validation it acquires a 256-byte scratch buffer and an owned output
buffer. It processes input in 256-byte chunks with a rotate/XOR stateful byte
transform, reverses each transformed chunk into the output and computes the
output hash. All three owners are destroyed before returning.

One request in eight has an invalid header and releases its input before
allocating scratch/output. Allocation failures at the first, second and third
phases exercise every acquired-owner cleanup prefix. A successful native request
follows each injected refusal in the same process to verify recovery.

The common external interface uses scalar inputs and a 32-byte `repr(C)` result.
The applications do not receive raw foreign input pointers. These are authored
application workloads with generated data; they are not third-party network
services or a representative sample of all production software.

## Default qualification denominator

```sh
python tools/benchmark_applications.py \
  --output artifacts/application-benchmarks.json
python -m unittest tests.test_application_benchmarks
```

The output path must be new. Failed qualification attempts retain their partial
records and error, and cannot overwrite earlier reports. Missing compilers,
failed native builds, wrong outputs, missing cleanup and incomplete timing
matrices fail qualification. There is no synthetic timing fallback.

| Part | Default execution |
| --- | --- |
| Source/native correctness | 3 implementations × 2 applications × 5 boundary/small sizes × 8 request IDs = **240 requests** |
| Real allocation failure and recovery | 3 implementations × 5 allocation phases × 2 consecutive requests = **30 requests** |
| Timing | 3 implementations × 2 applications × 3 sizes × 3 trials × 96 requests = **5,184 requests** |
| Warmup | 16 checked requests before each timing batch |
| Incorrect native implementation | Separately compiled and linked executable rejected by the same native oracle |

The sizes are 1, 32 and 1,024 work units. Packet wire sizes are 64 B, 2 KiB and
64 KiB. Transform payload sizes are 256 B, 8 KiB and 256 KiB, with a separate
four-byte input header. Correctness also includes zero units and the first
rejected size beyond the declared 4,096-unit limit.

Request IDs start at the frozen seed 20,261,024 and retain the same values across
all three implementations. Implementation execution order rotates by workload,
size and trial. Where the host exposes CPU affinity and `taskset`, all measured
child processes use one allowed CPU. This does not provide an otherwise idle or
exclusive machine.

## Correctness oracles and native control

Every warmup and measured request is checked by a separate C oracle in the
common native driver, outside its timed interval. The transform oracle streams
input directly into its final reverse positions, independently of the
application's input/scratch/output staging. Every small/boundary correctness
request and every failure/recovery request is also checked by a separately
written Python oracle. Timing records must agree across all three native
implementations for each paired request ID.

`applications_wrong.c` is an actual incorrect implementation, not a mocked
report. It is compiled, linked with the same driver and allocator instrumentation
and executed. The driver must reject its result with the designated oracle
failure exit code. An always-passing or skipped oracle cannot satisfy this
control.

## What the latency includes

The same C driver calls each application through the same scalar C ABI. Each
timed interval includes the call, input generation, application allocations,
validation, processing, cleanup and allocation instrumentation. It excludes
native build, process startup, warmup, the independent oracle, transcript output
and RSS queries. No LTO combines the driver with an application body.

Both Rust implementations use the same pinned compiler with `opt-level=3`,
overflow checks enabled and `panic=abort`. The independent C backend retains its
default `-O3` profile, checked source arithmetic/bounds, `-ffp-contract=off` and
`-fno-strict-aliasing`. The C optimizer differs from rustc's optimizer. The
benchmark does not silently switch to the optional unroll profile.

The common allocator instrumentation has measurable overhead. Therefore these
records do **not** claim uninstrumented production latency. The timer's observed
minimum back-to-back read duration is retained for context and is not subtracted
from samples. Every raw interval is retained without outlier deletion.

For each application/size/implementation the report recomputes min, p50, p95,
p99, maximum and mean from all 288 default request samples. Quantiles use the
nearest-rank definition. It also reports each status separately, so differences
between successful requests and shorter error paths remain visible. A p99 from
288 observations is a finite descriptive statistic; it is not a reliable
long-running service tail bound. Smaller status subsets have fewer observations.

Reported service throughput is

```text
number of timed requests / sum of their timed service intervals
```

It does not include the oracle, driver output or request scheduling gaps and is
not externally observed server requests per second. Complete child-process wall
duration is retained separately. No concurrent arrival process, async I/O,
network queue, long-running load or deadline SLO is represented by this suite.

All observed p50/p95/p99/max/mean time ratios above the independent Rust baseline
remain in `all_observed_slowdowns`. A passing correctness/cost qualification does
not require Hepta to win. Regressions are evidence to investigate, not rejected
samples.

## Allocation counters and memory observations

Both Rust libraries install the same benchmark-only `GlobalAlloc` adapter. The
C library reaches the same C instrumentation through linker-wrapped
`malloc`/`calloc`/`realloc`/`free`. A fixed-capacity tracking table performs no
allocations of its own. Input generation and all owned buffers remain inside
the measured application call.

Each request records allocation attempts and successes, explicit frees,
failures, individual allocation-call kinds, attempted and successfully allocated
bytes, freed bytes, peak tracked live bytes and remaining live bytes. These
counts are observed at the native allocator entry points. The byte values are
the requested allocation sizes; allocator metadata, usable-size rounding,
virtual-memory mappings and implicit kernel costs are excluded.

The native driver verifies the complete expected allocation protocol for every
request. Injected failure occurs at the actual allocator entry point. Failed
allocations do not increment successful allocations or live bytes. Every
acquired owner must be freed before the call returns, and every following request
begins with no tracked allocation identity. Ordinary native allocation failure,
an instrumentation-capacity error or a missing cleanup does not become a fake
zero-cost success.

Two separate Linux memory observations are retained:

- `rss_ru_maxrss_kib`: `getrusage(RUSAGE_SELF).ru_maxrss`, with both initial and
  final observations. Linux preserves resource-use metrics across `execve`, so
  this value can retain launcher high-water usage. It must not be interpreted
  as the fresh application's heap usage. See the Linux
  [`getrusage` manual](https://man7.org/linux/man-pages/man2/getrusage.2.html).
- `rss_address_space_hwm_kib`: `/proc/self/status` `VmHWM`, again with initial
  and final observations. The kernel documents it as the resident-set high-water
  value in its [`proc` reference](https://docs.kernel.org/filesystems/proc.html).
  An unavailable observation is explicitly `-1` in the raw process record.

Both include executable/runtime pages, the common driver, warmup and oracle
work. They are process observations and are not attributed solely to the owned
buffers. They are distinct from peak requested bytes in the allocator table.
Neither establishes a whole-process memory budget or multi-machine behavior.

## Evidence validation

`validate_application_report(report)` requires the full default profile:
at least three trials, 96 requests per trial and 16 warmups. Explicitly smaller
development runs cannot pass those defaults. The validator checks:

- Exact current source/compiler identities and all required native builds.
- Re-created Hepta lowering from current source, and the exact allocator source
  appended to both Rust builds; C must report that rustc was not used.
- Common driver/meter objects, library and executable identities, optimizer
  flags and link inputs.
- Every correctness/failure input, request identity, status, ownership cleanup,
  raw latency, process record and reconstructible native transcript hash.
- Complete trial denominators and implementation rotation, agreement of paired
  native results/warmups, and actual rejection of the wrong linked executable.
- All statistics recomputed from raw requests, including every observed
  slowdown and the unchanged timing/memory scope.

These are source-bound, replayable qualification records. Their hashes are not
signatures, and schema validation cannot authenticate fabricated arbitrary JSON.
Publication should retain the frozen source, native execution logs and report
together. Native performance on more machines, representative services and
uninstrumented production memory/latency remain separate work.
