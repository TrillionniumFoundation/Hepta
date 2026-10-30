# A real Ring-Buffer implementation maintenance cycle and native host profiles

This is a separate continuation of tracks 4 and 8. It changes the upstream
**implementation** across two real historical commits, retains the original
build and public interface, and qualifies the resulting implementation on each
actually observed native Linux host. It is not an optimization-advantage study,
a proof of source equivalence, or a Rust-backed safety qualification.

## Upstream change and original project

The complete eight-file trees are pinned in
`tests/fixtures/c_migration/ring_buffer_implementation_history/UPSTREAM.json`.
Every file has its original Git blob identity, byte count, SHA-256, and mode;
`verify_upstream` reconstructs both whole Git tree identities. The original MIT
license is retained.

| Revision | Original upstream commit | Tree | Implementation behavior |
| --- | --- | --- | --- |
| Before | `8f133fe1ea0b0ce0095bb9552ba7fbb7caeac600` | `d2db09d1576bfcc635b212f598ee727a0a04f007` | `dequeue_arr` calls dequeue before testing the requested count; a short or zero-length read can consume and write one extra byte. |
| After | `bbe82ad2b460db79d94bbb847dd3b3ece4f191cb` | `ae95a50c8ce843ca48a07a8465a09ada7efbe0da` | The upstream fix tests the requested count first and avoids the extra pop/write. |

The change is [the upstream implementation fix](https://github.com/AndersKaloer/Ring-Buffer/commit/bbe82ad2b460db79d94bbb847dd3b3ece4f191cb).
Only `ringbuffer.c` changes between those trees. The original public header,
`examples/Makefile`, and `examples/simple.c` remain byte identical. This is a
different maintenance cycle from the earlier Ring qualification whose upstream
change affected `examples/tail.c`.

The harness runs the original `make` and original `simple` executable. It then
invokes that same Makefile with a recorded `CC` adapter that replaces exactly
one expected `ringbuffer.c` link input with the translated shared library.
All original client flags are retained; the adapter verifies compiler, original
source, and replacement identities before and after the invocation. The
upstream client and source files are never edited. Both original and translated
client executables and their stdout/stderr are retained, and the stdout byte
streams must agree separately for each revision.

## Translation and the ABI boundary

`tools/migrate_c_inline_record_project.py` captures the original compilation
database and physical source declarations through the existing complete C
capture and original-type gates. `hepta/c_inline_record_views.py` adds one
explicit, narrow profile: a fixed inline byte array plus primitive scalar
record state. It does not weaken the shared migration IR or its declaration
coverage rules. Fixed/incomplete array parameters still require the existing
independently bound original-type evidence. VLA parameters, unsupported
attributes and unused unsupported declarations reject the whole bundle.

Each revision translates all nine captured function bodies into checked Hepta.
The existing independent C backend emits the implementation. A generated thin
C wrapper projects the original record into scalar state and an explicit byte
slice, calls those generated Hepta bodies, and writes back only scalar state.
The wrapper does not contain a separately hand-written queue implementation or
link the original implementation as its implementation.

The original C record contains a 128-byte inline array and two `uint8_t`
indices. The original example leaves the payload uninitialized and initializes
only the indices. This route therefore does **not** create Rust references to
uninitialized inline payload. It does not zero-fill the original record or
change the client. A structurally checked initializer must write each real
scalar field to zero exactly once, with no read of old scalar state or payload.
Only this verified initializer uses zero-valued private scalar state at the
boundary. Unread payload bytes are left untouched.

| Layer | What is checked or observed | Remaining obligation or limit |
| --- | --- | --- |
| Original source | Complete captured declarations, physical spelling, original parameter types, full source/dependency identity | Finite admitted subset; no arbitrary C/C++ or source-equivalence theorem |
| Hepta representation | Existing frontend checks; scalar state plus explicit byte slices; original loop and short-circuit order retained | Foreign initialized-byte and lifetime facts are not inferred |
| Independent C backend | Existing backend borrow-call validation and checked indexing/arithmetic for this profile | This result does not borrow Rust's checker or the separate HIA Core→LLVM theorem scope |
| C ABI wrapper | Original function types and record layout; numeric pointer range/alignment and mutable overlap checks | Numeric checks do not establish allocation provenance or actual allocation size |
| Native artifact | Unchanged client execution, independent full-state oracle, real ABI and fault/host observations | Finite observations on the recorded host/compiler; no universal safety or performance result |

Caller obligations are explicit: the record must be live; scalar state must
have been initialized; bytes actually read must have been initialized; external
slices must provide the declared extent; record and external mutable ranges
must not overlap; and foreign mutation must be exclusive. These obligations
restrict the supported foreign-call domain. The original C implementation can
have other defined aliasing or empty-buffer calls that this conservative
contract does not admit. An unchanged ABI does not imply that every possible
C caller is automatically admitted.

The old revision's output extent is explicitly `len + 1` for `dequeue_arr`,
including `len == 0`. The fixed revision uses `len`. The wrapper computes the
extent in `size_t`, so `uint8_t` value 255 plus the legacy extra byte becomes
256 rather than wrapping to zero. The old bug is retained within its declared
valid output extent. A negative control deliberately removes the old extra
extent; the generated checked body must then terminate with `SIGABRT` when it
attempts its second write for a requested length of one.

## Independent semantics and negative controls

The frozen protocol is `experiments/ring_implementation_cycle/PROTOCOL.json`.
It defines a deterministic fixed regression prefix plus 640 mixed stateful
operations. Each of the resulting 658 operation observations contains the
return value, both indices, item count, empty/full flags, every inline payload
byte and all 256 output backing bytes. The independently authored Python model
specifies the old extra pop/write separately from the repaired behavior. It
never calls a translated implementation to produce expected values.

Checks include zero-length and short reads, consecutive short reads, empty and
full queues, wrap-around and overwrite, values through `0xff`, lengths through
255, and payload-preserving reinitialization. Both native implementations are
checked against their own revision model. Four wrong-revision controls verify
that both original and translated candidates fail the opposite revision's
model. Comparing only return values would miss several of these differences;
full state and output-byte observations are required.

Five additional translated-boundary controls run in children: null record,
output overlapping record storage, input overlapping a mutable record, a head
index outside the fixed array, and null output. Each must terminate through
`SIGABRT`, after which the parent successfully executes a healthy ring
transaction. No invalid-pointer test is used to ascribe safety to the original
unsafe C implementation. Process isolation and OS child cleanup are the
recovery mechanism; this does not demonstrate repair of corruption within a
continuing failed process.

## Native host, resource, and Linux descriptor profiles

A run requests either `x86_64` or `aarch64` and requires the actual Linux machine
identity to match. Each host must execute the generated binaries natively.
The public-header ABI probe records record size/alignment/offsets, integer and
pointer widths, `size_t` width, plain-char signedness, and array capacity. The
expected record layout is size 130, alignment 1, and offsets 0/128/129. Plain
`char` signedness is measured and follows the captured target model; it is not
forced to the x86 default on ARM.

For both revisions and both implementations, the runner executes three
profiles: one thread, four independent records, and four threads operating on
one record under a host mutex. Each has three repetitions, 128 batches per
thread, and 128 transactions per batch. Every transaction validates bytes and
queue state; thread checksums and total byte counts also have an independent
Python oracle. There is no unsynchronized shared-record claim.

The raw per-batch nanosecond observations are retained, together with nearest
rank p50/p95/p99 and whole-run elapsed time. A compiled Linux supervisor records
`wait4` peak RSS, its own memory floor, and the child's pre-exec memory floor.
These values describe the observed whole process, including dynamic loader,
threads, harness, library and the measured pre-exec baseline. They are not
isolated ring allocations, static memory bounds, WCET, or guaranteed tail
latency. Original/translated measurement order alternates by repetition;
there is no speedup gate or optimizer selected from these observations.

The host also performs actual Linux OS operations: reading 64 zero bytes from
`/dev/zero`, sending them through the ring, observing `ENOSPC` from `/dev/full`,
observing an empty nonblocking `eventfd` return `EAGAIN`, writing and reading its
counter, observing `EBADF` after close, and reopening a fresh counter after the
failure. A live `/proc/self/fd` inventory must match before and after the
sequence. These are **OS pseudo-device and descriptor** operations. They do not
qualify physical GPU, DMA, MMIO, board, interrupt, or bare-metal behavior.
Thread handles, mutexes and barriers are joined/destroyed after normal
completion; asynchronous cancellation safety is not claimed by this harness.

## Prospective cost and evidence accounting

The runner starts a timestamped, monotonic operation journal before any
qualification work. It records non-overlapping stages for verification,
materialization, capture/translation/check/compile, original builds, switching
and rebuilding through the original Makefile, native observer build,
functional/fault observations, host measurements, cleanup and final source
reverification. Each directly invoked process has exact argv/cwd,
stdout/stderr byte identities, return code and elapsed time. Nested compiler
and capture work remains within the enclosing measured stage and is represented
by the migration/capture receipts; the top-level invocation count is not
reported as a count of all OS processes.

`runner_wall_ns` starts at instrumentation and stops before final result and
manifest serialization. Per-stage times exclude gaps between stages; their sum
is not substituted for total runner wall time. CPU usage fields are the
process-lifetime observations returned by `getrusage`, including imports before
runner instrumentation. Earlier research, implementation, dependency
preparation, human engineering/review, and this session's AI token usage are
unknown where no actual timing or usage receipt exists. They remain **null**,
not zero. No claim that a fully measured human maintenance cost has been
completed follows from the machine ledger.

A separate `WORK_JOURNAL.jsonl` in the development output parent records when
implementation-session instrumentation began. It does not retroactively time
work that preceded that event. Any later human or model usage receipt must be
retained as an actual independently attributable record; wall time must not be
invented into human hours or token counts.

Every qualification result is bound to the protocol, upstream identities,
selected compiler binary/version hashes, all imported Hepta source modules,
qualification helpers, driver and observer sources, generated Hepta/C files,
AST/type-capture receipts, native binaries and command observations. The final
manifest covers all retained files. Source bindings are recomputed after the
run. A formal run additionally matches every bound source file to the supplied
Git commit before running; an explicit development run is labeled unfrozen.
Previous development failures stay separate from successful runs and are not
rewritten or relabeled as formal evidence.

## Reproduction and registration

Before execution, commit the protocol and all bound sources. Run each native
host in an isolated new output directory:

```sh
PYTHONDONTWRITEBYTECODE=1 python tools/qualify_ring_implementation_cycle.py \
  --output evidence/ring-implementation-x86_64 \
  --source-sha FULL_REGISTERED_GIT_COMMIT \
  --native-host x86_64 --clang clang-20 --cc gcc
```

Use `--native-host aarch64` on an actual AArch64 runner. The original Makefile
uses `gcc`; the selected `--cc` must resolve to that same executable. `--clang`
is the actual capture compiler. Both compiler identities are retained. This
profile does not require a Rust toolchain.

The focused admission and independent historical-model tests are:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest \
  tests.test_c_inline_record_views tests.test_ring_implementation_cycle -v
```

Use `--development` only for explicitly unfrozen local qualification. This
protocol is a repeatable correctness/host qualification and does not call its
input trace an unseen optimization workload. Formal results must be published
with their own exact source registration and original raw evidence, separately
from the prior Ring maintenance/optimization studies and separate HIA native
Core-to-LLVM profiles.
