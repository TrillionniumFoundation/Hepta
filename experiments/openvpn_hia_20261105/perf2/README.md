# Packet codec optimization: one frozen candidate

The candidate reduces redundant checked-byte branches and removes the foreign
wrapper's call to an outlined Core function. It passes the existing full codec
qualification. The one complete, fixed-budget comparison gives mixed performance:
both write workloads improve against the old HIA object, while long reads have
paired regressions. The new adapter path remains **4.51–6.89 times the original C
batch-average time**. These measurements do not establish a VPN throughput gain,
a production hotspot, or a DCO result.

The predeclared [plan](plan.json), [freeze identities](freeze.json),
[qualification receipt](qualification/summary.json),
[complete comparison receipt](comparison/summary.json), and
[all recorded samples](comparison/samples.stdout) are retained. The previous
[packet results](../PACKET_KERNEL.md) and their regressions remain unchanged.

## Diagnosis and implementation

The old object's [disassembly](baseline/packet.asm) shows a call from each finite
foreign entry point to an outlined `__hia_fn_*` Core body. For example, the epoch
writer's admitted eight-byte wire write contains eight separate checked-byte
branches, eight byte stores, fragmented state stores, and six saved callee-saved
registers. Some initial state loads are already combined into machine-word loads;
it would be inaccurate to describe every state operation as byte-at-a-time.
The [adapter disassembly](baseline/adapter.asm) separately contains application
object/alignment/alias admission and packing/unpacking of the 32-byte state.

Two small changes form the single candidate:

1. In `hepta/hia_program_llvm.py`, only internal Core functions selected by the
   explicit finite `foreign_buffer_exports` profile receive `alwaysinline`.
   The wrapper and its extent, null, numeric overflow, and alias checks are still
   emitted. IR provenance verification and every checked Core access remain in
   place. No unchecked access operation or C codec was added.
2. In `packet_program.py`, the entry explicitly requires the already-declared
   maximum wire capacity of 65,536 bytes. Byte indices use an exact `u32` then
   `usize` round-trip, and each already-admitted word visits its highest byte
   first. This exposes nonwrapping index arithmetic and makes the highest byte's
   bounds test dominate the lower byte tests. Word ordering is unchanged.

The bound follows from `offset <= capacity` and `length <= capacity - offset`,
followed by the existing complete-word room check. Thus every accessed wire
index is below 65,536; state indices are fixed within 32 bytes. Narrowing these
indices is exact. This argument applies under the existing synchronous loan
contract: the caller supplies live, exclusive ranges, and the foreign wrapper
rejects overlapping mutable ranges. The checks do not authenticate arbitrary
pointer liveness.

The byte reordering occurs inside a word whose whole extent was admitted before
its first access. It does not move one word across another. Long append still
handles ID before time, prepend handles time before ID, and a later word's
failure still preserves prior output and state updates. Time initialization,
packet-ID consumption on capacity failure, signed time comparison, integer
wrap, receiver initialization, epoch-zero consumption, and untouched epoch
receiver time are unchanged. The adapter source and object are byte-identical
to the prior qualified version.

In the [candidate disassembly](candidate.asm), the four public exports contain
their Core bodies; the outlined internal functions are absent. The epoch
writer's per-byte wire bounds tests decrease from eight to one. It still emits
eight byte stores, fragmented state stores, and six saved callee-saved registers.
The candidate therefore addresses redundant checks and the internal call; it
does not eliminate the byte lowering or adapter work. Both the old and new
unoptimized emitted LLVM are retained as [old IR](baseline/packet.ll) and
[new IR](candidate.ll).

### Code size

| Quantity | Old | Candidate | Change |
| --- | ---: | ---: | ---: |
| ELF executable `.text` bytes | 2,822 | 2,632 | −190 (−6.73%) |
| GNU `size` aggregate `text` column | 3,278 | 3,000 | −278 (−8.48%) |
| Whole relocatable object bytes | 4,744 | 4,224 | −520 (−10.96%) |

The GNU `size` column includes `.eh_frame`; it is not the `.text` section size.
Both the [old section listing](old-size-sections.txt) and
[new section listing](new-size-sections.txt), plus their GNU summaries, are
retained. Symbol renaming for the comparison checks equality of executable
section names and bytes before and after `objcopy`; it does not compare section
table indices, which the tool may reorder.

## Qualification of the frozen candidate

The [44-method regression log](regression44.log) covers foreign buffers,
composite ABI, LLVM lowering, source exports, and native command logging. All 44
methods passed, with no errors, failures, or skips. The
[regression receipt](regression44.json) fixes the backend and packet generator
source hashes.

The existing qualifier ran unchanged, without its optional benchmark:

| Gate | Result |
| --- | --- |
| Official C differential | 228,336 inputs; 456,672 full observations compared; zero differences |
| Failure-state coverage within that differential | 68,211 partial-failure cases retained |
| Guard-page cases | 15,504; zero failures |
| Raw ABI admission | 83 cases; zero failures |
| Adapter admission/alias rejection | 80 cases; zero failures |
| Receiver observations | 11 cases; zero failures |
| Ownership observations | zero HIA frees; two caller frees |
| C-side ASan and fatal UBSan | full differential and admission rerun; zero failures; empty diagnostic streams |

The C harness, C oracle, and C adapter are sanitizer-instrumented. The generated
HIA machine code is not; its boundary accesses are separately exercised by the
guard-page suite. `ASAN_OPTIONS=detect_leaks=0` disables the host-incompatible
process-based leak scan, while `UBSAN_OPTIONS=halt_on_error=1` makes undefined
behavior diagnostics fatal. Ownership is observed with `--wrap=free`. This is
finite empirical qualification, not a proof of the backend or the whole language.
The [command log](qualification/commands.json) and all qualification stdout/stderr
files are retained.

## Fixed-budget six-arm comparison

The [driver](paired_benchmark.c) compares the original C functions, the C byte
buffer control, old/new raw HIA, and old/new HIA with the unchanged application
adapter in one process. Old and new HIA objects are renamed into separate symbol
namespaces, with executable bytes checked unchanged. The C oracle, C byte
control, and adapter object hashes are identical across the two qualification
runs. The runner rejects changed qualified sources or mismatched receipts.

All objects use the same Clang 20.1.8 binary, x86-64 target, `-O3`, and `-fPIC`.
C uses separate translation units and no LTO; HIA Core can inline inside its
foreign wrapper. The C byte control calls separately compiled original C, so its
optimization visibility differs. Its timing is a control for that particular
integration, not a pure language comparison. The driver additionally uses
`-Werror=format`, which does not change generated optimization flags.

For each of four workloads there are 18 samples per arm, each with 1,000,000
calls, following 10,000 warm-up calls per arm. The six-row Williams order starts
`0,1,5,2,4,3`, rotates labels modulo six, and repeats the six rows three times.
This places each arm in every position equally. The same operation, byte array,
state initialization, offset/length reset, returned result, and byte/ID sink are
used for corresponding arms. Calls inside a batch are direct calls, and the
whole-batch drivers have the same `noinline` attribute. All six final sinks match
in every recorded sample. These checks complement, rather than replace, the
separate full-state differential suite.

The completed run on 2026-11-05, 08:26:03–08:26:09 UTC contains 72 JSON sample
rows, each with six arm times: **432 recorded batches, none discarded**. It used
CPU 0 on the shared AMD EPYC 9V74 host, Linux 6.18.57. CPU frequency was not locked
and the host was not exclusive. The receipt records affinity and load averages.
The following numbers are medians of batch-average nanoseconds per call; they
are not individual-call tail latencies.

| Workload | Original C | C byte control | Old raw HIA | New raw HIA | Old adapter HIA | New adapter HIA |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Long write | 4.080 | 11.701 | 13.905 | 12.183 | 19.932 | 18.413 |
| Long read | 2.808 | 13.216 | 9.485 | 9.720 | 16.846 | 16.500 |
| Epoch write | 2.900 | 12.591 | 10.542 | 9.501 | 17.709 | 16.514 |
| Epoch read | 2.186 | 12.454 | 9.753 | 8.840 | 14.597 | 15.070 |

Pairing uses each row's new/old time ratio, then takes the median of those 18
ratios. Values above one are regressions. The number of individually faster
pairs is reported to retain direction changes instead of treating a median as
uniform improvement.

| Workload | Raw paired new/old | Raw faster pairs | Adapter paired new/old | Adapter faster pairs | New adapter/C ratio of medians |
| --- | ---: | ---: | ---: | ---: | ---: |
| Long write | 0.8593 | 15/18 | 0.8967 | 15/18 | 4.51× |
| Long read | **1.0069** | 8/18 | **1.0475** | 4/18 | 5.88× |
| Epoch write | 0.9222 | 15/18 | 0.9274 | 15/18 | 5.69× |
| Epoch read | 0.9088 | 16/18 | 0.9849 | 10/18 | 6.89× |

Long read regresses by approximately 0.69% raw and 4.75% with the adapter on this
paired statistic. Epoch read's adapter ratio is slightly below one, but its
separate new median is higher than the old median. Medians of paired ratios and
ratios of independent medians measure different summaries; both are shown, and
neither is promoted to a universal speedup. All ranges and raw samples, including
the candidate epoch-read adapter maximum of 55.745 ns/call, remain in the receipt.
No outlier filtering, confidence claim, best-run selection, or follow-up timing
round was used.

The remaining C gap is consistent with work still visible in the disassembly:
foreign admission, Core metadata/state validation, byte lowering, and the
application adapter's additional object checks and state packing. This is a
mechanistic explanation, not a measured additive cost breakdown. Subtracting
raw from adapter times would mix different stacks and harness state layouts.
The measurements concern four small codec workloads; they do not establish how
often those paths execute in a real tunnel or their contribution to total VPN
CPU time.

## Preserved failed measurement attempts

There is one production candidate and one complete comparison round. Two
measurement-infrastructure failures preceded it; neither changed the candidate
nor produced usable recorded sample rows. They are retained, not silently
excluded as bad performance results.

| Attempt | Failure and measurement status | Evidence |
| --- | --- | --- |
| comparison1 | Preflight compared executable sections by their numeric indices. `objcopy` reordered the section table while preserving the bytes; the overly strict index comparison rejected it before benchmark execution. Fixed by comparing unique section names and bytes. | [receipt](failed-attempts/comparison1/summary.json), [runner snapshot](failed-attempts/comparison1/source_snapshot/run_comparison.py) |
| comparison2 | Driver JSON `printf` had seven integer sink conversions for six sink arguments, followed by `%s`. Clang emitted format warnings; execution exited with SIGSEGV (`-11`) at serialization. The first six-arm timing group had already executed, but buffered stdout remained empty, so those measurements were lost and cannot be reconstructed. Zero complete sample rows were successfully recorded. Fixed the extra conversion and made format warnings fatal. | [receipt](failed-attempts/comparison2/summary.json), [warnings](failed-attempts/comparison2/compile-benchmark.stderr), [driver snapshot](failed-attempts/comparison2/source_snapshot/paired_benchmark.c), retained empty stdout/stderr |

The receipts preserve start/end times, commands, elapsed durations, and exit
status. It would be incorrect to claim that no timing occurred in comparison2
or that every executed historical measurement survived. The all-samples-retained
claim applies to the complete comparison3 round. All prior delivered timing
rounds remain in `../packet-results/` as separate historical evidence.

## Frozen identities and reproduction

| Artifact | SHA-256 |
| --- | --- |
| Candidate packet object | `05d189d73cb75e49ef251ba8a7fe97bb36f837b3bb3936fe3b907614233e7c31` |
| Old packet object | `67e17b4113f8aeca171efb9b1a45909373daddeaae448060c20ec080e0725983` |
| Unchanged adapter object | `64c78f6e9e8d04d9887a040460e157aae53a75aac738c996f650e80555e3ea6f` |
| Candidate Core | `ac14be9d4608692f63c236b6e18215a7573b38f0f8d691d3d8529acf0afd7247` |
| Candidate backend file | `3d339558d4464bf33f71bbe0dbbf23ca5470c15bab1b35f98c157cc3c825ddf8` |
| Candidate packet generator | `932ab59a68e354095ef0a7e7b009ea20cb051491e8e357fab78fc54d3756020d` |
| Recorded complete raw samples | `2fd610603b6091b1701c28e840142d861d27b2aae6ab9515ef58a093d5570282` |

The base commit is `5a699214b974c1af95a8044315f0818a2f72064f`. The old generator
and backend snapshots are in `baseline/`. The public ABI, adapter signatures,
packet qualifier CLI, and compiler requirements are unchanged. The new optional
comparison runner takes `--old-run`, `--new-run`, `--openvpn-source`,
`--openvpn-build`, `--clang`, and `--output`; it requires a fresh output directory
and qualified objects matching the predeclared identity.

Rebuild each version with `tools/qualify_openvpn_hia.py --sanitize`, using the
locked official source/build and exact Clang recorded in the qualification
receipt, and use the two run directories with `run_comparison.py`. The old
backend/generator snapshots must be restored together in an isolated checkout
when rebuilding the old object. The raw LLVM, build receipts, commands, and
source hashes provide the independent object identity checks. The finite
qualification receipt intentionally retains `tunnel_qualified: false` and
`dco_qualified: false`; application and target-host validation belong to their
separate evidence sets.
