# OpenVPN 2.7.8 packet-ID HIA experiment

This page preserves the initial qualified object and its two timed runs. The
later candidate and its complete same-round old/new comparison are recorded in
[perf2/README.md](perf2/README.md), with application evidence linked from
[CONTINUATION.md](CONTINUATION.md).

This experiment implements the packet-ID codec in verified HIA Core and links
its generated native object through a small C adapter. The wire arithmetic,
network byte order, partial failures, rollover and state changes are HIA
instructions. The adapter validates its caller boundary and marshals fields;
it does not implement the packet codec. The replay window remains the official
C implementation. The independent replay assessment is in `run_replay.py` and
`packet_replay_differential.c`; application evidence is recorded separately by
`tools/openvpn_hia_baseline.py` and `BASELINE_STATUS.md`.

The final codec passed the finite differential and boundary tests below.
The measured HIA paths are slower than the original C entrypoints. This work
therefore establishes a working, tested integration candidate, not a speedup or
deployment recommendation. No real TUN tunnel or DCO acceptance follows from
these codec measurements.

## Frozen sources and exact build

The C oracle is the **unmodified** `src/openvpn/packet_id.c` from OpenVPN
**v2.7.8**, commit `dc1f569087135894ac2703aeabd7a960ee9452d4`.
`packet-source-lock.json` fixes that source, its relevant headers and release
archive digest. The official source file is compiled directly; no rewritten C
reference substitutes for it. Section garbage collection discards unrelated
upstream functions with dependencies outside this finite codec harness.

The experiment starts from Hepta commit
`3102c2bb6cd819c27aef36cc927c23b39b279204` plus the recorded foreign-buffer ABI
change. Both C and HIA use **Clang 20.1.8**, x86-64 Linux, `-O3 -fPIC`, no LTO.
The generated-HIA receipt records the verified Core hash, emitter implementation
hash, compiler hash, command captures and object-symbol inventory. C flags and
configuration-header digest are recorded in each summary. The complete official
application was also built with Clang 20.1.8; its application tests and separate
instrumented profile are distinct evidence from this microbenchmark.

All codec and adapter sources carry `SPDX-License-Identifier: GPL-2.0-only` and
upstream provenance. The experiment does not copy an upstream large source file
into this repository.

## Boundary and ownership contract

The four selected entrypoints use the compiler's opt-in bounded foreign-buffer
profile. Each readbuf/mutbuf becomes a `(pointer, uint64_t length)` pair. Inputs
are borrowed synchronously; neither the caller's storage nor a pointer to it is
retained or freed. The caller must provide live, correctly initialized storage
and synchronization for the entire call. Numeric checks cannot authenticate
allocation provenance or detect an arbitrary dangling pointer.

The declared wire extent is the buffer capacity and cannot exceed 65,536 bytes.
The mutable state extent must be exactly 32 bytes. Its layout is:

| Byte offset | Type / representation | Meaning |
| --- | --- | --- |
| 0 | u64, little endian | Packet ID |
| 8 | i64 bit pattern, little endian | Time |
| 16 | u64, little endian | Buffer offset |
| 24 | u64, little endian | Buffer length |

HIA validates offset <= capacity and length <= capacity - offset before changing
state. Long-form and prepend arguments are canonical u32 booleans, 0 or 1.
The wire uses network byte order; the state uses the fixed LP64 little-endian
representation above.

The u64 return packs foreign-boundary status into high32 and the Core u32 result
into low32. Boundary statuses are 0 accepted, 1 extent too large, 2 null pointer
with nonzero extent, 3 numeric address wrap and 4 overlap involving a mutable
range. Boundary rejection occurs before Core execution and changes no bytes.
An accepted call may return Core error `0xfffe0001` for malformed state/flags,
also without effects. Otherwise regular codec results are 0/1 and epoch read
returns the decoded u16 epoch. A zero epoch can still consume a valid packet.

The application adapter additionally requires live, initialized and aligned
`struct buffer` and packet-ID objects. Their ranges must be disjoint from each
other and from the entire nonempty data range. It checks object addresses,
alignment and overlap before reading fields, then reads the buffer descriptor
to check its shape and data range before reading packet state or mutating
anything. These are explicit additional admission rules; equivalence with
upstream C is claimed only inside this domain. Rejected application arguments
return false/0 without mutations.

A regular receiver can be uninitialized because upstream writes its ID/time
before use. The adapter consequently does not read either incoming field.
Epoch read never reads or writes receiver time and only publishes the ID after
an accepted complete eight-byte read. It preserves the ID on truncation.
Native write-only receiver calls and sentinel observations exercise this
contract; they are not claimed to detect every uninitialized-memory error.

## Preserved upstream failure semantics

The implementation intentionally preserves partial changes, including:

- Regular read clears ID/time even when fewer than four bytes are available.
- A long read of four to seven bytes consumes the ID word and leaves time zero,
  then returns failure.
- A write initializes a zero sender time before checking rollover, and advances
  the sender ID before checking capacity.
- Long append writes ID before time. With only four free bytes it retains the
  first word and its length update, then fails.
- Long prepend writes time before ID. Four bytes of headroom can therefore
  retain only the timestamp and its offset/length update before failure.
- At the 32-bit maximum, short form fails; long form only rolls over if signed
  `now` is greater than the effective stored time. Timestamp serialization
  retains the low 32 bits. Defined u64 overflow is compared as well.
- Epoch write rejects ID `(1 << 48) - 1` after any initial time update. Epoch
  read requires eight bytes; a truncated read leaves the complete state intact.
- Epoch read never modifies time. A decoded epoch of zero still updates ID and
  consumes eight bytes when the word is complete.

For example, starting at ID7/time42, a long append into capacity4 writes
`00 00 00 08`, advances the sender to ID8 and length4, and returns false. A long
prepend with headroom4 instead leaves `00 00 00 2a`, advances ID8 and consumes
that headroom before returning false. These are required observations, not
transactional failures.

## Final qualification evidence

`packet-results/corrected-run4/summary.json` is the completed final correctness receipt.
`packet-results/manifest.json` records exact source and object hashes. The full
run also retains a source snapshot, generated Core and LLVM in the executor's
`packet-run-final4` directory. Build these deterministic artifacts using the
runner rather than substituting hand-written LLVM or C.

| Check | Observed result |
| --- | --- |
| Exhaustive small buffers plus deterministic random inputs | 228,336 cases |
| Original C vs adapted HIA plus same-state-ABI C vs direct HIA | 456,672 complete comparisons, 0 differences |
| Calls returning failure with observable state updates | 68,211 preserved cases |
| Exact live ranges ending at PROT_NONE guard pages | 15,504 cases, 0 differences/faults |
| Raw range/state admission | 83 cases, 0 differences |
| Adapter overlap, wrap, null, alignment and shape rejection | 80 cases, 0 changes |
| Write-only and sentinel receiver observations | 11 cases, passed |
| Four HIA calls followed by caller releases | 0 HIA frees, exactly 2 caller frees |
| ASan + UBSan on C oracle, C adapter and drivers | Differential and admission suites passed |

Every normal comparison checks return values, sender/receiver fields, buffer
metadata, pointer identity and all bytes of the guarded backing arrays. Raw
ABI comparisons check the complete 32-byte state plus the entire guarded wire
storage. The deterministic seed is `0x20261105a83f29b1`. Coverage includes short,
long and epoch formats, append/prepend, truncation, zero, protocol maxima,
u64 wrap, signed time extremes and IDs outside the normal protocol range.

ASan/UBSan instrument the C side only. They do not instrument the generated
HIA object. HIA access boundaries are separately exercised with actual guard
pages; no claim of arbitrary native memory safety is made. LeakSanitizer could
not inspect `/proc/.../task` under this managed host's ptrace restrictions.
The original failure is retained in corrected-run2. Corrected-run3 sets only
`ASAN_OPTIONS=detect_leaks=0` for those subprocesses. Run4 further sets
`UBSAN_OPTIONS=halt_on_error=1` so a future UB diagnostic cannot be hidden by
UBSan's default recover mode. Both final3 sanitizer stderr files were already
empty; final4 passed the stricter gate with empty stderr again. Run4 requested
no benchmark, reports `finite_packet_codec_qualified_correctness_only`, and
has byte-identical native objects and executables to final3. Caller ownership is tested
independently with the native linker's `--wrap=free` interception.

## Measured performance, including every regression

Medians below are **nanoseconds per call**. Every mode/arm has 18 samples of
1,000,000 calls after a 10,000-call warmup. The C/raw-HIA/adapter-HIA triplet uses
all six fixed orders, repeated three times. The same-buffer-ABI C control
alternates before and after the triplet. Each iteration resets offset/length;
return values and observed bytes/state enter a volatile sink. All arms use the
same compiler, target and optimization level. The process is pinned to one
available CPU, without exclusive host isolation.

| Run | Mode | Original C | Direct HIA | Adapter + HIA | C with same buffer ABI |
| --- | --- | ---: | ---: | ---: | ---: |
| corrected-run2 | long_write | 4.810 | 16.979 | 24.780 | 13.945 |
| corrected-run2 | long_read | 3.567 | 13.364 | 21.681 | 19.832 |
| corrected-run2 | epoch_write | 2.921 | 10.620 | 18.061 | 12.325 |
| corrected-run2 | epoch_read | 2.297 | 10.324 | 15.756 | 13.555 |
| corrected-run3 | long_write | 4.177 | 13.546 | 19.891 | 11.720 |
| corrected-run3 | long_read | 2.699 | 9.351 | 15.722 | 13.576 |
| corrected-run3 | epoch_write | 2.837 | 10.656 | 17.154 | 11.674 |
| corrected-run3 | epoch_read | 2.095 | 9.570 | 14.400 | 11.789 |

Direct HIA includes foreign-range admission and the pre-marshaled state ABI.
The C same-buffer-ABI control implements the same admission/marshaling and calls
the original C function in another translation unit. Without LTO, that extra
C call cannot be inlined across the translation-unit boundary. Its numbers are
useful context, not proof of an intrinsic language advantage.

The two timed corrected runs use identical codec/adapter/driver source. Run3 repeats
the full runner to complete the sanitizer phase after the environmental LSan
failure. It was not chosen for favorable timings. Both sets of samples,
including every slow sample, are retained. The later final4 correctness-only
run strengthens the sanitizer exit gate without collecting another timing set. Do not infer an exact additive
adapter cost by subtracting unlike harness timings. The substantial variation
also prevents treating these medians as universal deployment estimates.

The timed workload uses successful eight-byte long/epoch paths, reused buffers
and incrementing write state; reads use the same zero-filled wire contents.
Rollover and error paths are checked for correctness but are not separate
performance workloads in this version. These tiny codec timings do not replace
DCO-off tunnel throughput/latency, authentication/rekey/reconnect validation,
or the official DCO comparison.

`packet-results/historical-prototype-two-arm` retains the earlier development
measurements from before adapter fixes. They are explicitly labeled historical;
the original full source snapshot was not retained and they are not claimed
independently reproducible. A failed intermediate adapter edit was caught at
compilation, never accepted as runnable evidence, and is retained under
`packet-results/compile-failure` with the exact offending source and diagnostic.

## Reproduction and linking

First obtain and configure the pinned official OpenVPN source. Use a new output
directory for each run; the runner refuses to overwrite previous evidence:

```sh
python tools/qualify_openvpn_hia.py \
  --openvpn-source /absolute/path/openvpn-2.7.8 \
  --openvpn-build /absolute/path/configured-build \
  --clang /absolute/path/clang-20.1.8 \
  --output /absolute/path/new-packet-run \
  --benchmark --sanitize
```

If the local Clang installation requires a custom loader search path, supply
its `LD_LIBRARY_PATH` when invoking the runner. `packet.hia.json` is constructed
from the HIA generator, independently verified, emitted by the actual HIA LLVM
backend and compiled with its normal origin checks. The fixed foreign exports
are the four `ovpn_hia_packet_id_*` functions; the object imports only `abort`.

For normal official application call sites, link the resulting `packet.o` and
`adapter.o` and use:

```text
-Wl,--wrap=packet_id_read
-Wl,--wrap=packet_id_write
-Wl,--wrap=packet_id_read_epoch
-Wl,--wrap=packet_id_write_epoch
```

The adapter provides the corresponding `__wrap_*` symbols. This affects normal
external application references and leaves unrelated crypto and replay-window
algorithms intact. Linking succeeds only as one part of application validation;
use the separate baseline and replay receipts to assess actual call paths and
behavior. A constructed TUN/DCO capability probe is not runtime-path evidence.
