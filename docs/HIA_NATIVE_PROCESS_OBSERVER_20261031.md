# HIA P5/P6: Linux native-process observation (research only)

This extension sits *on top of* the P5/P6 synthetic full-cost arithmetic gate
in #455. It adds real **Linux ELF process execution** and records every actual
sample, rather than claiming that user-supplied nanoseconds are measured.

It is explicitly **not** a standalone proof of HIA performance superiority or
NDU benefit. In particular the preregistered reference outputs, source / hardware
identity, compiler-toolchain identity, and external preparation, proof and
human-work costs remain **supplied claims**, not independent attestations.
A program can fork; this observer records the direct child's `wait4` peak RSS,
not a whole descendant process tree. There is no authority to load or deploy
native HIA output.

## Exact bounded protocol

`tools/hia_native_process_observer.py` consumes strict immutable
`hepta.hia.native-observation-registration.v1` JSON (up to 256 KiB).

The complete required top-level fields are:
`schema`, `source_digest`, `objective_digest`, `hardware_digest`,
`workload_digest`, `candidate_bank_digest`, `generation`, `trials`,
`arms`, `repetitions`, `timeout_ms`, `max_output_bytes`,
`minimum_gain_ppm`, `minimum_gain_ns`, `maximum_peak_rss_bytes`,
`maximum_p99_ns`.

- Exactly 8–128 sorted registered trials: `id`, `stdin_base64`,
  `input_digest`, `expected_result_digest`. Actual standard input is
  SHA-256 checked before any process starts.
- Exactly four arms in order `baseline`, `fixed`, `dp`, `ndu`, each
  containing `strategy`, `binary_path`, `binary_digest`, `core_digest`,
  `toolchain_digest`, `argv`, `one_time_ns`, `unknown_costs`.
  Every one-time cost required by the full-cost gate must be present, including
  toolchain, dependency, controller/candidate builds, calibration, search,
  verification, measurement, publication, switch and rollback.
- Every executable is an absolute, regular, nonsymlinked ELF file at most
  64 MiB. Exact SHA-256 is checked while copying to a private directory;
  this frozen copy, not the original pathname, is executed.
- 2–128 executions per trial per strategy, interleaved in registration order.
  The subprocess is started without a shell, with fixed argv and stdin, bounded
  file output, a deadline, disabled core dumps and new process group.
  `wait4` obtains **per-child** maximum RSS instead of the cumulative
  `RUSAGE_CHILDREN` peak. Timed out children are killed/reaped.
- Complete stdout must match the registered reference SHA-256; stderr must
  be empty and the child must exit zero. A mismatch, crash or timeout stops
  further trials and retains its raw negative evidence. No sample is silently
  dropped or replaced.
- Per trial, `execution_ns` is the sum of all recorded elapsed samples,
  `p99_ns` is the nearest-rank sample p99, and `peak_rss_bytes` is the
  direct-child maximum. Snapshot freezing cost is charged as measurement
  overhead. Startup and observer polling are included in the wall cost.
- Once all arms finish, the output includes a **separately marked**
  `full_cost_input` compatible with `hepta.hia.full-cost-comparison.v1`
  and its arithmetic-only `full_cost_verdict`. It does **not** certify
  independent preregistration, correct controller work, complete costs, or
  statistical significance.

Result security posture always remains:
`authority=DENY_ALL`, `safety_certificate=false`,
`production_activation_allowed=false`.

## Execute (Linux)

```sh
python -B -m unittest tests.test_hia_native_process_observer -v
python -B -m unittest tests.test_hia_full_cost_gate -v
python -B tools/hia_native_process_observer.py \
  --registration /absolute/path/registered.json \
  --output /new/path/observations.json
```

The test compiles four **real** C ELF executables, checks completed native
observations and arithmetic replay, then injects wrong output, an infinite
loop with timeout, an executable digest drift, a symlink, non-ELF input, and
malformed wire fields. A passing synthetic/echo fixture is *not* a real
HIA-vs-Clang-vs-Rust or NDU advantage result.

The writer uses exclusive creation and fsync; existing output is not replaced.
The observer measures process-level latency, not instruction-only execution;
short tasks are particularly sensitive to launch and polling overhead.
Neither machine-code equivalence nor original program correctness is tested by
these observations. Independent native/refinement and safety gates remain
mandatory before any optimization can be installed.

## Remaining closure criteria

P0–P4 stay open for complete semantics, owner/cancellation, cross-target ABI,
C migration and complex C++ compatibility. P5 needs real, preregistered
positive HIA net-benefit against strong Rust/Clang/LLVM controls, independently
bound build/proof/switch costs, and held-out workloads. P6 additionally needs
genuine original Rust NDU execution under the same candidate bank and
information budget as fixed and DP controls, with complete cost
attestation. P7 requires genuine Agent hidden tasks, human effort, hardware
resource evidence, fault recovery and runtime authority qualification.

**No P0–P7 production blocker is claimed closed by this additive observer.**
