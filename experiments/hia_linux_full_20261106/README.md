# Finite Linux system benchmark guest

`guest_bench.c` is a static PID1 collector for a disposable x86_64 QEMU/Bochs guest. It emits real measurements for four fixed operating-system workloads. It does not install a host kernel, run as a host benchmark, modify the existing 14-check `guest_init.c`, or claim complete Linux validation.

## Execution contract

The program immediately refuses a non-PID1 process. Inside PID1 it mounts proc/sysfs, checks QEMU/Bochs DMI, parses the kernel command line strictly, compares `uname.release` exactly with the declared release, requires 4096-byte base pages, pins itself and inherited children to CPU 0, disables core dumps, and arms a 180-second alarm. A host-side collector must also enforce a finite 240-second QEMU timeout.

Required command-line controls are:

```text
hia_bench=1 hia_run_id=<24 lowercase hex characters> hia_expected_release=6.18.60
```

Optional controls are `hia_seed` (decimal uint32, default 20261106), `hia_iterations` (decimal integer 64..8192, default 1024), and `hia_phase`. Duplicate or unknown `hia_` controls, signs, overflow, malformed identity, and invalid budgets are rejected.

Omitting `hia_phase`, or selecting `all`, executes all four phases in the order below. A phase name selects only that phase and its own workload setup. The default produces 28 samples: two warmups and five measured repetitions for each phase. A single-phase boot produces seven samples. Every repetition uses the same seed and iteration count.

| Phase | Deterministic operation unit | Work and correctness |
|---|---|---|
| `syscall_process_pipe` | N pipe request/response cycles | Explicit getpid/gettid calls, fork/wait and two-pipe ping-pong; both endpoints validate every payload. |
| `anonymous_memory` | N initialized and verified pages | Fresh anonymous mapping, explicit THP policy, page touches, read-only protection, an expected access fault, restored writes and unmap. |
| `tmpfs_files` | N file lifecycles | Exclusive creation, full 4096-byte write/read comparison, EOF and size checks, close, unlink and missing-path confirmation. |
| `unix_tcp` | 2N socket request/response cycles | N AF_UNIX exchanges and N TCP loopback exchanges; both TCP endpoints use TCP_NODELAY and every payload is checked. |

The memory phase declares `hugepage_policy`. If the kernel exposes THP, every mapping must accept `MADV_NOHUGEPAGE`. If THP is absent, the guest declares `kernel_not_exposed`, and the collector independently requires `CONFIG_TRANSPARENT_HUGEPAGE != y` in the exact resolved configuration. An unsupported advice syscall is never silently accepted. Non-memory single-phase runs declare `not_selected`.

The protection-fault child installs an SA_SIGINFO handler. It must receive SIGSEGV/SEGV_ACCERR at the exact protected address and exit through that handler; the parent verifies and reaps that exit. This avoids unhandled-fault kernel logging and printk rate-limit changes between repeated samples.

## Metrics and records

Each record is one JSON object on a line beginning exactly `HIA_LINUX_BENCH `. The normative machine-readable contract is [PROTOCOL.json](PROTOCOL.json).

A `begin` record binds the run identity, release, seed, workload size, selection, CPU affinity, DMI and budgets. Ordered `sample` records carry actual CLOCK_MONOTONIC_RAW elapsed nanoseconds, a deterministic operation count and unit, actual and independently expected 64-bit checksums encoded as hexadecimal strings, correctness, and SELF/CHILDREN rusage deltas. All children have completed before the after-rusage read.

The timed region includes each phase's descriptor/mapping/fork setup and cleanup. Reference checksum construction, fixed template initialization, and JSON output are outside the timed region. Operation counts describe the declared logical workload, not an inferred total number of kernel syscalls. Interrupted or partial I/O loops are checked; errors cannot produce accepted samples.

Rusage user/system time has microsecond accounting resolution and is represented in nanoseconds after exact conversion. Faults, I/O blocks and context switches are counter differences. Max RSS is a high watermark, so its before/after values are reported separately and must not be summed as per-sample memory usage.

A terminal summary is PASS only when every expected sample passes. Failures emit an error and FAIL summary. A deadline cannot create PASS. After a result summary, the guest requests normal poweroff. The external collector must still require actual QEMU exit 0, observed kernel power-down, complete logs, and a drained owned process group. Guest text alone is insufficient.

## Build and smoke procedure

Compile without executing the resulting ELF on the host:

```sh
CLANG=/absolute/pinned/llvm-20/bin/clang
LLD=/absolute/pinned/llvm-20/bin/ld.lld
"$CLANG" -std=c11 -O2 -Wall -Wextra -Werror -static -fno-pie \
  --ld-path="$LLD" guest_bench.c -o /new/isolated/output/init
```

Create a new initramfs with this ELF as `/init`, plus proc/sys/dev/tmp directories and console/null device nodes. Preserve the existing stock image and existing smoke initramfs. Boot only the already-qualified stock bzImage for collector smoke, using the pinned QEMU machine/CPU, explicit BIOS/data paths, two vCPUs, 1024 MiB, no external NIC, a unique run ID and the exact release control. Record hashes for source, protocol, compiler, flags, ELF, initramfs, stock image/config, QEMU command, logs and parsed observations.

Static compilation/source review and actual guest execution are distinct evidence. A collector smoke run establishes that the collector executes and reports valid observations on the qualified image; it is not a performance comparison. Do not infer NDU gains, production performance, full selftest coverage, persistence, or external-device behavior from it.

## Phase selection for controlled evaluation

For a controller, freeze the chosen image, current phase, seed and all allowed prior observations before boot. Set `hia_phase=<phase_id>` to collect only the selected phase. Do not expose later heldout outcomes to the decision process. Calibration and heldout traces must retain separate labels and immutable image/config/guest identities.

Within-boot repetitions share one system session. Across-image comparisons require the same frozen protocol and guest binary plus an explicit independent-boot schedule and environment controls. TCG and hardware/KVM results belong to different measurement environments.

## Reusable collector

`tools/hia_linux_system_benchmark.py` publishes `expected_checksums()`, `parse_serial()`, `qemu_argv()` and `run_guest()`. The CLI mirrors `run_guest` keyword names with hyphens. It requires predeclared kernel/config SHA256 values, the actual static guest build receipt, the actual source commit, explicit QEMU/data/module/BIOS paths, and a new output directory.

`--profile tcg` uses `tcg,thread=multi` with `qemu64,-popcnt`; `--profile kvm` uses `kvm` with `qemu64,-popcnt,-svm`. Both profiles keep the same machine, memory, guest CPU count and guest affinity. Each profile must complete its own real collector qualification. Results from different profiles must not be pooled or inherit one another's admission.

Optional `--host-cpus 2,4` enforces a nonempty subset of the launcher's actual allowed CPU set through an explicit taskset prefix. The result records the allowed/requested/inherited masks, taskset identity, complete execution argv and bare QEMU argv. The collector does not claim live per-vCPU thread migration sampling. Without this option, QEMU inherits and records the launcher's current affinity.

Before starting QEMU, `PREEXECUTION.json` freezes image/config/guest/initramfs/collector/protocol/QEMU/dependency hashes, selection, seed, iteration budget, profile, argv and environment. `TRACE.json` retains raw parsed records, all samples and admitted measured samples. `RESULT.json` binds those artifacts to the real process-group receipt and unchanged input identities.

`parse_serial` requires the predeclared argv, actual command receipt, raw UTF-8-decoded stdout/stderr, exact config text and run controls. Use `read_bytes().decode("utf-8")`, preserving CRLF: edited, excerpted, or newline-rewritten logs fail the recorded raw hash binding. Duplicate JSON keys, non-finite values, incorrect types, missing samples, forged checksums, incomplete groups, and missing powerdown are rejected. Synthetic parser counterexamples in `tests/test_hia_linux_system_benchmark.py` are separate from real guest observations.
