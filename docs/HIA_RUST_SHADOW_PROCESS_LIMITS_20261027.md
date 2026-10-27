# HIA P7: hard per-process resource limits on the Rust shadow transport

This is a **bounded development transport** increment built on PR #261 exact
commit `63c74114912e8ec255f90557bdf8b13ffb258fa9`.
The canonical `hepta.hia_program.verify_program` remains the single HIA
program admission authority. The Rust verifier remains an optional shadow and
does not grant native final-use rights.

## Defect and mitigation

The existing `_run_bounded_shadow` correctly limited stdout/stderr, wall
clock time, stdin bytes and post-exit process-group cleanup, but the child
process had no hard virtual-memory/CPU/file-output resource caps. A pinned
but misbehaving executable could exhaust host memory or create huge output
files before the wall-time monitor reacted.

`_limited_shadow_command` now starts an isolated Python standard-library
helper (`-I -S`) which sets Linux kernel limits then **execves the exact
staged, hash-pinned Rust executable**. No shell, `preexec_fn`, unverified
binary substitution, new IR authority, LLVM emitter or native success claim.

Hard resource limits per shadow process:

| Linux resource | Limit |
|---|---|
| `RLIMIT_AS` | 1 GiB virtual address space |
| `RLIMIT_CPU` | ceil(user wall deadline) + 1 seconds |
| `RLIMIT_FSIZE` | 0 bytes of regular-file output |
| `RLIMIT_CORE` | 0 core dump bytes |
| `RLIMIT_NOFILE` | 64 file descriptors |

Both soft and hard values are set. Ordinary stdout/stderr pipes still use the
existing 32 KiB bounded collector. The existing 15-second maximum user
deadline and always-kill-private-process-group teardown remain unchanged.

## Local executable control

A real CPython/Linux subprocess experiment (not simulated resource reads)
observed `RLIMIT_AS=[1073741824,1073741824]`,
`RLIMIT_CPU=[4,4]`, `RLIMIT_FSIZE=[0,0]`,
`RLIMIT_CORE=[0,0]` and `RLIMIT_NOFILE=[64,64]` in the child.
An attempted regular-file write failed with Errno 27 (`EFBIG`) and left the
created file empty. This is an independently executed resource-control
experiment; it is **not** a test of the full exact Hepta checkout.

Added exact-repository regression inputs:

```sh
python -m unittest tests.test_hia_rust_shadow_limits \
  tests.test_hia_rust_crosscheck tests.test_hia_rust_crosscheck_cli -v
python -m unittest tests.test_hia_rust_shadow tests.test_hia_rust_owned_shadow -v
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
```

## Trust boundary / blockers

RLIMIT_AS constrains virtual address space **per process**, not total
cgroup RSS or child aggregate memory; RLIMIT_CPU is per-process CPU time,
not entire process-tree CPU. Executables can attempt privilege-changing or
detaching operations unless separately sandboxed. This tool only runs
a caller-approved exact pinned binary; it does not contain hostile native
code. A production P7 target still requires OS namespace/cgroup/seccomp
qualification, target execution, recovery and sustained p99/RSS evidence.
Rust-native, full HIA differential, C/C++ L2/L3, GPU/DMA and Agent provider
A/B remain OPEN; `whole_project_blockers_closed=false`.
