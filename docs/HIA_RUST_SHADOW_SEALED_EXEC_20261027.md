# HIA P7 — exact-image Rust shadow execution with sealed memfd

Status: **source hardening candidate**, NOT production/hostile-code sandbox
qualification or whole-language soundness proof. Based on the checked HIA
convergence PR #268 exact first parent
`c67d14a867cfe888824f4b7750c5b9bb96ec497e`.

## Previously open identity window

`hia_rust_crosscheck.crosscheck_rust_shadow` already checked the caller's
SHA-256 of a bounded ordinary executable before running the Rust shadow.
It then copied those bytes into a mode-0700 temporary path and executed that
path after a separate Python RLIMIT launcher. This creates a time-of-check /
time-of-execution gap: a same-user process with sufficient access can replace
or alter the staged file before `execve`. A correct input digest did not pin
the actual bytes which the kernel loaded.

## New execution contract

On Linux, `_sealed_shadow_executable` writes the previously hash-verified
bytes to a private `memfd_create(MFD_ALLOW_SEALING)` object, sets executable
mode and asks the kernel for all four seals:

- `F_SEAL_WRITE` — deny content mutation, including via proc FD re-open
- `F_SEAL_GROW` and `F_SEAL_SHRINK` — deny truncation or extension
- `F_SEAL_SEAL` — make the seal set permanent

It **rechecks** the actual seals, byte size and content. Only then does the
bounded launcher inherit exactly that FD via `Popen(pass_fds=...)` and call
`execve("/proc/self/fd/N", ...)`. This also handles scripted finite test
oracles whose shebang interpreter needs the descriptor to survive exec.
The parent owns and closes its FD after launch/observation. Neither its
resource policy nor canonical Python `verify_program` is replaced.

If memfd creation, sealing, byte recheck, FD inheritance or execution fails,
the request fails closed. There is **no** temporary pathname fallback.

## Reproducible controls

```sh
python -m unittest tests.test_hia_rust_sealed_exec -v
python -m unittest tests.test_hia_rust_crosscheck \
 tests.test_hia_rust_shadow_limits tests.test_hia_rust_crosscheck_cli -v
python -m unittest tests.test_hia_program tests.test_hia_rust_scalar_vm -v
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
```

New tests examine Linux F_GET_SEALS, real kernel pwrite/ftruncate refusals,
FD close, a deliberately modified original executable in the pre-exec window,
a successful existing fake-script witness from the **sealed** image, and
failure before transport when memfd support is blocked.

**Actual isolated Linux kernel control** in the authoring environment:
Python 3.13.5 created a sealed memfd; pwrite was denied, and a real shebang
script executed successfully from inherited `/proc/self/fd/N`. This
is an independent syscall/launcher probe, **not execution of the committed
full Hepta module**, Rust compiler or native HIA artifact.

## Remaining security obligations

Kernel seals provide **image content immutability**, not an overall sandbox.
Same-user ptrace, inherited file descriptors, namespace/FS visibility,
non-exhaustive native seccomp restrictions, aggregate cgroup/CPU/RSS controls,
host tampering, host kernel bugs, source/native equivalence, real Agent A/B,
GPU/DMA hardware and production p99 remain outside this change. The
`rust_is_production_admission_authority`, soundness and backend-refinement
claims remain false. Full exact-HEAD regression tests are not reported as
passed until actually executed.

`whole_project_blockers_closed=false`.
