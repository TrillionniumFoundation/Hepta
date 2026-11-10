# Finite standalone HIA on a native Linux AArch64 host

The existing `run_finite_program_aarch64` runner and qualification command
accept an explicit `execution="native"` / `--execution native` selection.
The default remains QEMU with its original v1 profile, status, counts and scope.

| Mode | Actual launch | Evidence scope |
| --- | --- | --- |
| Default `qemu` | Reviewed QEMU executable followed by the checked AArch64 ELF | User-mode emulation; original v1 report |
| Explicit `native` | Checked ELF directly, with no external runner argument | Measured Linux AArch64 LP64 host; separate native-host schema |
| Physical board | No automatic selection or inference | Remains a separate unexecuted qualification |

Native admission reuses the measured host ABI profile, requires Linux,
little-endian AArch64 and 64-bit pointer/size_t/long, and checks the kernel's
architecture observation as well. x86-64, non-Linux, unsupported ABI, unknown
execution modes, a QEMU path supplied for native execution, and an explicitly
selected QEMU executable as a target tool refuse. There is no fallback from a
failed native attempt to QEMU. These are OS/ABI observations, not external
hardware attestation; a hosted AArch64 VM is not a physical-board experiment.

## The same compiled program and driver

The selected primitive Core is freshly verified, lowered by the existing LLVM
backend and linked with the existing reviewed finite allocator and C caller.
The static ELF is checked by the same bounded loader/symbol inventory before
execution. The normal harness, 17 fixed ABI cases, two wrong-Core controls and
one bounds-abort control remain unchanged. The normal allocator observation is
four successful allocations, four releases, zero outstanding and one real NULL
refusal. This is the 4096-byte, one-live-allocation profile.

Bounds abort uses the reviewed runtime's `exit(134)` syscall, including in
native mode. It does not claim a host SIGABRT or cleanup after termination.
Wrong sum and wrong allocation-error Core variants must produce their original
nonzero exits, rather than obtaining acceptance from structural verification.

## Run only on the intended host

> Removed source/mixed-campaign reproduction command; its harness is not
> delivered. No historical result is promoted to current qualification.

The native qualifier requires a clean Git checkout and records its commit,
tree, compiler source hash, qualifier and fixture-producer hashes before and
after all four compiled executions. Each run retains checked Core/LLVM/runtime
and ELF identities, actual compiler/linker identities, host observations and
the direct launch command. Complete bounded raw command streams are retained
as hex with byte counts and completeness flags. Capture failures retain their
available prefixes and propagate; missing or incomplete streams cannot qualify.
No Rust frontend or alternate generator is introduced.

Native results use `hepta.hia.program.aarch64-native-host-qualification.v1`
and `finite_standalone_aarch64_native_host_corpus_passed`. Their
`finite_corpus_native_host_execution_passed` claim is independent from
`finite_corpus_qemu_execution_passed`; `physical_board_executed` and
`hardware_attestation_proved` remain false. Merely adding an ARM CI job does
not establish that the native command executed or passed.

An x86-64 development host can run the native refusal controls and the complete
original QEMU qualification. It cannot produce a successful native AArch64
receipt. General ABI coverage, other operating systems, physical devices,
hardware performance and whole-backend refinement remain separate gates.
