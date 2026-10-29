# HIA continuation: explicit Rust frames and actual CI refusals

This increment continues the public source
`1669ddc05a918e7c01b17e9262d4461130d44aaa`. It closes specific implementation
and qualification gaps. Python remains the production admission and execution
authority. Optimization policy remains `no_change`; all broad P0–P7 closure
claims remain false.

## Same Machine, explicit language call frames

Rust no longer recursively calls the host interpreter for each language call.
An explicit frame stack retains the caller's operation index, pending call,
SSA environment, parameter loans and returned-loan origins. Returning from a
callee restores that caller and binds its checked results. All frames share
the original Machine and ByteMemory ledger. A trap or evaluator stop retains
the stopped resources; dropping interpreter frames is not reported as program
cleanup.

The separate [bound-v3 contract](HIA_RUST_BOUND_BUDGET_V3.md) accepts the Python
evaluator's three budget ceilings: 256 root-inclusive frames, ten million
allowed ticks and 1 GiB of logical payload/node bytes. The previous v1/v2
protocols and policy ceilings remain unchanged. The new envelope binds the
actual version, program, entry, typed arguments and all policy fields; a
rehashed result or a result from another envelope version cannot authorize
execution.

The finite corpus exercises all 256 depth policies, deep returned loans and
chains, normal returns and exact stopped ledgers, ten million actual allowed
ticks, and allocation/release of 16 MiB plus one byte. The upper heap-policy
test refuses an over-limit request before allocation. It does not observe a
successful 1 GiB allocation and does not measure process RSS. A separate
small-host-stack Rust control uses a 512 KiB thread stack. No whole-platform
native stack bound follows from that observation.

The complete Python API is still broader: Rust retains a `u64` allocation-
failure index and a bounded scalar public transport. General memory/provenance,
arbitrary recursive ADTs, escaping foreign lifetimes, asynchronous cancellation
and complete cleanup are not added here. These exclusions and the absent
deployment/refinement qualification prevent a Rust production-authority switch.

## Preserve the selected LLD executable while choosing its ELF driver

The hosted full-release run
[40799429611](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40799429611)
for `1669ddc` rejected `rust-lld --version`. Generic LLD dispatchers require a
driver selection. The integrated tool probe already supplied `-flavor gnu`,
while other tool probes and the actual filecheck linker path did not.

The common version probe now supplies that flavor as the first argument.
Actual Clang links use a temporary `ld.lld` spelling of the same selected
executable when the selected path names a generic `lld` or `rust-lld` driver.
This is necessary because Clang appends `-Wl` arguments later, while generic
LLD reads `-flavor` at its first argument. The intermediate attempt to pass
`-Wl,-flavor,gnu` is retained as a failed experiment.

The adapter records the original invocation, resolved executable and SHA-256;
it verifies the selected path and temporary alias before and after execution.
Changing either to another executable refuses qualification. The alias is
removed after normal completion or a raised exception. Trial owns its context
through build and all finite validation phases, so a cleanup or identity error
also produces a failed report. This does not authenticate a hostile machine or
provide a sealed-execution theorem.

Full LTO, the native CPU policy, complete positive/negative CPU features and
the original eight experimental routes are preserved. The controlled raw-IR
SIGILL negative case remains a required refusal; actual bound-IR and C controls
must execute under the same masked CPU. Preparation alone remains
`prepared_not_measured` and supplies no new performance advantage.

The same hosted run's standalone HIA regression also observed a timeout in
the `fork_and_stall` syscall-refusal control. That test required exact `SIGSYS`
but allowed only 200 ms from Python worker startup; the other fork control
already allowed three seconds. Both fork controls now use that normal
observation window and still require `SIGSYS`. A deliberate 350 ms pre-fork
initialization makes the distinction executable. The independent non-forking
stall still requires its 200 ms timeout and the marker/descendant-absence
check remains. Production timeouts, seccomp and process cleanup are unchanged.
The old runner did not record the child's precise startup phase, so the
controlled delay does not reconstruct that missing historical detail.

## Strict qualification results and preserved history

The new v3 collector requires its complete method denominator and zero
failures, errors, skips, expected failures and unexpected successes. A real
`unittest.expectedFailure` can leave `wasSuccessful()` true even after a method
records observations and then fails; it must not grant qualification. Dedicated
tests execute that case and every other non-pass outcome.

The reviewed safety matrix retains all 80 previously selected methods and
adds eight v3 execution/refusal methods, two LLD identity/cleanup methods and
four strict-result methods and one exact syscall/timeout control: 95 unique methods in the same 16 capabilities.
The integrated full-regression coverage requires both new Rust modules and
the existing native syscall/timeout module whose control was corrected.
Counts from component, safety, full-regression and independent review runs
overlap; they are never summed as independent tasks.

Automatic workspace cleanup interrupted publication of the earlier local
supplement. The original component archive and all 31 hosted artifact ZIPs
were recovered and anchored on the
[evidence branch](https://github.com/TrillionniumFoundation/Hepta/tree/codex/hia-core-closure-evidence-20261029/evidence/hia_core_closure_20261029).
The old local 3,614-test raw report and its frozen supplement were not recovered.
Summary text is not substituted for those records. The subsequently completed
hosted full-release failure is retained under its original source identity.
New component and integrated-source observations keep their own exact source
identities and actual limitations.

The recovered Windows C++ reports also distinguish ordinary CRLF checkout
bytes from raw Git blob bytes. Locked upstream header and license checks remain
strict. A platform's observed checkout conversion is not relabeled as universal
byte equality across all hosts.

## Strict remaining obligations

The complete [P0–P7 table](HIA_CORE_CLOSURE_20261028.md#broad-p0p7-closure-remains-open)
still applies. This increment removes the old Rust three-budget-ceiling gap
within the declared finite primitive Core profile; it does not close production
API/semantic coverage, authority switching, general direct-LLVM ABI, complete
historical migration, independent real-task efficiency, physical-device/RSS/
representative performance qualification, or implementation soundness and
backend refinement proofs.
