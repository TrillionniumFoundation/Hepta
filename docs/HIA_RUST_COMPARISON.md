# HIA and Rust: implementation and comparison work

The engineering target is to extend independently checked native execution
across HIA's supported language and to improve measured workloads against
same-host optimized Rust. A completed kernel, source test or bootstrap fixed
point closes its own obligation. Every additional language family needs its
own semantics, machine-code validation and execution evidence.

## Current work and closure criteria

| Area | Implemented work | Remaining closure criterion | Existing verification source |
| --- | --- | --- | --- |
| Register scalars | Direct caller-saved register entry; unsigned checked add/sub/cast in addition to wrapping arithmetic; independent final ELF refinement | Extend the checked domain to the remaining scalar operations and signed types, preserving traps and ABI behavior | `tests/test_hia_safe_core*.py`, `tests/test_hia_verified_scalar*.py`, `ScalarExecutionTests` in `tests/test_hia_program.py` |
| Borrowed byte loops | Sum, all-zero detection and nonoverlapping copy; complete range admission; SSE2, AVX2 and AVX-512 candidates; reversible SSA/block renaming | Address every observed performance regression in the complete matrix; retain all earlier samples | `tests/test_hia_verified_simd*.py`, `benchmarks/hia_verified_kernels/PROTOCOL.json` |
| Standard build entry | `hia build --kind shared` defaults to verified auto selection and host-native ISA; both CLI owners implement the same route; matching-source cold/native/wheel qualification recorded for `633feee` | Requalify each later source extension and complete the separate broader native-component workflow | `tests/test_hia_agent_entry.py`, `tests/test_hia_verified_cli.py`, `tests/test_hia_cli_native.py` |
| Actual loading | Fresh CPU/OS observations; independent proof rerun; sealed bytes bound to actual mapped code; no target dlsym | Preserve these invariants for each additional image/ABI profile | `tests/test_hia_verified_cpu.py`, `tests/test_hia_verified_kernel_load.py` |
| General calls and loops | Ordinary native lowering and execution tests exist | Independent call/return and loop-invariant validation for the supported general Core, including failure and resource effects | `DirectExecutionTests` in `tests/test_hia_program_native.py`, `tests/test_hia_program.py` |
| Ownership and heap | Capability-flow admission, allocation/move/drop/loan rules and native effects are exercised | Connect static capabilities and runtime heap provenance, calls, returned loans, chains and lowering in one soundness argument | `formal/HiaCapabilityBorrow.lean`, `docs/HIA_CAPABILITY_BORROW_ACCESS.md`, `tests/test_hia_capability_flow.py` |
| Concurrency and asynchronous work | Cooperative composite task protocol | Define and implement shared-memory ownership, synchronization, scheduler and cancellation semantics, then validate races and lifetime transitions | `tests/test_hia_program_composite.py`, `tests/test_hia_semantics_contract.py`, `hepta/hia_program.py` capability report |
| Foreign pointer lifetime | Synchronous numeric range/null/wrap/overlap admission and exact byte-effect controls | Establish allocation provenance, liveness and exclusive-write authority at the actual foreign boundary | `hepta/hia_native_byte_abi.py`, `tests/test_hia_native_byte_abi.py` |
| Bootstrap and targets | Bounded Linux x86-64 self-hosted compiler and native component workflows | Complete current-source B0/B1/B2/B3 and modified-source replay; qualify additional language/target families separately | `docs/HIA_SELFHOST_CORE_SUPPORT.json`, `.github/workflows/hia-core.yml` |
| Product and project throughput | Standalone source, agent integration and native component entry points | Runtime/library, durable publication/recovery, native-only installation and clean-machine real-project workloads | `docs/HIA_PROGRAM.md`, `docs/HIA_CORE_ONLY_SCOPE.md`, existing component qualification tools |

The current general Core/native operation inventory is broader than the Safe
Core final-code model. Owner/chain/loan operations, arbitrary calls and loops,
signed values and several checked operations are not admitted merely because
the ordinary backend can execute their tests. The closed borrowed-byte
recurrences are separately proved additions to that model.

## Performance comparison discipline

The third protocol retained every previous comparison arm and original length,
added AVX2/AVX-512, and expanded to 23 boundary-focused lengths. Its 487 cases
ran 21 measured batches after three warmups: 10,227 retained samples. The fourth
protocol retains that full matrix and adds both original wide-copy byte-tail
arms at every length, totaling 533 cases and 11,193 samples per campaign.
The Rust and C references, indirect-call driver, deterministic input generation,
per-batch checksums and copy-effect controls remain common across the arms.
The new runtime identity records libc and the selected memcpy implementation.

Each workload/length has its own Rust-to-HIA time ratio. A favorable aggregate
does not close a slower row. A tiny difference near the timing noise is a tie
or unresolved observation, rather than statistical evidence of superiority.
Small buffers, empty ranges, vector tails and large buffers remain visible in
the matrix. Original HIA packed-u32 timings concern the valid inputs where
results agree with the direct u64 ABI; invalid-input behaviors have their
separate functional checks.

These kernel comparisons are one stage. The remaining project matrix must
cover scalar arithmetic families, function-call graphs, loops, allocation and
ownership transitions, composite values, startup/proof cost, working sets
beyond cache, and real application throughput under matched semantics. The
repository has no finite test that establishes a speed ordering for every
possible HIA and Rust program. Claims are attached to the measured matrix and
declared proof domain as those domains expand.

## Evidence and adoption

Every result binds the tested source tree, compiler/solver/tool identities and
the actual final image. A later source edit requires its applicable gates
again. Documentation-only result commits identify the measured code parent
explicitly. Failed experiments and counterexamples remain in the record.
Draft review is separate from merge or production adoption.

All three recorded campaigns and their exact source identities remain in
`benchmarks/hia_verified_kernels/results/`. The initial 64 KiB zero-scan
regression and its four-accumulator repair are preserved in
`docs/HIA_VERIFIED_KERNELS.md`. The third complete campaign has 487 cases,
10,227 samples and six wide proof/CPU receipts. AVX-512 sum is faster than
Rust on the listed 4 KiB and 64 KiB inputs, but 45 of its 69 span medians are
higher; the worst ratio is 8.241 at 127-byte copy. The complete comparison,
including every slower row, remains in `ai395-20261119-wide-comparison.json`.
Changes made after measured source `93bccb9` do not inherit these timings.
