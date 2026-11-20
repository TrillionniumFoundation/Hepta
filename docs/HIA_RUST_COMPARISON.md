# HIA and Rust: implementation and comparison work

The engineering target is to extend independently checked native execution
across HIA's supported language and to improve measured workloads against
same-host optimized Rust. A completed kernel, source test or bootstrap fixed
point closes its own obligation. Every additional language family needs its
own semantics, machine-code validation and execution evidence.

## Current work and closure criteria

| Area | Implemented work | Remaining closure criterion | Existing verification source |
| --- | --- | --- | --- |
| Register scalars | Direct caller-saved register entry; unsigned v2–v5 and signed integer v6 arithmetic, casts, comparisons and shifts; independent final ELF refinement | Complete the fixed signed/Rust performance matrix and extend independently checked general call and loop behavior | `tests/test_hia_safe_core*.py`, `tests/test_hia_verified_scalar*.py`, `ScalarExecutionTests` in `tests/test_hia_program.py` |
| Borrowed byte loops | Sum, all-zero detection and nonoverlapping copy; complete range admission; SSE2, AVX2 and AVX-512 candidates; reversible SSA/block renaming | Address every observed performance regression in the complete matrix; retain all earlier samples | `tests/test_hia_verified_simd*.py`, `benchmarks/hia_verified_kernels/PROTOCOL.json` |
| Standard build entry | `hia build --kind shared` defaults to verified auto selection and host-native ISA; both CLI owners implement the same route; matching-source cold/native/wheel qualification recorded for `633feee` and `60409ea` | Requalify each later source extension and complete the separate broader native-component workflow | `tests/test_hia_agent_entry.py`, `tests/test_hia_verified_cli.py`, `tests/test_hia_cli_native.py` |
| Actual loading | Fresh CPU/OS observations; independent proof rerun; sealed bytes bound to actual mapped code; no target dlsym | Preserve these invariants for each additional image/ABI profile | `tests/test_hia_verified_cpu.py`, `tests/test_hia_verified_kernel_load.py` |
| Proof input identity | Executing decoder, canonicalizer, hash and primitive admission modules bound before input admission and rechecked at proof completion; actual selected native helper mappings and source bindings recorded | Independently refine the selected native input helpers' semantics; preserve the input closure for each new language family | `tests/test_hia_verified_input_identity.py`, `tests/test_hia_verified_input_native.py` |
| General calls and loops | Ordinary native lowering and execution tests exist | Independent call/return and loop-invariant validation for the supported general Core, including failure and resource effects | `DirectExecutionTests` in `tests/test_hia_program_native.py`, `tests/test_hia_program.py` |
| Ownership and heap | Capability-flow admission, allocation/move/drop/loan rules and native effects are exercised | Connect static capabilities and runtime heap provenance, calls, returned loans, chains and lowering in one soundness argument | `formal/HiaCapabilityBorrow.lean`, `docs/HIA_CAPABILITY_BORROW_ACCESS.md`, `tests/test_hia_capability_flow.py` |
| Concurrency and asynchronous work | Cooperative composite task protocol | Define and implement shared-memory ownership, synchronization, scheduler and cancellation semantics, then validate races and lifetime transitions | `tests/test_hia_program_composite.py`, `tests/test_hia_semantics_contract.py`, `hepta/hia_program.py` capability report |
| Foreign pointer lifetime | Synchronous numeric range/null/wrap/overlap admission and exact byte-effect controls | Establish allocation provenance, liveness and exclusive-write authority at the actual foreign boundary | `hepta/hia_native_byte_abi.py`, `tests/test_hia_native_byte_abi.py` |
| Bootstrap and targets | Bounded Linux x86-64 self-hosted compiler and native component workflows | Complete current-source B0/B1/B2/B3 and modified-source replay; qualify additional language/target families separately | `docs/HIA_SELFHOST_CORE_SUPPORT.json`, `.github/workflows/hia-core.yml` |
| Product and project throughput | Standalone source, agent integration and native component entry points | Runtime/library, durable publication/recovery, native-only installation and clean-machine real-project workloads | `docs/HIA_PROGRAM.md`, `docs/HIA_CORE_ONLY_SCOPE.md`, existing component qualification tools |

The current general Core/native operation inventory is broader than the Safe
Core final-code model. Owner/chain/loan operations and arbitrary calls and
loops are not admitted merely because the ordinary backend can execute their
tests. Signed integer arithmetic is covered by v6; the closed borrowed-byte
recurrences are separately proved additions to that model.

## Performance comparison discipline

The third protocol retained every previous comparison arm and original length,
added AVX2/AVX-512, and expanded to 23 boundary-focused lengths. Its 487 cases
ran 21 measured batches after three warmups: 10,227 retained samples. The fourth
protocol retains that full matrix and adds both original wide-copy byte-tail
arms at every length, totaling 533 cases and 11,193 samples per campaign.
The fifth protocol retains all 533 original cases with their original machine
profiles, and adds the two ISAs' bounded sum/zero tails and fast one-byte copy
dispatch: 671 cases and 14,091 samples. A new default receives a separately
named arm; changing a default does not silently replace a control.
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

All five recorded campaigns and their exact source identities remain in
`benchmarks/hia_verified_kernels/results/`. The initial 64 KiB zero-scan
regression and its four-accumulator repair are preserved in
`docs/HIA_VERIFIED_KERNELS.md`. The third complete campaign has 487 cases,
10,227 samples and six wide proof/CPU receipts. AVX-512 sum is faster than
Rust on the listed 4 KiB and 64 KiB inputs, but 45 of its 69 span medians are
higher; the worst ratio is 8.241 at 127-byte copy. The complete comparison,
including every slower row, remains in `ai395-20261119-wide-comparison.json`.
Changes made after measured source `93bccb9` do not inherit these timings.

The fourth full campaign binds all 533 cases, 11,193 samples and eight wide
proof/CPU receipts to `60409eacc6cda870d2be1d090f2c66b682c9466b`.
Its AVX-512 endpoint copy reduces the 63-byte median from the simultaneous
old byte-tail control's 14.871 ns to 1.420 ns, and the 127-byte median from
14.890 ns to 1.688 ns. AVX-512 has 32 lower and 37 higher span medians than
Rust; AVX2 has 29 lower and 40 higher. The all-zero and sum short tails,
4 KiB copy and 64 KiB all-zero scan remain slower examples. One-byte copy
suffixes also regress against their byte-tail control. Every such row and
all raw samples remain in `ai395-20261120-endpoints.json.gz` and its summary.
These results motivate the fifth protocol's additional candidates; they do
not establish their performance before that new campaign runs.

The fifth campaign binds 671 cases, 14,091 samples and fourteen wide proof/CPU
receipts to `e9de97cee2a44cfbe044b245f2cf344c2cc3ef47`. New AVX-512 defaults
have 42 lower and 27 higher span medians against Rust; AVX2 has 40 lower and
29 higher. Exact vector boundaries and 0/1-byte suffixes still expose guard
chain overhead. The original driver also leaves absolute buffer alignment and
source/destination distance uncontrolled after DSO loading. Stable large-copy
differences therefore cannot be attributed solely to changed machine code.
All observed samples remain in `ai395-20261120-bounded.json.gz`; a new protocol
must separately fix and record those address conditions and both copy address
orders. Protocol v6 first retains the original driver and all 671 controls,
and adds 92 explicitly named one-byte reduction candidate cases. Its 763 cases
and 16,023 samples therefore retain the original address-layout limitation.
The address-controlled extension requires another complete campaign, without
transferring old ratios or replacing the existing control samples.

## Signed integers and input execution identity

Safe Core v6 extends final-image validation to `i8`, `i16`, `i32`, `i64` and
`isize`, together with the existing unsigned types. The register producer,
ordinary checked fallback, build tools and sealed scalar loader select the
same version. The supplied-ELF consumer independently interprets signed Core
values, actual sign extension, arithmetic flags and signed division; it does
not reproduce the producer. Previous profile domains remain unchanged.

Signed values use raw SysV argument words. Narrow values are interpreted from
their low bits and sign-extended; negative returns are 64-bit two's-complement
words. Checked overflow, negative or oversized shift counts, zero divisors,
and `MIN / -1` or `MIN % -1` retain the original Core abort behavior. The
existing 15-second default proof deadline is unchanged.

The signed comparison protocol is declared in
[`PROTOCOL_SIGNED_V1.json`](../benchmarks/hia_verified_kernels/PROTOCOL_SIGNED_V1.json).
It contains 33 semantic cells and 66 HIA/Rust arms, with 64 legal input triples
per cell and separate invalid-input child-process checks. Every complete
measurement retains three warmups and all 21 measured batches. Preparation
and functional-only runs carry explicit non-performance status. Existing
unsigned/SIMD campaigns remain separate records.

The input audit reproduced a concrete false acceptance before the fix: an old,
timestamp-valid decoder bytecode cache transformed an addition into a
subtraction while retaining the addition's canonical source hash. The proof
and final execution agreed on the wrong decoded program. A stale payload
hasher could similarly falsify the reported Core identity. The corrected
consumer binds the executing input modules before decoding, records actual
selected native input mappings, and rechecks the identities before returning.
The input module and native route inventory is part of the fresh proof, not
a claim derived solely from a source filename or a previously saved report.

These additions close the signed scalar and reproduced input-identity defects
within their explicit contracts. General calls and loop invariants, heap and
foreign allocation lifetimes, shared-memory concurrency, complete native
bootstrap and real-project performance retain their own entries above.
The native helper receipt identifies operator-selected trusted code; its
`native_semantic_refinement_proved` field remains `false`. Identifying the
helper that executed does not establish the helper's semantic correctness.
