# Complete stb_divide migration and native service study

`tools/qualify_hia_stb_service.py` joins the existing real-module maintenance
qualifier, actual Core resource admission, interpreter execution, actual LLVM
build and eight native comparison arms. It does not replace the capture,
translator, Core verifier, resource analyses or LLVM builder with a benchmark
implementation.

The module is the complete active six-function `stb_divide.h` integer module
under `C_INTEGER_DIVISION_TRUNCATES`. This is a small arithmetic component;
completion does not mean that all of STB, libc, GSL or a C/C++ application has
been migrated. The retained workload is a long-running, in-process arithmetic
service harness using the real module. It is not production traffic or an
application-level performance result.

## Source maintenance and functional contract

The mandatory first stage is the existing
`qualify_hia_stb_divide_update.py` (historical path `../tools/qualify_hia_stb_divide_update.py`; not shipped in this tree).
It pins both full upstream headers, captures their exact compile configuration,
migrates all six definitions, lowers both versions to Core and direct LLVM,
and retains original C, Core interpreter and native observations. The service
stage uses the freshly translated 0.94 source without editing the translated
function bodies.

The upstream history is:

- [0.93 source, `dcb1116f1351bc8edad059d9ca432e8f322ba922`](https://github.com/nothings/stb/blob/dcb1116f1351bc8edad059d9ca432e8f322ba922/stb_divide.h).
- [Semantic fix, `c38ec91d229cbe56167f8af865c05b3d92db705f`](https://github.com/nothings/stb/commit/c38ec91d229cbe56167f8af865c05b3d92db705f).
- [0.94 source, `003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5`](https://github.com/nothings/stb/blob/003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5/stb_divide.h).

The upgrade changes active arithmetic in `stb_div_floor` and `stb_mod_eucl`.
The earlier qualifier distinguishes common defined inputs from four witnesses
where old original C has undefined intermediate arithmetic, the old checked
translation traps, and the successor returns a defined result. It includes
stale/wrong-image controls and invalid-input traps. Old undefined behavior is
not recorded as successful equivalence. The source fixtures include the
original license text and are not a rewritten approximation of upstream.

The service adds six explicitly authored error-return wrappers, identically
specified for HIA, original C/C++, and the independent Rust implementation:

| Public service function | Defined successful result |
| --- | --- |
| `service_stb_div_trunc` | Quotient truncated toward zero |
| `service_stb_div_floor` | Quotient rounded toward negative infinity |
| `service_stb_div_eucl` | Euclidean quotient, with nonnegative remainder |
| `service_stb_mod_trunc` | Remainder corresponding to truncating division |
| `service_stb_mod_floor` | Remainder with the divisor's sign when nonzero |
| `service_stb_mod_eucl` | Remainder in `0, abs(divisor))` |

Every function has the Linux x86-64 C ABI `int64_t(int32_t, int32_t)`.
Successful results are signed 32-bit integers. A zero divisor returns
`2147483648`; `INT32_MIN / -1` returns `2147483649` in all six functions before
performing arithmetic. These two values cannot be mistaken for a successful
result. The invalid pair is rejected for remainder operations too, matching
the declared service domain and avoiding the C/Rust division overflow case.
This authored service contract does not silently change the original raw
six-function API or claim that old upstream undefined behavior was defined.

Inputs are exact signed 32-bit integers. Boundary tests include `INT32_MIN`,
`INT32_MAX`, sign changes, zero and the error pairs. The bounded input reader
rejects malformed, incomplete and out-of-range records without relying on
out-of-range `scanf` integer conversions. Each native request checks every
actual function result against the independent integer oracle. A deliberately
wrong shared library fails the same driver.

## Resource admission on the same module

The fixed policy is:

```json
{
  "max_allocator_interactions": 0,
  "max_live_heap_bytes": 0,
  "max_vm_ticks": 70,
  "max_call_depth": 3
}
```

This policy is required by both `execute_program` and
`build_program_native`, through the existing composed
[`qualify_bounded_resources` (historical path `HIA_BOUNDED_BYTE_PROFILE.md`; not shipped in this tree) admission. The
current translation has 18 explicit exports: six original translated bodies,
translation helpers and six service wrappers. Every explicit export and the
private definition graph participates in the reused analyses; the profile is
not applied only to the fastest service entry. The longest structural bound
is 70 interpreter events and three root-inclusive frames.

A mandatory negative build lowers the tick policy to 69 and requires
`E_HIA_BUDGET_EXCEEDED` before LLVM/artifact publication. The successful native
receipt and every interpreter observation bind the same immutable Core and
recomputed resource receipt. The evidence stores one full resource receipt
and its digest with each interpreter result to avoid duplicating the complete
analysis 1,542 times.

The module contains scalar arithmetic and direct acyclic calls, so buffer
bounds, borrowed references and module allocation failure are absent from
this configuration. Zero requested HIA payload does not mean zero process
RSS, native stack, allocator metadata or loader allocations. The separate
bounded byte-resource tests cover allocation failure and borrow cleanup;
they do not become arithmetic-module observations by association. A resource
receipt does not prove source/LLVM refinement or rule out every program trap.

## Native comparison and optimization opportunity

The same driver loads each arm through `dlopen`, resolves the six service
symbols and keeps the module loaded for all requests in that process. Calls
are made through function pointers, and every result is checked, so an
optimizer cannot replace the workload with a constant summary. The checksum
uses explicitly defined unsigned 64-bit modular accumulation.

| Arm | Compiler and optimization policy |
| --- | --- |
| `hia` | Existing admitted direct LLVM builder, Clang 20+, `-O3`, generic target; bounded resource policy required |
| `c-generic`, `cpp-generic` | Original unmodified header plus wrapper, GCC/G++, `-O3 -flto -fno-semantic-interposition -ftrapv -march=x86-64` |
| `c-native`, `cpp-native` | Same original source and checks, `-march=native` |
| `rust-generic` | Independently authored `no_std` Rust, `opt-level=3`, fat LTO, one codegen unit, panic abort, overflow checks on, `target-cpu=x86-64` |
| `rust-native` | Same Rust source and checks, `target-cpu=native` |
| `rust-native-pgo` | Same native Rust plus profile generation, fixed training, matching Rust LLVM profile merge and profile-use recompilation |

All Rust arms explicitly link libc for abort and the instrumented profiler's
exit hook; this is not a special change to the measured PGO source. Ordinary
module calls have a common no-interposition contract. The C/C++ flag prevents
shared-library symbol interposition from forcing extra internal PLT calls
when HIA/Rust can use direct calls. The exported service ABI still uses the
same dynamic call boundary for every arm.

The HIA admission/build path is used as shipped. Its current generic target
is not relabeled as a tuned target or claimed to have identical flags to
Rust/GCC. Generic and hardware-tuned comparisons remain separate, and the
strongest Rust comparator has an explicit PGO opportunity. The study does not
infer a language advantage from compiler-family differences. C/C++ functional
regressions additionally run the original header with undefined-behavior
sanitization; sanitizers are not added only to timed competitor arms.

Integer overflow and error semantics are fixed. The service itself does not
allocate or use buffers, so this particular comparison cannot establish an
advantage for allocation or bounds-check policies. Source-to-Core translation,
all-input arithmetic equivalence and LLVM-to-machine-code refinement remain
separate obligations. The canonical runtime calls and machine-code checks
are real finite evidence, not proofs over all 32-bit pairs.

## Fixed workload, costs and limits

[`PROTOCOL.json`](../benchmarks/hia_stb_service/PROTOCOL.json) freezes eight
arms, four groups, 41 samples per arm per group, 128 repetitions per sample
and 257 input pairs. Each pair requests all six functions. The 257 pairs
contain a 10-by-10 boundary grid and deterministic full-range integer inputs.
A sample performs 197,376 scalar calls. Arm order rotates by group and
reverses on odd groups. No result-based retries, discarded samples or outlier
removal are allowed. Each process performs one paid, checked warmup pass.

Rust PGO uses 129 deterministic training pairs disjoint from the evaluation
pairs, repeated 256 times. The PGO instrumented binary also performs the
same driver's cold request and warmup, using only those training pairs.
The evaluator rejects missing profiles, incompatible LLVM major versions,
profile-use warnings and incorrect training results. Training, instrumentation,
merge and final compilation are all retained and paid. Disjointness is not a
claim that these source-visible evaluation tasks are secret or unseen by a
model.

The report retains:

- All attempted external commands, exit status, raw stdout/stderr and measured
  process wall cost, including failed commands.
- Original migration/upgrade cost, source lowering, individual builds and
  PGO preparation. `whole_wall_ns` includes children, postflight and readback;
  child stage costs must not be added to it again.
- Actual call denominators and every raw batch timing, with nearest-rank
  median, p95 and p99 computed from all 164 samples per arm.
- Dynamic loading, symbol resolution and first-request time, plus full process
  delivery wall cost. The latter includes harness startup, corpus reading,
  execution, verification and result output for the fixed declared workload.
- Maximum process RSS and image size. RSS includes the common driver and
  runtime; it is not a native module heap or stack bound.
- Compiler identity/version and source hashes, CPU affinity and a declaration
  that the host is shared. Affinity does not isolate frequency, contention,
  thermal state or other tenants.

A batch p99 is **not individual request p99**. This small arithmetic service
also does not establish behavior in a network server, large application or
production load. No superiority threshold is encoded: a complete slower
result is retained as a complete slower result. Human maintenance time is
`null`; automated elapsed time does not measure human review burden. Initial
development, toolchain provisioning, and earlier failed experiments are
outside a particular invocation's wall ledger and must be reported separately
when making lifecycle-cost claims.

`module-candidates.json` exposes the exact same module's eight artifact IDs,
build/preparation costs and evaluation timing/RSS for downstream experiments.
It grants no adoption authority. Consumers must not relabel its evaluation
measurements as policy training or proof of NDU benefit. They must establish
an independent calibration/holdout protocol, charge controller and bank
costs, and check for identical machine code before counting compiler arms as
distinct useful choices. This file itself does not evaluate an NDU controller
or constrained RSI generation.

## Run and read back

Commit the source changes before qualification. The source gate requires the
exact full commit, a clean checkout, raw Git blob agreement, matching file
modes and no injected ignored files in the source closure. It does not trust
index cleanliness alone. Output must be a new directory outside the checkout.
Do not run other performance campaigns concurrently.

```sh
python -B -m unittest tests.test_hia_stb_service -v
python -B tools/qualify_hia_stb_service.py \
  --output /absolute/outside-checkout/stb-service-run1 \
  --source-sha "$(git rev-parse HEAD)" \
  --clang /absolute/clang-20 \
  --cc /usr/bin/gcc --cxx /usr/bin/g++ \
  --rustc /absolute/rust-1.95.0/bin/rustc \
  --rust-profdata /absolute/rust-1.95.0/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata \
  --stage study
```

`--stage qualification` runs the full changed-body upgrade, bounded resource
checks, original C/C++, all Rust/PGO builds and functional observations, but
omits the repeated performance campaign. Its result is not a performance run.
A failed run retains `report.json` and collected children; repair the cause
and use a new output directory, without erasing the failed attempt.

`validate_qualification(output)` rereads the inventory and reconciles the
registration, exact current source, freshly rederived Core/LLVM/resource
admission, earlier upgrade evidence, all native outputs and every timing
summary. It does not execute archived native binaries or establish a trusted
signature for wall timing. Re-reading after moving to a different source
commit is deliberately rejected. `DENY_ALL` remains explicit throughout;
these records are not production admission credentials.
