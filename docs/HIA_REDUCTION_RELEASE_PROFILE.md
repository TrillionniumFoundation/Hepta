# Checked byte reduction: proof chain and release qualification

> Historical finite Core/native observations; removed harnesses are not
> delivered product entry points or current-source qualification.

This profile connects the existing inductive checked-reduction pass to a new,
independently verified low-byte arithmetic pass and a strong native comparison.
It does not change the Core opcode semantics, the LLVM backend, resource
operations, or allocator-failure policy. A negative timing gate remains a
completed campaign result.

## Implemented path

`hepta/hia_reduction.py` exposes `propose_byte_narrowing`,
`propose_reduction_pipeline`, `verify_reduction_pipeline`, `reduction_program`,
and `build_reduction_native`.

1. The untrusted proposer recognizes unsigned modular arithmetic truncated to
   `u8`. It proposes equivalent byte arithmetic for wrapping add, subtract,
   multiply, and bitwise AND/OR/XOR. Existing scalar operations are retained;
   checked operands still execute and can trap. New nontrapping instructions
   occur at the original truncation, without moving resource effects.
2. `hia_optimization.verify_optimization` independently checks every scalar
   segment, first-trap outcome, effect operand, and CFG edge operand for all
   bit-vector inputs in their declared widths. Recognition does not constitute
   proof. Counterexamples, UNKNOWN, deadlines, and unsupported profiles cannot
   proceed to native publication.
3. The existing `hia_guarded_optimization` pass proposes and independently
   checks loop invariants. The runtime guard is
   `n <= floor((2**64 - 1) / 255) = 72,340,172,838,076,673`.
   It precedes every original effect. At the loop header, `i <= n` and
   `acc <= 255*i`; at the body, `i < n` and `acc <= 255*i`. Every CFG edge must
   preserve these facts, and each removed checked addition must be unable to
   trap at its actual instruction position. Arithmetic in the invariant is
   widened to 128 bits, preventing a modular multiplication from making the
   bound falsely true.
4. Outside that guard, the complete checked reduction remains in the fallback.
   Its preceding low-byte rewrite has the independent all-input equivalence
   proof from step 2. The gate never converts a benchmark length limit into an
   `assume`, and the full program remains checked outside the measured profile.
5. Both proofs run again when building. Their exact source, intermediate Core,
   final composed Core, solver identities, compiler identity and artifact bytes
   are bound together. Checker and solver identities are rechecked around
   publication; a changed implementation prevents or withdraws publication.

The scalar rewrite and induction are two separately budgeted verifications.
Saved JSON receipts cannot authorize compilation. The native builder receives
canonical admitted Core, not custom or externally supplied LLVM.

### Counted-step extension

`propose_reduction_pipeline(..., include_induction=True)` also proposes removal
of the fill-loop and reduction-loop index overflow checks. The option requires
an actual boolean and defaults to false, preserving the original proposal.
Both sequential and affine byte workloads then have three separate
`removed_check_cannot_trap` obligations: fill index, sum, and reduction index.
The existing independent invariant checker discharges every obligation; the
proposer introduces no unchecked instruction annotation. Nonzero initial sums
cannot inherit the zero-prefix bound. The successful and refused allocation
traces, both sides of a small guard, and the original checked fallback remain
part of semantic and native regression checks.

This connects the same counted-step proof used by the single-kernel narrowed
release path to the general two-workload pipeline. It does not introduce a new
Core opcode or modify native lowering.

## What is and is not established

| Property | Coverage |
| --- | --- |
| Low-byte rewrite preserves modeled scalar/effect/first-trap behavior | Every declared scalar input of each admitted primitive Core v1-v7 program whose independent equivalence check completes successfully |
| Removed reduction overflow checks cannot trap | All loop iterations admitted by the executed guard and successfully discharged invariants; not merely tested lengths |
| Behavior beyond the fast guard | Complete checked fallback, after the separately proven scalar rewrite |
| Resource instruction order and allocation-failure sequence | Same Core trace under the checker model; native probes provide additional scoped execution evidence |
| Native lowering correctness | Existing trusted LLVM compiler/backend boundary; no new backend refinement theorem |
| Performance | Only the registered workload, toolchain, sizes, seeds, allocation probes and observed host |
| Whole-language type/ownership soundness, concurrency or hardware safety | Not established by this pass |

The induction overapproximates successful byte loads as arbitrary `u8` values.
It does not assume the benchmark fill formula, sample checksum or future
memory contents. Resource effects remain barriers. VM step counts, proof work,
code size, compiler costs and timing are separate observations; equivalence
does not assert they are unchanged.

## Registered native comparison

`retired harness qualify-hia-reduction-release` freezes its protocol and source hashes
in a new output directory before compiling or timing. It builds four arms:

| Arm | Implementation |
| --- | --- |
| `hia_checked` | Original checked Core through the production O3 LLVM path |
| `hia_reduction` | Two-stage independently verified pipeline through that same backend |
| `rust_release` | Existing Vec-based source, opt-level 3, fat LTO, one codegen unit, panic abort |
| `rust_byte_release` | The same Rust ownership/allocation code with explicit equivalent byte arithmetic, with the same release flags |

The second Rust arm prevents crediting HIA solely for a favorable source
expression against an unnecessarily wide Rust fill. This profile binds actual
Rust 1.95.0 and actual Clang 20+ identities, using generic x86-64 code generation.
It is not a replay of earlier Rust 1.90 evidence.

Two fixture families fill, sum, and release a fallibly allocated owned byte
buffer: sequential byte values and an affine byte sequence. They differ in
arithmetic and byte distributions, but are related allocation/reduction
workloads, not two independent real applications. For both, the original Rust
release sum is non-overflowing on every successful measured input. Rust's
release overflow semantics outside the measured profile are not asserted to
equal checked HIA; huge-input tests force allocation refusal before reduction.

The protocol includes prior development lengths 0, 1, 64, 257, 4096, 8193 and
65536, plus held-out lengths 13, 127, 509, 2053, 12289, 65521, 131071 and 262147.
Seeds 383, 659 and `u32::MAX` cover differing and wrapping byte values. There
are 21 batch observations per seed, 64 calls per batch and 3 warmup calls. Each
workload/length/arm therefore retains 63 batch observations, including outliers.
Order rotates and reverses by seed; no retries or favorable-run selection are
part of the protocol. Both Rust arms must satisfy median ratio <= 1.10 and p95
ratio <= 1.20 for the all-length Rust gate. Empty and one-byte failures remain
in that gate.

### Separate multi-load protocol v2

`--profile induction-multiload-v2` enables the counted-step extension and creates
a separate prospective registration. The original v1 registration is byte
identical under canonical serialization (SHA256
`4641c52985ab1b25168117ffac3fc142daf59197948836d3932c67d23c84c8e7`).

The v2 profile uses the same seven regression sizes, new timing lengths
19, 73, 269, 1051, 4109, 16421, 65557 and 262171, and seeds 5471, 6761 and
4294967291. Each workload and size is separately measured at 1, 16 and 64 calls
per batch. There are 1,080 native timing requests, 22,680 retained batches and
612,360 timed kernel calls. Ninety workload/size/load cohorts produce 180
comparisons against the two Rust arms. Load identities cannot be pooled: a
tail failure for one call per batch remains a failure even if 64-call batches
are fast. The median limit stays 1.10, the p95 limit stays 1.20, and v2 also
requires p99 <= 1.20. Empty and one-byte cohorts remain in the gate.

The new axes are distinct from this tool's v1 axes. They are not asserted to
be unseen in every previous experiment. Both Rust sources retain opt-level 3,
fat LTO, one codegen unit and panic abort; this two-workload protocol does not
include Rust PGO. The prior single-workload PGO campaign remains separate and
cannot be superseded by this comparison. Clang 20+ remains mandatory through
the unchanged native admission path. One run on the frozen implementation is
retained irrespective of its outcome; stronger or broader parity remains open.

The native driver checks independent periodic checksum formulas, successful
allocation/free counts, requested and usable peak bytes, live bytes and refusal
results. Refusal-only probes execute lengths around the actual reduction
guard, `ISIZE_MAX`, and `U64_MAX`, with the first allocation refused. They do
not silently attempt a successful enormous allocation first. Native unit
coverage additionally uses a guard of 16, so ordinary successful executions
exercise both the fast branch and the original checked fallback.

## Complete cost and evidence

The campaign stores every bounded compiler stdout/stderr stream, actual argv,
LLVM input snapshot, solver query, raw driver request/response, disassembly,
tool and artifact hash, load/mapping observation, and sample. Its compiler
observer delegates to the real bounded subprocess implementation without
modifying arguments, budgets, outputs or return codes. Production Core
admission and artifact publication remain in the executed path.

Campaign wall time covers setup, proof, compilation, link, launches, loads,
cold calls, warmup, measurements, oracle validation and cleanup. Nested stage
and command durations are reported without being added again. Separate
amortization rows include build/proof/link/load costs and measured median
per-call costs. They compare the cheapest Rust total at each declared call
horizon and report the call count needed to beat both Rust arms, when one
exists. These horizons are a cost model, not claimed executed replay traces.
Manual engineering, energy and historical tool-acquisition costs remain null.

Source state, source hashes, tools and artifacts are checked again at the end.
An incomplete cohort, changed source, changed identity, checksum mismatch,
resource-accounting mismatch or failed child makes qualification invalid.
Performance failure alone does not invalidate faithfully collected evidence.

## Reproduction

With the registered Clang, Rust and pinned Z3 4.15.4 available:

> Removed source/mixed-campaign reproduction command; its harness is not
> delivered. No historical result is promoted to current qualification.

Run qualification from one frozen source combination. `REGISTRATION.json`
defines the cohort before native measurements; `RESULT.json` carries the
outcome, full receipts, costs, raw-evidence bindings and explicit limitations.
Do not replace a failed campaign with a later favorable run. A later run needs
its own registration, source combination and retained predecessor evidence.
