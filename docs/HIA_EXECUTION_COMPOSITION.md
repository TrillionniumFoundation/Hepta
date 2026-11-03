# Fixed-source execution campaign

This campaign uses one clean Hepta commit/tree, the native NDU stream source
`8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d`, explicitly selected as
`zero-abstain-v1`, and the fixed tool profile:
Linux x86_64, Clang 20, Rust 1.95.0, Z3 4.15.4, and the existing SHA-256-pinned
Lean 4.19.0 kernel. It does not relabel results as the earlier Rust 1.90 profile.
Historical `original-v1` stream callers still require the original
`c4a1bbed3a39beba43a6abf1a18b6f75c5725c21` source. Composition schema v2
records the corrected exact-zero abstention input profile and the distinct
`induction-multiload-v2` reduction protocol. NDU evaluator mathematics is unchanged.

`tools/qualify_hia_composition.py` builds NDU with its original Cargo.lock into
an empty target directory. It then writes `COMBINATION.json` before any HIA
qualification. The manifest pins every materialized source/fixture to its
actual HEAD Git blob, the full source tree, actual tool binaries, the loaded
Z3 bindings/library, native NDU build inputs, and the bridge binary/manifest.
The same combination must survive each phase and the final check. Git index
flags hiding a modified file cannot satisfy the clean-source condition.
Python optimization mode is refused; the registered child environment keeps
assertion-based qualification checks enabled and routes tools/dependency caches
through the explicitly selected paths.

The campaign performs actual Core rejection and durable pure-queue crash/replay tests,
Lean qualifications, an independently built Rust shadow, production capability
edge witnesses, the all-export sequential scalar proof chain,
native cancellation/verified-switch/single-use suffix recovery, the reduction
holdout, native full-cost NDU controls, and C++ reset/release migration with
fresh-Clang negative sources. It also requalifies the existing Microsoft GSL
v3.1.0/v4.0.0 final_action migration on the same tools, including the actual
old-version refusal/new-version acceptance of the non-const lvalue factory.
This is inherited, narrowly scoped upstream-upgrade capability revalidated
alongside the new unique_ptr profile; it is not a newly generalized C++
translator. Every child command has raw stdout/stderr and
an outer wall-time record, so Python startup and final report writing are not
silently excluded from the NDU build/experiment envelope. Nested costs must
not be added twice. Cargo dependency cache warmth is declared; an empty target
directory is not a claim of an entirely cold machine. Existing SQLite codec
upgrades and GSL conditional cleanup resource profiles also run on this exact
combination. Human migration time remains unmeasured.

The same campaign also runs the host-region qualification and the v2 Agent
tool controls. The former exercises actual Linux page protections, concurrent
readers, exclusive writers, timeout quarantine and joined-worker recovery.
It relies on the explicit trusted synchronous no-escape C contract described
in `HIA_HOST_REGION_PROFILE.md`; it grants no device/MMIO/DMA authority. Agent
model inference is a separately registered, commit-matched run after native
timing, so the model workload cannot interfere with the timing campaign.

## What the Core proof now covers

The production CFG verifier calls the extracted `rename_capabilities` helper.
`formal/HiaCapabilityRenaming.lean` contains 31 theorems for every finite selected
capability graph and every injective renaming, without a loop-unroll bound:
root equality, parent/child relations, parent suspension, the exclusive-alias
relation, graph closure, selected capability count, type/external/origin
preservation, composition, and identity. Four semantic mutations must fail
their intended theorem; no `sorry` dependency is admitted.

The selected graph is the set of capabilities **carried across the edge**.
The extended model additionally proves that an admitted selection drops only
external capabilities, preserves the local kind/origin inventory, preserves a
strict parent rank and maintains these invariants along any finite trace of
admitted edges. Production witnesses retain the actual full input, selected
input and observed renamed result, including discarded external parameters.
The executable checker's full correspondence to this model is still outside
the kernel-checked claim; see `HIA_CAPABILITY_PROJECTION_TRACES.md`.

| Domain | Current evidence | Explicit boundary |
| --- | --- | --- |
| Every admitted Core module | Executable type, effect, CFG, ownership and borrowing verification | Whole-language progress/preservation is not established |
| Every admitted projection/renaming and finite edge trace in the resource model | Lean relational, inventory and rank proofs, independent negative mutations | Production checker refinement and arbitrary instruction transitions remain unproved |
| Every well-formed selected u32 register program | Existing generic totality/register-growth/dead-literal theorems rerun | Straight-line selected model; exporter, LLVM and native code are outside theorem |
| Actual checked byte reductions in registered profile | All-input scalar SMT transformation plus inductive guarded reduction and complete fallback | No claim about arbitrary loops or universal speed superiority |
| Native owner cancellation and continuation | Actual committed prefix, verified image switch, exact single-use suffix and balanced native ledger | No external-I/O exactly-once, process-crash or durable recovery claim |

## How to interpret results

`qualification_commands_passed` means the experiment/control commands ran
successfully on the fixed combination. It does **not** mean the performance,
NDU net-benefit, C++ generality or Agent productivity targets passed.
`reduction/RESULT.json` retains each workload/length comparison against both
strong Rust implementations. `ndu-cost/REPORT.json` retains every fixed,
exact-DP, lightweight and native-NDU result, including skip and loss cases.
The combination report separately completes the outer NDU build/run costs.

The C++ profile is an independently generated Hepta/Core/native module from
actual Clang ASTs, tested with an independent C caller and allocation-failure
oracle. Its source/API maintenance variant is deliberately authored and does
not count as an external library's real upstream release upgrade. The C++
standard-library declarations are audited dependencies, not translated code.

All receipts retain `authority: DENY_ALL` and `safety_certificate: false`.
They are scoped, reproducible engineering evidence and do not authorize a
production deployment or assert absolute safety on arbitrary hardware/FFI.

## Reproduction

Use the `hia-full-execution.yml` workflow or invoke the campaign with explicit
absolute tool paths, a clean checkout of the pinned NDU source and its normal
Cargo cache. The output directory must be new and outside the source worktree.

```sh
python -B tools/qualify_hia_composition.py \
  --output /absolute/new/evidence \
  --ndu-source /absolute/ndu-8e52-checkout --cargo-home /absolute/cargo-cache \
  --clang /absolute/clang-20 --clangxx /absolute/clang++-20 --cc /absolute/gcc \
  --rustc /absolute/rustc-1.95.0 --cargo /absolute/cargo-1.95.0 \
  --lean /absolute/lean-4.19.0/bin/lean
```

The source must remain unchanged for the entire campaign. Missing tools,
source drift, an invalid native identity, skipped required tests, or a failed
control are failures with retained evidence; they are never success-by-skip.
