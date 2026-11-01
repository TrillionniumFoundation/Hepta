# Fixed-source execution campaign

This campaign uses one clean Hepta commit/tree, the native NDU stream source
`c4a1bbed3a39beba43a6abf1a18b6f75c5725c21`, and an explicitly new tool profile:
Linux x86_64, Clang 20, Rust 1.95.0, Z3 4.15.4, and the existing SHA-256-pinned
Lean 4.19.0 kernel. It does not relabel results as the earlier Rust 1.90 profile.

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

The campaign performs actual Core rejection tests, four Lean qualifications,
native cancellation/verified-switch/single-use suffix recovery, the reduction
holdout, native full-cost NDU controls, and C++ reset/release migration with
fresh-Clang negative sources. Every child command has raw stdout/stderr and
an outer wall-time record, so Python startup and final report writing are not
silently excluded from the NDU build/experiment envelope. Nested costs must
not be added twice. Cargo dependency cache warmth is declared; an empty target
directory is not a claim of an entirely cold machine.

The same campaign also runs the new host-region qualification and the Agent
tool controls. The former exercises actual Linux page protections, concurrent
readers, exclusive writers, timeout quarantine and joined-worker recovery.
It relies on the explicit trusted synchronous no-escape C contract described
in `HIA_HOST_REGION_PROFILE.md`; it grants no device/MMIO/DMA authority. Agent
model inference is a separately registered, commit-matched run after native
timing, so the model workload cannot interfere with the timing campaign.

## What the Core proof now covers

The production CFG verifier calls the extracted `rename_capabilities` helper.
`formal/HiaCapabilityRenaming.lean` proves 14 theorems for every finite selected
capability graph and every injective renaming, without a loop-unroll bound:
root equality, parent/child relations, parent suspension, the exclusive-alias
relation, graph closure, selected capability count, type/external/origin
preservation, composition, and identity. Four semantic mutations must fail
their intended theorem; no `sorry` dependency is admitted.

The selected graph is the set of capabilities **carried across the edge**.
The executable checker separately rejects duplicate target names, unknown
capabilities, lost local owners/loans, and missing roots/parents. It can forget
unused external parameters before renaming. That projection is not proved by
the selected-list length theorem. The Python helper's implementation
correspondence is exercised by production CFG, graph-renaming and refusal
controls; it is not a kernel-checked refinement theorem.

| Domain | Current evidence | Explicit boundary |
| --- | --- | --- |
| Every admitted Core module | Executable type, effect, CFG, ownership and borrowing verification | Whole-language progress/preservation is not established |
| Every finite selected resource graph under injective renaming | Lean relational proofs, independent negative mutations | Does not cover every instruction transition or external forgetting |
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
  --ndu-source /absolute/ndu-c4a-checkout --cargo-home /absolute/cargo-cache \
  --clang /absolute/clang-20 --clangxx /absolute/clang++-20 --cc /absolute/gcc \
  --rustc /absolute/rustc-1.95.0 --cargo /absolute/cargo-1.95.0 \
  --lean /absolute/lean-4.19.0/bin/lean
```

The source must remain unchanged for the entire campaign. Missing tools,
source drift, an invalid native identity, skipped required tests, or a failed
control are failures with retained evidence; they are never success-by-skip.
