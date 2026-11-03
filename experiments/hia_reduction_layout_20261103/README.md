# Compile-only reduction layout ablation

This independent diagnostic lane asks whether LLVM shrink-wrapping changes
production reduction machine-code layout. It does not execute target code,
measure performance, compare Rust, activate an optimization, or change any
formal gate or threshold. No thin wrapper, constant-zero specialization,
manual assembly edit, or modified Core is introduced.

## Hypothesis and likely negative control

The archived production `calculate` saves callee-saved registers and evaluates
the large-length guard before returning for n=0. The previous experimental
thin wrapper already bypasses this cost; repeating it would not be new work.

LLVM 20's [shrink-wrap pass](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/llvm/lib/CodeGen/ShrinkWrap.cpp)
tries to move frame setup/teardown to safe CFG locations. The Linux x86
[target policy](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/llvm/lib/Target/X86/X86FrameLowering.cpp)
normally permits it already. Therefore explicitly enabling it may produce
exactly the same bytes. That rules out an object-level benefit from forcing
this flag on this source/compiler, not a failed experiment to hide or rerun
until faster. Equal bytes alone do not prove the pass was enabled by default:
an explicitly enabled pass can find no applicable transformation. Pass traces
and the actual compiler policy are needed to investigate that distinction.

## Fixed experiment

For each of linear and affine:

1. Reconstruct and independently verify the current production induction
   reduction pipeline, then emit one canonical LLVM input.
2. Compile that identical input using the production object flags and three
   frozen arms: default, `-mllvm -enable-shrink-wrap=false`, and
   `-mllvm -enable-shrink-wrap=true`.
3. Compile default once more with before/after shrink-wrap MIR printing. Its
   entire object must equal the uninstrumented default object byte-for-byte.
4. Preserve objects, `.text` bytes, relocation-aware disassembly, symbol sizes,
   MIR, full bounded command outputs, proposals/proofs and Core/LLVM bytes.
5. Report entire-object and `.text` identity separately. Equal `.text` alone
   does not establish identical relocation or object semantics. Neither equal
   nor different objects implies a speedup. No timed samples are collected.

Eight compiler invocations maximum; 60-second command bounds; 300-second
runner bound and 15-minute CI job bound. No adaptive arm search or reruns.
The new workflow alone selects this experiment. Existing qualification
workflows and thresholds are not edited.

## Exactness and limitations

`REGISTRATION.json` freezes the exact clean source HEAD/tree, all local Hepta
Python dependencies, runner, workflow and fixtures, tool executable hashes,
commands, arms and budgets before proof/compilation. The solver version and
identity are also retained in the verification receipts. Source/tools are
checked again at completion. Full artifact SHA-256 inventory is in RESULT.

The lane reuses the repository's signed apt LLVM-20 setup and pinned
Z3 4.15.4.0. It records the actual Clang version and executable hash rather
than pretending the rolling apt package is a historical patch-level binary.
No Rust installation is needed for this compile-only question. A subsequent
performance experiment would need the actual pinned Rust 1.95.0 profile.

Until this CI runs, local tests cover flag isolation, negative/changed-object
interpretation and real proof/LLVM generation only. They do not establish
native code equivalence. Compilation or timeout failures retain the available
logs/artifacts and are not interpreted as a completed ablation. Catastrophic
runner/host loss can still interrupt the final inventory; incomplete evidence
must not be treated as complete.

## Next decision, not automatic qualification

If default/on objects match, record that negative finding and inspect the MIR
for the early register definitions/frame requirement. If they differ, inspect
the actual empty-path prologue and all relocations first. A new code-layout
candidate requires its own prospective registration, correctness/refusal
controls, both strong Rust comparators and the complete existing v2 wall-time
protocol before any performance claim. Empty-input amplified timing would be
separate diagnostic evidence, never a replacement denominator or gate.

`authority=DENY_ALL`, `production_activation_allowed=false`,
`performance_qualified=false`, `timing_performed=false`.

## Run

With the existing qualified solver and Clang 20 available, from a clean tree:

```sh
python -B -m unittest tests.test_reduction_layout_diagnostic -v
python -B tools/diagnose_hia_reduction_layout.py --clang /usr/bin/clang-20 --output /tmp/hepta-layout-new
```

Evidence output must be outside the source checkout. The workflow uploads
successful, negative and failed observations with the exact source HEAD.

## Follow-on common-code sinking ablation (separate profile)

The actual first shrink-wrap run is preserved at
[immutable evidence commit 6c696eae](https://github.com/TrillionniumFoundation/Hepta/tree/6c696eae8c13a470a291a46750c10a573b30f5d9/experiments/hia_reduction_layout_20261103).
All default/off/on objects matched for both workloads. No timing followed.

That MIR shows the empty branch defining callee-saved r14 and joining a
`common.ret.sink` path. A separate **common-sink** profile tests one limited
hypothesis: disabling SimplifyCFG common-code sinking may change that shared
return structure and the empty-path register-save burden. This is a hypothesis,
not a claim that the block name proves its creating pass or the root cause.
LLVM20's [implementation switch](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/llvm/lib/Transforms/Utils/SimplifyCFG.cpp)
controls this transformation; the same Core and canonical LLVM remain intact.

The frozen arms are default and `-mllvm -simplifycfg-sink-common=false`.
Both receive a separate MIR-printing compilation which must exactly match
its own uninstrumented object, for eight total compilations over two workloads.
The existing shrink-wrap profile is retained, separately registered and run,
not retroactively replaced. CI uses two isolated matrix jobs, each with the
same 60-second/300-second/15-minute bounds and distinct complete artifacts.

First compare entire objects and inspect empty-path assembly/MIR. Equal bytes,
or different bytes without a reduced empty-path save/restore burden, are
negative outcomes to retain. No automated instruction-count threshold is a
new qualification gate. A different layout alone is not semantic refinement,
latency improvement, or permission to activate the optimization. Only a useful,
safe candidate would justify a separate prospective timing protocol; this
profile performs no timing even when its object differs.

```sh
python -B tools/diagnose_hia_reduction_layout.py --profile common-sink --clang /usr/bin/clang-20 --output /tmp/hepta-common-sink-new
```
