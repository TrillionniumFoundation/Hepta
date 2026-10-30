# HIA Core convergence and eight delivery tracks

This work integrates PR #399 at `e0ab595468d67bcf95485eacd22cea8ff332520c`
and PR #400 at `1bdb305fc5c6706c0e41ed66a4d43772c297d00e`, using their
actual common ancestor `0e1f5dd9bf0f54c492d96bd5dd1ae52e8c804997`.
Both parents and their historical evidence are retained. A historical passing
report is not an integrated-source qualification.

## One instruction contract

`hepta/hia_opcodes.py` defines all 50 primitive instructions, their exact
attributes, operand/result signatures, introduction versions, effects,
conditional effects, trap descriptions, resource guards and transitions.
The production Core verifier consumes these contracts. Terminator field
validation uses the same catalog. The public interface is:

```sh
python -m hepta hia catalog --schema hepta.hia.program.v8
python tools/generate_hia_catalog.py --check
```

The same source generates [the instruction reference](HIA_OPCODE_REFERENCE.md)
and [the JSON catalog](hia-opcode-catalog.v8.json), and is included by the
schema/route inventories. The textual assembly parser delegates instruction
admission to that verifier; it does not maintain another instruction whitelist.
It now accepts explicit primitive v6/v7/v8 and preserves v8 declarations such as
`return_loans(["input",null])`. Missing versus explicit nullable contracts remain
distinct canonical bytes. Older primitive and nominal spellings keep their
existing explicit adapters; no namespace is guessed or automatically upgraded.

The generated portion is local checking and named resource-guard dispatch.
The complete CFG/ownership algorithm, interpreter, LLVM lowering and machine
code remain separate implementations. They are not made proved by generating
a catalog. The production authority remains the full Python Core checker; the
Rust shadow is still a comparison implementation.

Every affected native/checker identity includes the new actual dependency.
Incremental admission now binds imported checker functions and the constants
read by both the Core module and the opcode module. Independent review found
that rebinding the latter's integer widths could otherwise leave a cached
literal admitted after fresh checking rejected it; a regression retains that
counterexample and requires rejection in both paths.

## Explicit resource and proof contracts

The [optimization resource contract](HIA_OPTIMIZATION_RESOURCE_CONTRACT.md)
rechecks actual leaf-call expansion and recomputes ticks, frames, allocator
interactions and live payload. `candidate_requalified` and
`both_fit_same_quotas` are distinct policies. Removing calls can change a VM
quota failure even when results and ordered resource actions agree; neither
policy promises an unchanged stop location, native RSS or asynchronous cleanup.

The [selected register proof](HIA_REGISTER_SAFETY.md) adds generic totality,
defined-register-read, exact register-growth and dead-literal transformation
theorems. The selected straight-line u32 machine is deliberately small.
Exporter correctness, source-to-Core correspondence, ownership, LLVM and
machine-code refinement remain outside these theorems. Native differential
execution and source hashes are separate evidence, not formal proofs.

## Prospective evidence

New Agent tasks and NDU workload protocols live under
`benchmarks/hia_agent_public_tools/` and
`benchmarks/hia_ndu_converged_holdout/`. Implementations and no-generation
controls are committed before registration; registrations are committed before
actual model generation or future-workload measurement. Hidden results never
enter model feedback. Positive reference controls are not model successes.

The NDU comparison retains exact finite/stream source and Rust pins, sealed
image custody, independent sessions and equal zero result-cache capacity.
Exact Q32 DP and lightweight controls receive the same finite candidate bank.
Historical native build costs, new setup and two-episode amortization are
reported separately. The fixed-plan comparator is strong within that candidate
set; it is not a claim about all C/C++/Rust compilers or universal optimality.

The real Ring-Buffer maintenance cycle reconstructs both complete upstream Git
trees, preserves the original Makefile and interfaces, and replaces the nine
implementation bodies through the checked Hepta-to-Rust path. It retains the
old `0xff`/EOF failure and observes the upstream correction after upgrade.
This route is not relabeled as standalone HIA-to-LLVM refinement. Independent
byte oracles, allocation failures, process recovery and pthread profiles are
required, with source identities before and after execution.

## Acceptance discipline

Each final result must identify the exact source and selected host/toolchain.
Correctness, measured performance, NDU contribution and Agent productivity are
separate gates. No failed performance comparison is removed by averaging it
with another profile. Unknown dependency acquisition or human review costs
remain unknown, not zero. x86-64 host processes and pthreads do not qualify
physical AArch64/RISC-V devices, GPU, DMA, shared mutable heaps or general async
cancellation. Those profiles remain open until their own evidence exists.

The final integrated readout and exact registrations/evidence links will be
recorded here after the frozen runs complete.
