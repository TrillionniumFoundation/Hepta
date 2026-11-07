# Explicit HIA machine plans

The Agent selects a plan. The direct backend validates and realizes it without
running a profitability search. Core remains the immutable semantic anchor;
an accepted plan cannot change ownership, ordered effects, traps or the public
call ABI. The original `hepta.hia.agent.block-layout.v1` remains supported.

## Reviewed v2 choices

`hepta.hia.agent.machine-plan.v2` requires every field below. Omitted choices
are not inferred. The `core_sha256` is the canonical verified Core digest.

```json
{
  "schema": "hepta.hia.agent.machine-plan.v2",
  "core_sha256": "<canonical Core SHA-256>",
  "block_order": {},
  "function_order": ["answer", "twice"],
  "scratch_registers": {"r10": "r11", "r11": "r10"},
  "instruction_selection": {
    "move_immediate": "mov32_if_exact",
    "alu_immediate": "imm8_if_exact"
  },
  "function_alignment": 64
}
```

| Choice | Independent admission and preservation rule |
| --- | --- |
| Block order | Exact permutation of all blocks in each named function. Every block retains its explicit transfer. |
| Function order | Exact permutation of all Core functions. Internal symbol identities and relocations are preserved. |
| Scratch registers | Only a bijection of `r10` and `r11`. These are explicit caller-clobbered scratch registers; implicit instruction registers, arguments, results and callee-saved registers remain fixed. This is not general SSA register allocation. |
| Immediate move | `movabs`, or explicitly selected `mov32_if_exact`: use a zero-extending 32-bit move only for values in `[0, 2^32)`. Both forms preserve flags. |
| Immediate arithmetic | `imm32`, or `imm8_if_exact`: use the sign-extended 8-bit form only for values in `[-128,127]`. The operation and flags remain the same. |
| Function alignment | `1`, `16`, `32` or `64`. Insert NOPs only between functions; declare sufficient ELF `.text` alignment so linking preserves the requested alignment. |

Raw instructions/bytes, arbitrary physical registers, unchecked value-location
changes, new instructions and automatic search remain rejected. Choice validity
does not establish a performance advantage.

## Use through the existing tool family

1. Read `hia_describe` and its `plan_schema` resource.
2. Retain the Core-bound plan with `hia_artifact`.
3. Request `hia_verify` with `subject.kind=agent_machine_plan` and the exact
   plan/profile/target references.
4. Pass that same receipt to `hia_emit` with `codegen.kind=agent_plan`.
5. Recheck actual encoding, then run the complete frozen workload through
   `hia_evaluate`. Adoption still requires the existing evidence and generation
   checks.

The eleven-tool wire catalog is unchanged: plans are referenced artifacts and
their versioned schema is discovered. Worker/backend hashes and derived profile
identities change with this implementation. Old receipts cannot authorize a new
implementation or a different plan.

## Evidence boundaries and cost observations

The receipt retains separate block-layout, scratch-register, instruction-form
and function-layout checks. Each is a finite preservation check relative to the
canonical lowering and encoder. The receipt explicitly keeps universal
Core-to-machine refinement unproved.

`tools/qualify_hia_machine_choices.py --out /absolute/new-directory` emits five
arms: canonical, scratch registers, instruction selection, function layout and
their combination. Each arm retains complete objects/images, exact build
receipts, all correctness cases, emission/rederivation/link/publication costs,
and interleaved native timing batches. Shared setup is identified separately.
Python/ctypes dispatch is included in those timings.

This fixture is synthetic. Model, discovery and failed Agent-search costs are
unknown, so full-search economics and real-task strategy benefit stay open even
when a planned image is smaller. The NDU macro-controller uses a separate
same-Agent, same-budget real-task gate; this experiment cannot close it.
