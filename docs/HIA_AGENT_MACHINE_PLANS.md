# Explicit HIA machine plans

The Agent selects a plan. The direct backend validates and realizes it without
running a profitability search. Core remains the immutable semantic anchor;
an accepted plan cannot change ownership, ordered effects, traps or the public
call ABI. The original `hepta.hia.agent.block-layout.v1` remains supported.

Before reading plan fields, the backend captures a detached snapshot using the
existing bounded plain-JSON admission path: exact built-in data types, at most
8 MiB of canonical JSON, 262,144 nodes and depth 64. Object hooks, subclasses
and cycles are rejected. Semantic checks and emission use that same snapshot;
later changes to the caller's containers cannot change the accepted plan.

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
changes, instructions outside the reviewed forms and automatic search remain rejected. Choice validity
does not establish a performance advantage.

## Reviewed v3 scalar register assignments and select forms

`hepta.hia.agent.machine-plan.v3` retains every explicit v2 field and adds
`value_registers`, a map from function name to SSA value-to-register assignments,
plus the required `instruction_selection.scalar_select` choice. The new plan is
discovered through the same artifact-based tool family. V1 and v2 keep their
existing byte realizations; an empty v3 value map with the branch selection and
canonical choices emits the same object as canonical lowering.

```json
{
  "schema": "hepta.hia.agent.machine-plan.v3",
  "core_sha256": "<canonical Core SHA-256>",
  "block_order": {},
  "function_order": ["plus7"],
  "scratch_registers": {"r10": "r10", "r11": "r11"},
  "instruction_selection": {
    "move_immediate": "mov32_if_exact",
    "alu_immediate": "imm8_if_exact",
    "scalar_select": "cmov_scalar"
  },
  "function_alignment": 16,
  "value_registers": {
    "plus7": {"x": "r12", "seven": "r13", "answer": "r14"}
  }
}
```

The referenced `plus7` Core in the qualification fixture has parameter `x`,
constant `seven` and output `answer`; arbitrary names are not accepted merely
because they appear in a plan.

| Choice | Independent admission and preservation rule |
| --- | --- |
| Scalar locations | Assign existing integer or boolean SSA definitions to `rbx`, `r12`, `r13`, `r14` or `r15`. Resource pairs, owners, loans, `unit`, unknown values and other registers are rejected. Unassigned values use the canonical stack locations. |
| Register reuse | Recompute closed-block live intervals from the verified Core. Definitions occupy their own point even when dead; inputs and outputs at the same instruction interfere. Two overlapping intervals cannot share a register. Different blocks can reuse registers because all incoming values are explicit parameters. |
| Edges and loops | Stage every source argument before assigning any target parameter. This preserves parallel copies, register permutations and self-loops. Target parameters cannot share a register even when a parameter is unused. |
| Calls and returns | Save each used callee-saved register before assigning parameters; restore it after writing all results on every ordinary return. This applies to internal calls, multiple results, recursion and external libc calls. Traps retain abort semantics. |
| Scalar selection | Explicit `branch` retains the old lowering. `cmov_scalar` uses `TEST`, flag-preserving scalar MOV loads, and register-only 64-bit CMOV. Core has already evaluated the scalar operands; no speculative pointer load or new side effect is introduced. |

These are real value-location choices: selected scalar loads and stores become
register moves. The initial implementation reserves the old scalar stack slots
and uses additional disjoint slots for callee saves, so it does not claim frame
compaction. Saving registers can increase both frame size and executable bytes.
The backend validates the Agent's assignment; it does not pick registers, insert
unrequested spill decisions or run an allocation/profitability search. General
caller-saved allocation, vectors, rematerialization and whole-backend formal
refinement remain outside this profile.

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
and function-layout checks. V3 additionally retains a per-function, per-block
register-lifetime witness and a separate scalar-select check. `same_slots` is
false when any scalar is placed in a register, even if rounded frame sizes happen
to match; both actual frame maps and `same_frame_sizes` are recorded. Each check
is a finite preservation check relative to the
canonical lowering and encoder. The receipt explicitly keeps universal
Core-to-machine refinement unproved.

`tools/qualify_hia_machine_choices.py --out /absolute/new-directory` emits five
arms: canonical, scratch registers, instruction selection, function layout and
their combination. Each arm retains complete objects/images, exact build
receipts, all correctness cases, emission/rederivation/link/publication costs,
and interleaved native timing batches. Shared setup is identified separately.
Python/ctypes dispatch is included in those timings.

For the v3 surface, run:

```sh
python -m unittest tests.test_hia_machine_registers tests.test_hia_machine_plan \
  tests.test_hia_machine_x64 tests.test_hia_agent_native_machine_choices -v
python tools/qualify_hia_machine_registers.py --out /absolute/new-directory
```

The v3 campaign freezes one nine-function fixture with loops, parallel copies,
register reuse, nested calls, multiple results, recursion and libc memory calls.
It compares canonical, scalar registers, scalar CMOV, layout and combined arms
against the existing independently implemented Core interpreter. It also runs
three expected rejections for overlapping lifetimes, a resource assignment and
an ABI-register assignment. Every attempt is checkpointed before execution and
retains success/failure status, diagnostics, commands and phase wall/CPU costs.
A failed arm leaves a failed complete report instead of disappearing from the
denominator. The native observation runs in a bounded disposable child; exit,
timeout and captured output remain visible. All five native timing arms run in
interleaved order inside that child.

Complete `.o` and `.so` files, Core, plans, per-case outputs, exact source hashes,
frame maps and full-image/text/object byte counts remain in the output directory.
Separate tests use an independent ABI caller to check callee-saved registers,
dirty upper argument bits and stack arguments, and a C memory observer to check
that invalid indices trap before a partial write. The encoder tests exercise
register-only CMOV over every admitted general-register pair and both true and
false signed/unsigned/equality conditions.

This fixture is synthetic. Model, discovery and failed Agent-search costs are
unknown, so full-search economics and real-task strategy benefit stay open even
when a planned image is smaller. The NDU macro-controller uses a separate
same-Agent, same-budget real-task gate; this experiment cannot close it.
