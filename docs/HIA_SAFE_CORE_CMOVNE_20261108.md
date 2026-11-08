# Safe Core CMOVNE leaf qualification

## Result and scope

The independent Safe Core x86 model now recognizes the 64-bit register-to-register
`CMOVNE` form used by the existing `cmov_scalar` producer plan. This is a leaf
instruction extension to the existing supplied-artifact validation profile:

`hia.safe-core.unsigned-acyclic-single-borrow.supplied-elf.x86_64.v1`

The Core profile, caller assumptions, five proof obligations, model limits,
checker source identity mechanism, and execution/adoption gates are unchanged.
The qualifier does not prove either the self-hosted compiler or the original
fresh-Agent `select` extension. That original task's strict four-claim gate
remains **HOLD**. Its old supported domain, newly supported domain, compiler
algorithm and emitted programs still need their separate proof obligations.

The implementation starts from exact repository commit
`e05dbfffcfc1ccc0bb380e4b0d97ec43f251e03e`. All 212 copied `hepta/*.py` files were
individually checked against that commit's Git blobs before editing. Only
`hepta/hia_safe_core_x64.py` changes in the production checker. The old file's
Git blob is `7f23d5fbd91775b11bd6aca6df1adbb565616b40`; the new file's SHA-256 is
`94560da1baf4526d93d5c7449f74afc2db6967ea70b42e962af33fbca3dcd092`.

## Instruction semantics

Admission requires a single REX prefix with W set, opcode bytes `0F 45`, and
ModR/M mode 3. REX.R extends the destination field and REX.B the source field.
The existing exclusion of REX.X remains. Both input values and ZF are read from
the pre-instruction state. The destination becomes the source when ZF is false
and otherwise retains its old 64-bit value. The operation leaves flags unchanged;
in particular the model's ZF and CF remain available to following instructions.
Source/destination aliases therefore preserve their value in both conditions.

This follows the CMOVcc encoding and operation in the Intel instruction reference,
Volume 2A, pages 3-176 through 3-178, and its REX fields in section 2.2.1. The
primary reference consulted is [Intel SDM, order 325383-085US, October 2024](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf).
The implementation remains a trusted Python ISA model; this manual cross-check
and the finite hardware witnesses are not a kernel proof of that model.

The decoder continues to reject 16/32-bit forms, memory operands, other CMOV
conditions, unsupported prefixes and truncated encodings. It decodes unreachable
bytes too. Recognition of an instruction does not authorize arbitrary use of a
stack or saved register: existing symbolic memory, stack and SysV obligations
still decide whether an entire supplied artifact is valid.

## Retained qualification

The explicit corpus contains:

| Group | Count | Expected result |
| --- | ---: | --- |
| Existing producer `cmov_scalar` plan, dynamic `u8/u32/u64/usize/bool` selects | 5 | `smt_validated` |
| Ordinary scalar leaves for REX.B, REX.R, both, low/high aliases, saved r12, ZF and CF preservation | 8 | `smt_validated` |
| Wrong operands, missing bool normalization, clobbered ZF, truncated true value, wrong REX destination, clobbered r12 | 6 | `refuted` with a SAT counterexample |
| Actual leaf artifacts using CMOVE, 32-bit CMOVNE or a CMOVNE memory operand | 3 | `unsupported`, no proof and no execution |
| Register destination/source encoding combinations | 256 | Exact decoding, no native execution implied |
| Unsupported raw instruction forms | 17 | Decoder rejection |
| Native calls on the 13 proof-qualified positive artifacts | 492 | Match independent integer selection/wrap mathematics |

Each positive proof records the exact Core, object and final image hashes,
`subject`, `property`, `profile`, `assumptions`, `checker`, and
`unproved_obligations`. Its obligations are, in order: caller contract SAT;
memory-bound violation UNSAT; SysV violation UNSAT; missing terminal outcome
UNSAT; Core-to-final-image return/abort/caller-byte mismatch UNSAT. Every SMT
query and result is retained. The six negative proofs preserve their partial
report and real counterexample; their expected rejection is not a positive
correctness claim for those artifacts.

The native child receives exact image SHA-256, scalar ABI words and no producer
receipt as authority. Only the positive artifacts are executed, in disposable
processes. These 492 calls are finite corroboration of the model, not universal
hardware correctness or general caller safety.

All objects are ordinary locally emitted two-function Safe Core objects. The
custom leaves use that established shape with a conventional SysV wrapper and
an unreachable `abort` import site.
No ELF metadata is mutated and the ELF binder is unchanged. The first development
attempt used the local default linker, which omitted `.hash`; the existing binder
correctly refused it before a proof. The reproducible qualifier explicitly uses
`--hash-style=both`, together with the existing immediate binding, RELRO and
non-executable stack link options. This is a normal supported link configuration,
not a waiver of the binder's input contract. That setup refusal and subsequent
development artifacts are retained separately from the final frozen-source run.

## Reproduction and source identity

The host must supply Linux x86-64, GNU `ld`, libc and exactly `z3-solver==4.15.4`.
From a source checkout, run:

```sh
python -B -m unittest tests.test_hia_safe_core_cmovne -v
python -B tools/qualify_hia_safe_core_cmovne.py --output NEW_EVIDENCE_DIRECTORY
```

The second command refuses to reuse an existing output directory. It launches a
new worker with `-B`, `PYTHONDONTWRITEBYTECODE=1`, and a newly created empty
`PYTHONPYCACHEPREFIX`. It verifies that cache stays empty, inventories source
bytes before and after qualification, and records `SourceFileLoader` origins
and SHA-256 for every loaded project and Z3 Python module. This prevents an old
adjacent bytecode cache from substituting for the identified source. The proof
itself separately pins the Z3 bindings and loaded native solver library.

`qualification.json`, per-subject `validation.json`, object/final images,
SMT queries, raw native process output and exact source snapshots form the
review evidence. The independent source tree's run does not automatically
qualify a later integrated repository commit. The integrated source CI must
rerun the same strict qualifier and bind that run's actual checker sources.

## Remaining proof boundary

The existing profile still admits one bounded, acyclic primitive Core function,
one scalar return, at most one borrowed range, and its declared operation/ABI
limits. It excludes the loops, recursion, multiple buffers, allocation and
language-extension relation required by the original compiler task. This leaf
change does not establish whole-language safety, a complete x86 refinement,
loader behavior beyond the existing assumptions, provider-history costs,
economic benefit, or adoption of the original Agent patch.
