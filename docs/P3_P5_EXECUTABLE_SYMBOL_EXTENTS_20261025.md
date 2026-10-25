# P3/P5 native code-section export identity hardening — 2026-10-25

This is a **bounded structural security increment**, not a declaration of
C/C++ ABI compatibility, native execution, Hepta memory safety, or whole
P0–P7 blocker closure.

## Exact integration base

- Parent: PR #111 exact head `d41bf638faf4dc6f7ce7fcf903710ba642ee6427`.
- Isolated source branch: `agent/hepta-p3-abi-capture-closure-20261025`.
- Keep PR #111's canonical HSIR, strict SSA/CFG origin and native LLVM
  whitelist unchanged. Reuse and harden the *existing* object-symbol
  authority in `hepta/object_symbols.py`; do not invent a second parser.

## Implemented finite acceptance rule

All targets first pass existing `hepta.object_structure.qualified_object`.
An exported function name by itself is **not** sufficient.

| Object format | New structure restriction |
| --- | --- |
| ELF64 | STT_FUNC's section index must exist, designate executable SHT_PROGBITS, and the positive `st_size` must lie completely within that code section after `st_value`. |
| COFF | Each externally defined function must start within the raw code section whose flags include IMAGE_SCN_CNT_CODE and IMAGE_SCN_MEM_EXECUTE. |
| Mach-O64 | Each externally defined N_SECT function must start within the section length for `__TEXT,__text` carrying instruction attributes; n_sect must resolve to the actual section inventory. |

The verifier also rejects repeated defined function names or an
export/import identity collision, instead of hiding duplicate entries in
a Python set. Name inventories continue to reject unexpected foreign imports
and extra exports in the native compilation path.

**Limitation:** COFF and Mach-O entries lack an independently verified full
function byte extent; only the entry position and declared executable
section facts are checked. Object headers and flags are self-declared and
do not prove machine code behavior. This is a defense-in-depth structure
gate in addition to the exact source→SSA→LLVM origin and compiler
assumptions, not a semantics proof.

## Negative tests

`tests/test_object_executable_exports.py` compiles one function to the
five target objects using actual Clang (ELF x86_64/AArch64, COFF x86_64,
Mach-O x86_64/AArch64). It first checks each authentic object and then
modifies the symbol value or code-section flags/name **without damaging**
the previously accepted object structure. Those modified objects must
fail with `E_OBJECT_SYMBOL_LOCATION`.

An isolated local Clang 17 structural *algorithm mirror* executed on the
same five actual compiler objects: **5/5 authentic object locations accepted,
5/5 tampered locations rejected**. This is not the full repository test.
The new integration test files and hardening code are committed, but
full exact-HEAD GitHub actions have not been confirmed complete.

Run the exact branch with:

    python -m unittest tests.test_object_executable_exports tests.test_llvm_ssa_target tests.test_llvm_ssa_host_c_abi -v
    python -m unittest tests.test_llvm_ir_profile_contract tests.test_llvm_ssa_origin_gate -v
    python -m unittest discover -s tests -v

The dedicated `hepta-p3-p5-executable-exports.yml` workflow requires
`git rev-parse HEAD` to equal the workflow's trigger SHA before running.

## Linux host C ABI: actual native caller control

This increment also **reuses** the original
`tests/test_llvm_ssa_host_c_abi.py` from PR #108 with the strict
`ssa=ssa, cfg=cfg` source-origin check added. It builds a native LLVM
library and links actual C11 callers from **GCC and Clang**, each at
-O0 and -O2. The expected result is compared with the original scalar CFG
interpreter; an independently compiled intentionally-wrong C implementation
must fail each caller. This qualifies a *specific Linux native C ABI subset*,
not general GCC/Clang/MSVC parity or C++ ABI.

An isolated local C-ABI experiment (Clang 17 LLVM library, GCC 14 and
Clang 17 C consumers, one scalar exported function) executed **4 positive
link-and-run combinations** and **4 deliberately wrong compiled library
rejections**. The full Hepta test fixture and the new strict SSA-origin
integration were committed but **not yet fully executed on this final SHA**.

## Qualification truth table

- **Increment implemented:** P3/P5 export placement checked for five
  bounded file formats; explicit tests and workflow checked in.
- **Not yet closed:** P0/P1 full semantic refinement and Borrow/Drop/Provenance;
  P2 full Rust compiler port; P3 complete C migration with pointers;
  P4 real bidirectional C++ ABI, RAII/STL/templates/MSVC;
  P5 source→LLVM semantic equivalence, full representative benchmark gates;
  P6 real Agent/model and crash-safe workspace evidence;
  P7 physical-board MMIO/DMA/IRQ/GPU, sustained tests.
- Keep `whole_project_blockers_closed=false`. A validator test or Git commit
  does not justify changing production release qualifications.
