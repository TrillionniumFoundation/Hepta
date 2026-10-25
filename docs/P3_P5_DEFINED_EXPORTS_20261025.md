# P3/P5: verify defined exported functions in five target objects

Stacked on PR #77 exact commit `065495c4ec6a5b9c150b87cba552e8e15d531a0e`.

## Issue

Target format, machine type and bounded sections can all be correct while
the object does **not define** the function names promised by SSA LLVM IR.
Five real Clang objects were relabeled in-place, retaining their exact byte
length, object format and section offsets. The previous structural gate
accepted each as an object artifact, even though its expected external
symbol was absent.

## Qualification upgrade

`_defined_exports` extracts only defined, externally visible function names
from ELF64 SHT_SYMTAB, COFF external function entries and Mach-O N_SECT|N_EXT.
Cross-object codegen requires **every** `SSA_LLVM_IR.functions` name to appear
before atomic publication; absent symbols reject `E_LLVM_SSA_SYMBOLS`.
Receipt includes `verified_defined_exports`. This gate reuses the already
strict object extent checks and is not a standalone ABI or semantic proof.

## Real local control and tests

Locally decoded all five real Clang 17 object files, accepting five external
function symbols, and rejected five same-length mutations that removed the
expected external symbol without changing any object header.
Independent Python tests: 3/3 PASS on the local proof prototype.
New repository regression suite: `tests/test_llvm_ssa_symbols.py` also
tests native no-publication when a required export is missing.

General Rust-level compiler correctness, source-to-native refinement,
bidirectional foreign ABI, physical devices and full P0–P7 blockers remain
OPEN. This is a strict object-only symbol inventory, not a proof of behavior.
