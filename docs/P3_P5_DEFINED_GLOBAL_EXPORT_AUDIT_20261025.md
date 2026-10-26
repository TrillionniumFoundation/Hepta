# P3/P5 defined-global export audit — 2026-10-25

## Confirmed trust-boundary defect

The finite `inspect_object_symbols` scanner in the combined native-object branch recorded callable exports (`ELF STT_FUNC`, COFF external functions, Mach-O public `__TEXT,__text`) and undefined imports. It could **ignore an additional publicly defined data/global symbol** on ELF64 or COFF and still return the declared function inventory. The source-facing `llvm_ssa_pipeline` then compared only that returned inventory with the checked Hepta export list.

This is not an LLVM code-generation bug nor proof of arbitrary source conversion: it is a **native artifact authority flaw** for unexpected global exports in compiler-produced/forged object bytes.

## Exact implementation and bounded policy

- Original scanner Git blob: `75c27ba7b446b39633427a344bf32f66838225eb`.
- New scanner Git blob: `fff2b071ca69faf91d619c968ad587e406571216`.
- Unchanged structural validator blob: `5231ee37ef4ca65a3175a1162178ea21b9503082`.
- Reject ELF global/weak **defined non-function** symbols including STT_OBJECT/NOTYPE/TLS/IFUNC instead of excluding them from the inventory.
- Reject COFF externally defined data/absolute symbols even when the symbol type is not marked function.
- Reject unsupported Mach-O externally defined kinds (N_ABS/N_INDR and other unreviewed symbols); existing exported `__DATA` section checks remain.
- Keep source-checked function exports and the existing abort-only import allowlist intact. This is intentionally strict for Hepta's finite scalar object profile, not a generalized ELF/COFF/Mach-O linker or broad C++ ABI model.
- Add a real Clang five-target negative regression: the expected function remains present while `@hepta_unapproved_global = global i64 77, align 8` is also defined. Object files must pass structural validation and then reject symbol qualification.

## Executed direct host probe — without CI

Actual tools: Python **3.13.5**, Clang **17**, Linux **x86-64** host with cross-target Clang object emission. Both exact old and new scanner sources and the unchanged object structure source were recreated locally, and `git hash-object` matched all three Git blob SHA values.

For **five** configured targets, each produced a valid positive relocatable object and a valid structurally well-formed negative object with an extra public global data export (10 real native object compilations). The **new exact scanner accepted all five positive objects and rejected all five negatives**.

Exact original scanner comparison on the *same negative objects*:

| Target | Original scanner | Patched scanner |
| --- | --- | --- |
| Linux x86-64 ELF | **Accepted, omitted public data export** | Rejected: `E_OBJECT_SYMBOL_EXPORT_KIND` |
| Linux AArch64 ELF | **Accepted, omitted public data export** | Rejected: `E_OBJECT_SYMBOL_EXPORT_KIND` |
| Windows x86-64 COFF | **Accepted, omitted public data export** | Rejected: `E_OBJECT_SYMBOL_EXPORT_KIND` |
| macOS x86-64 Mach-O | Rejected: data outside executable text | Rejected |
| macOS arm64 Mach-O | Rejected: data outside executable text | Rejected |

The positive objects exported only `hepta_symbol_target` with no unbound imports. The regression test is committed in `tests/test_object_executable_exports.py`.

This **does not** execute the full Hepta checkout, rustc, verified SSA-to-object pipeline, Windows/macOS binaries, QEMU, GPU or actual devices. Cross-target artifact parsing is not execution or ABI qualification. The new code must receive its own complete pinned-release acceptance before mainline publication.

`whole_project_blockers_closed=false`. The general P0–P7 blockers (language soundness/refinement, owned ABI, full C++ L3, genuine Agent A/B, physical DMA/hardware and GPU/NPU) remain open.
