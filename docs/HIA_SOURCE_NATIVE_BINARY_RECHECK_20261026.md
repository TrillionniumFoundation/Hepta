# P2/P3: source-facing native ELF/object byte inventory recheck

**Scope:** reviewable independent source-side structural ABI gate; not source→native semantic refinement, release qualification or generalized safety.

## Observed existing boundary

In the checked-source HIA path, `build_checked_hepta_hia_native` obtains a
native receipt and already checks its Core/LLVM digests and that the staged
file bytes hash to the receipt. However, those values may be mutually
consistent with a different native object. The native backend itself checks
`inspect_owned_shared_elf` or `inspect_object_symbols`, but the
source-facing final publication gate did not repeat that check against the
actual, currently staged bytes and current Core ABI inventory.

## Implemented single-authority reinspection

`hepta.hia_source_bridge._reinspect_source_native_bytes` is required before
the source-facing `publish_verified` call. It does **not** introduce a new
ELF parser, code generator, ownership checker or C++ translator.

- Bind the receipt to exact current verified Core/LLVM/implementation/profile,
  target, output stage pathname and artifact SHA-256/size, with an exact
  closed set of native receipt fields and **identity-typed** Boolean proof
  claims (in Python, `False == 0` cannot justify `0`).
- Require precisely the C ABI exports in the current independently verified
  HIA `ir.exports`, not a caller-supplied export inventory.
- For Linux x86-64 ET_DYN, reparse the actual byte buffer using existing
  `inspect_owned_shared_elf(payload, ir.exports)`. The parser also checks
  the reviewed dynamic imports and loader metadata.
- For Linux x86-64 or AArch64 ELF64 relocatable objects, reparse the actual
  byte buffer with existing `inspect_object_symbols` using machine 62 or
  183, then match all exports and allowlisted unresolved imports.
- Compare the actual parsed inventory with the backend's complete inventory
  using type-sensitive canonical JSON. An independently resealed forged
  receipt does not make the binary eligible for publication.
- Preserve the existing final no-replace verified hard-link publisher and
  exact source/compiler replay. Source reports record
  `source_native_binary_abi_rechecked=true` only after all checks pass and
  retain the complete reinspection inventory.

This is deliberately a source-stage *structural* binary guard. It does not
assert that a binary implements the correct arithmetic/ownership semantics
merely because its symbols are correct; that requires the separate source
replay/LLVM-origin, native differential and future formal refinement gates.

## Regression inputs

`tests/test_hia_native_source_reinspect.py` builds **actual Clang** shared
ELF files and x86-64/AArch64 relocatable objects and checks the existing
shared/object scanners through this new source-facing gate. Positive controls
are valid C artifacts exporting the expected function. Negative controls
include a forged Core export list, profile/path/digest/proof scope, unknown
receipt fields, Boolean-vs-integer proof claims, extra function exports,
unapproved foreign imports, extra public data and object machine mismatch.

Those C compilation controls test the scanner and source-facing receipt
binding. They are *not* Hepta→HIA→LLVM compiler products. On a complete exact
checkout, execute these plus existing source/LLVM/native suites:

```bash
python -m unittest tests.test_hia_native_source_reinspect \
  tests.test_hia_source_bridge tests.test_hia_program_llvm \
  tests.test_hia_native_differential -v
python tools/release_check.py
```

No CI result is required to **continue development**, but passing CI or
targeted native tests on other commit SHAs must not qualify this commit.

## Remaining independent production blockers

General Owner/Loan/provenance SSA, source/Core/LLVM semantic refinement
and formally justified optimizations; arbitrary C/C++ L2/L3 migration,
MSVC and broader live target ABI; real-model Agent A/B and economics;
physical MMIO/IRQ/DMA/GPU/NPU and sustained p99 resource metrics remain open.
No arbitrary hostile-code sandbox or generic linker trust proof follows.

`whole_project_blockers_closed=false`
