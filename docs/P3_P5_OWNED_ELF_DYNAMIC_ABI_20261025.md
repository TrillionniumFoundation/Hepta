# P3/P5 — source-bound Owned LLVM Linux ELF dynamic ABI gate

Date: 2026-10-25. Stacked on the **exact current PR #115 base**
\`a04ae789b2348504089e2c3484178998a6f332ba\`, not mainline 0.2
or an older scalar-only fork. This is a **bounded native hardening increment**,
not general C/C++ ABI certification or a claim that P0–P7 are closed.

## Actual safety defect

The existing \`compile_owned_llvm\` regenerated LLVM from the checked AST,
canonical semantic snapshot and independent Resource IR, then required a
recognized native toolchain. For \`kind="shared"\`, native artifact acceptance
checked only the ELF64 header, ET_DYN and target machine, not the loader's
dynamic symbol table. Thus the checked export inventory was not independently
compared with what the operating-system linker/loader can actually resolve.

\`hepta.elf_shared_abi.inspect_owned_shared_elf\` is a closed,
size/depth-bounded, dependency-free Python implementation of this **Linux
x86-64 ELF64 ET_DYN** acceptance boundary. It refuses:

- Missing/truncated/oversized section and program tables, invalid ELF target
  and malformed .dynsym/.dynstr links or symbol name offsets.
- Loader PT_DYNAMIC that does not agree with SHT_DYNSYM/SHT_STRTAB:
  DT_SYMTAB, DT_STRTAB, DT_STRSZ and DT_SYMENT are pinned to actual sections.
- Unexpected DT_NEEDED dependencies; the admitted hosted profile only
  accepts the measured \`libc.so.6\` dependency at this stage.
- Public functions not in executable, file-backed code sections **and**
  executable PT_LOAD segments, zero-length/misplaced/hidden/non-function
  exports, extra/missing/duplicate symbols.
- Foreign unresolved symbols beyond the finite, reviewed hosted libc
  allocation/memory/error set and known weak GNU/Clang runtime stubs.

All ELF data and numeric table extents are bounded without external parsers,
executing the candidate shared library, or trusting a source-supplied receipt.

## Integration

- The pre-publication \`compile_owned_llvm\` path parses **actual compiled
  shared bytes**, checks against \`ir.functions\`, then records \`dynamic_abi\`
  with \`backend_refinement_proven=false\`.
- The higher-level \`build_llvm_owned_source\` parses the same staged file
  independently and requires an exact, canonical-JSON-equal native receipt
  before no-replace publication.
- \`kind="object"\` is intentionally distinct; its \`dynamic_abi\` is null.
  Existing target-object identity checks remain the authority for that kind.
- No alternate Hepta frontend, AST/IR encoder, Rust port or native LLVM
  emitter was introduced; no prior safety requirement was downgraded.

## Executed local evidence and limits

The exact blobs:
- \`hepta/elf_shared_abi.py\`: Git blob
  \`3493cc86d9edf4a2c40092ccde4648c96ab4df30\`.
- \`tests/test_elf_shared_abi_native.py\`: Git blob
  \`9fb2f2a09db2596ffe0751bff78543bee33a47e3\`.

Both hashes matched the uploaded GitHub bytes. On local Python 3.13.5 /
Clang 17 / GCC, the **exact files** passed **9/9 unittest methods** with
no skips, including real ELF objects, malformed-table/dynamic-tag mutants,
unknown foreign imports, duplicate exports, wrong executable segment/section
and **4 positive + 4 deliberately wrong native C caller executions** across
GCC/Clang and \`-O0/-O2\`.

Run:

    python -m unittest tests.test_elf_shared_abi_native -v

The existing full-repo \`tests.test_llvm_owned_backend\` was extended to
require \`dynamic_abi\` on the source-checked Owned LLVM native receipt.
**It has not been executed on this exact GitHub branch HEAD**, because this
isolated local container lacks the pinned Rust and Clang 20 complete Hepta
native build environment. Its test additions are committed, not falsely
counted among the nine locally passed tests.

## Crucial limitations

- ELF is complex. This narrow parser checks admitted dynamic symbol/loader
  records and code extents; it does **not** validate all relocations, GNU
  hash/version machinery, ELF constructors, arbitrary loader side effects or
  machine-code semantics. Clang, linker, glibc, native runtime and the
  source-to-codegen implementation remain trusted assumptions.
- A compiled wrong implementation can carry an identical valid C ABI.
  The independent C caller **must** reject it on value checks; parsing the
  ELF alone never proves equivalence.
- No universal \`unsafe\` elimination, all-architecture C/C++ ABI, complete
  pointer provenance, whole-language ownership proof, real-model Agent A/B
  gain, physical hardware or GPU qualification is established.
- PR #115's previous source-bound **46-gate (44 pass / 2 inconclusive
  performance stability)** and **1,369-test** record cannot qualify this new
  branch HEAD. Preserve both stability failures and all production blockers.
- Do not set \`whole_project_blockers_closed=true\`. Keep this stacked change
  Draft until actual complete native source and current target workloads pass.
