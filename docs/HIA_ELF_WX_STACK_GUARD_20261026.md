# P2/P3: fail closed on unsafe x86-64 shared ELF segment permissions

**Exact code parent:** PR #236 initial integration commit
`438bb9b7ff2abc16416fe115c08940e2076d906c`, containing
PR #234 startup isolation and PR #233 source-publication ABI reinspection.

## Concrete gap

The single shared-ELF scanner (`hepta.elf_shared_abi.inspect_owned_shared_elf`)
validated ET_DYN, dynamic symbols, loader-linked import inventory and an
executable PT_LOAD. But it **accepted a PT_LOAD with PF_W|PF_X and ignored
PT_GNU_STACK permissions**. The same correct exported C functions can occupy
unsafe writable+executable loader mappings, or the file can request an
executable process stack. A correct symbol inventory is not a segment policy.

This code path is reused by existing Owned LLVM, scalar-host-LLVM and the
HIA Core source-facing dynamic ELF reinspection. No new ABI parser, linker,
lowerer, or proof language is introduced.

## Exact finite policy

- PT_LOAD must have precisely `PF_R`, `PF_R|PF_X`, or `PF_R|PF_W`
  (4, 5 or 6). RWX, W-only, X-only and unknown/OS-defined extra flag
  bits are unsupported in this reviewed native profile.
- An explicit **single** PT_GNU_STACK is mandatory and must carry precisely
  PF_R|PF_W (6); executable, missing or duplicate stack descriptors reject.
- Retain the existing required executable-load, PT_DYNAMIC,
  section/symbol/DT_NEEDED and source-export checks. The receipt's schema
  and existing false proof flags remain unchanged.

The checked native toolchain is required to emit an ELF with a non-executable
GNU stack. This deliberate fail-closed policy may refuse other valid ELF
binaries outside the reviewed host profile. It is not a whole loader
verification, W^X runtime enforcement, or immunity to dynamic dependencies.

## Actually executed local native transport controls

Using installed Clang and GCC on Linux x86-64, compiled four genuine ELF64
shared libraries (each -O0 and -O2). Each has RX and RW PT_LOAD plus a
single RW PT_GNU_STACK. Independently examined raw program headers; **four
valid originals passed** the same finite permission predicate. For each
real binary, independently modified RX→RWX, RW→RWX,
GNU_STACK RW→RWX, deleted GNU_STACK and duplicated GNU_STACK:
**all policy mutations rejected**. This is a standalone native
program-header predicate control; it is **not** the entire new in-repository
ELF scanner, Hepta source/native execution or a formal security proof.

An actual in-repo Clang integration regression is added to
`tests/test_elf_shared_abi_native.py` and uses the real scanner with
positive and negative program-header cases. The test has been committed
but **not executed on an exact complete checkout**.

## Reproduce on the integrated commit

```bash
python -m unittest tests.test_elf_shared_abi_native tests.test_scalar_host_abi -v
python -m unittest tests.test_hia_native_source_reinspect \
    tests.test_hia_native_startup_isolation -v
```

The remaining blockers are broader source/Core/LLVM refinement, memory
provenance beyond the finite byte-owner profile, arbitrary C/C++ migration,
cross-target ABI execution, physical DMA/IRQ/GPU/NPU, live Agent A/B and
stabilized production performance. CI status is not an engineering stop.

`whole_project_blockers_closed=false`.


## Follow-up: reject unreviewed ELF dynamic-loader redirection

The earlier scanner parsed PT_DYNAMIC but used only DT_NEEDED, STRTAB,
SYMTAB, STRSZ and SYMENT, silently ignoring loader search redirection and
auditing tags. Even with an exact Hepta C-export inventory, DT_RPATH,
DT_RUNPATH, DT_AUDIT/DT_DEPAUDIT, DT_FILTER/DT_AUXILIARY, DT_CONFIG,
DT_SYMBOLIC and DT_TEXTREL could alter the ELF loader's behavior or execute
unreviewed code. The scanner now explicitly refuses these tags. DT_FLAGS
ORIGIN/SYMBOLIC/TEXTREL and DT_FLAGS_1 LOADFLTR/ORIGIN/GLOBAUDIT bits also
reject without adding a separate parser. The existing CRT DT_INIT/FINI,
init/fini arrays, GNU hash, symbol and relocation metadata remain admitted
according to the narrow existing native profile. This is not a complete
check of arbitrary ELF constructors, relocations or all loader extensions.

**Independent native controls actually executed:** Clang and GCC, -O0/-O2,
produced four genuine ELF64 ET_DYN libraries, all satisfying the finite
dynamic-tag predicate. Mutating real PT_DYNAMIC records produced 60 rejected
negative samples (nine forbidden tags and six dangerous DT_FLAGS/FLAGS_1
values per original). The dedicated in-repository Clang regression now calls
the actual scanner on equivalent modified binary data. This repository
regression remains **not run on a complete exact checkout**; the standalone
controls are not a release qualification or proof of whole-language safety.


## Host shared-object boundary: no PT_INTERP or PT_TLS

The reviewed HIA native shared-object profile is not an ET_DYN PIE
executable with its own interpreter and does not model implicit
thread-local storage initialization/teardown. PT_INTERP (3) and PT_TLS
(7) are now rejected before any source/native ELF qualification. Real
Clang and GCC -O2 host shared objects were independently compiled and
inspected: both had GNU_RELRO and **neither** PT_INTERP nor PT_TLS.
The updated repository regression mutates an existing real GNU_RELRO
program-header type into 3 or 7 and expects exact scanner refusal.
The actual full checkout scanner regression is still not run.
