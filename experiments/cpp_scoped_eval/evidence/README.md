# C++ scoped ownership migration: retained native evidence

This final run passed after the compiler implementation was frozen. It translates the actual C++ lifecycle into Hepta, including nested scope construction, scope-exit destruction, moves and constructor-failure cleanup.

## Observed result

- 1,121 cases execute on each of original C++, Hepta/Rust, Hepta/C and direct LLVM: 4,484 positive native calls.
- Every route agrees with the independent integer/resource oracle: 3,180 successful allocations and frees, 398 real allocator refusals, zero live allocations after calls, and the same destruction identity/order trace.
- All 64 active declarations have an explicit admitted destination; the three source declarations are accounted for, with no unconverted declarations.
- The original C++ object is linked only into the reference executable. Translated target link inputs do not include it.
- Two deliberately broken, actually compiled C executables are detected: one leaks eight resources in the first case; the other frees all eight in the wrong destruction order.

This finite qualification does not establish arbitrary C++ migration, C++ object ABI preservation, general RAII coverage, formal source equivalence, whole-language soundness or a performance advantage.

## Retention and scope of evidence

`qualification.json` is the complete observation report. `command.json` retains the actual argv, exit code, stdout, stderr and elapsed time. `source-identity.json` pins all included implementation, driver and fixture bytes. `raw-evidence.tar.xz` contains the complete successful output tree, the earlier ENOSPC attempt, and a source snapshot. `archive-members.json` records every retained member size and SHA-256; packaging re-read and checked every archive member.

The first attempt failed during host storage exhaustion; its files are retained under `historical-enospc-attempt/`. The successful retry ran after archived temporary output was removed. It did not overlap the registered benchmark timing. These source hashes and local reports are reproducibility evidence, not authentication of arbitrary third-party receipts.

## Requalification after concurrent-verifier repair

These top-level observations were rerun after independent review reproduced a SIGSEGV when four threads used the old verifier's shared Z3 default context. The implementation now creates a separate Context for each verification call and explicitly binds its constants, symbols and Solver. The prior successful bundle is preserved unchanged under `superseded-before-z3-context-fix/`; it does not qualify the repaired implementation. The earlier ENOSPC attempt also predates this repair and is retained as historical environment evidence, not as a result for the current source snapshot.

Both final native qualifications ran after the registered performance benchmark and the NDU cost measurement had completed. The current source snapshot was hashed before and after execution, and every included source file was unchanged.
