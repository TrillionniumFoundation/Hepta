# HIA P0/P2/P3 source, LLVM, ABI and migration host matrix

Research-only follow-up to the exact green P0/P1/P5 integrated candidate
`d6247cb5e4787ed86d52787858c38029afcddf61` (PR #464). This change does not alter Core, the native Rust
NDU owner, C/C++ translators or production runtime logic. All results must
be reported against this new candidate's exact HEAD, not inherited from #464.

## Additional strict suites

- **Legacy:** explicit incompatible HSIR v0 envelope audit, versioned scalar
  SSA bridge, CFG/SSA verifier, v8/safe legacy routes and checked Agent assembly.
  Unknown source wire identities must reject instead of guessing a schema.
- **LLVM:** actual direct native LLVM-20 compilation on x86-64 host, C ABI,
  first-trap behavior, live owner cleanup, AArch64 object emission, independent
  VM/native differential comparison; native LLVM does not inherit Rust proof.
- **C/C++ migration:** real GSL branching-callback profiles, captured C
  project source and SQLite fixed slices, independent control and evidence
  rejection. No general C++ ABI or fully automated migration claim.
- **Actual host matrices:** enable *existing unchanged* host jobs on the
  candidate branch by adding just its push branch name to:
  `.github/workflows/hepta-native-hosts.yml` and
  `.github/workflows/hepta-cpp-upstream-hosts.yml`. Those actual jobs cover
  x86-64 Linux (GCC/Clang), AArch64 Linux (GCC/Clang), Windows x86-64
  (MSVC/Clang) and macOS ARM64 (Clang). Individual job failures and all
  machine-specific limitations must be retained, not masked by rerun.
  The source branch addition does not change their original implementations.

The scoped qualifier remains `DENY_ALL` and refuses missing tests, any skips,
errors, expected wrong output or changes to tracked source. LLVM20 is installed
only through the existing pinned apt.llvm.org signing-key fingerprint. Rust
1.95.0 is explicitly pinned for native-source comparisons.

## No claims and remaining gates

This is a finite qualification of supported profiles only, not arbitrary
full-program compiler refinement, universal memory safety, unrestricted C ABI,
arbitrary C++ translation, full hardware devices, or global optimality.

P0 still needs one semantic authority and exact-source whole-backend
refinement; P1 lifetime/provenance and exceptional cleanup remain incomplete.
P2 true Windows-native HIA LLVM backend and device-level AArch64 execution are
separate from ABI probes. P3 needs a real complete third-party project
maintenance/upgrade cycle with measured human effort.
P4/NDU (P5) have not demonstrated independent full lifecycle net advantage,
P6 Agent productivity not established, and P7 final-use/ledger/rollback/
power-loss production qualification remains OPEN.

The original PR #464 same-SHA green 105 Core + 13 ELF/replay + 13 Rust tests
cannot be relabelled as this branch's pass.
