# c2hia / cpp2hia stricter native receipt identity gate — 2026-10-26

The L1 migration wrapper must refuse to publish a native artifact unless
the **actual checked generated Hepta source** and the current native HIA build
are identified as the same bytes.

New strict acceptance fields in the pre-existing HIA-SSA → LLVM receipt:
- native build output path must match the requested staging path;
- real Rust-reference check must report `ok=true` and `rustc_checked`;
- resource CFG, SSA/CFG native origin, HIA source replay and host ELF symbol
  checks must truthfully match the current target profile;
- target execution and foreign C ABI proof remain explicitly false;
- source SHA-256 must match the *generated candidate.hepta* bytes;
- LLVM IR SHA must be a proper digest identical in top-level identities and
  the native backend receipt; final staged native bytes must match the native
  artifact digest and byte count;
- all these checks happen before the manifest-last directory publication.

No alternate compiler, verifier or source translator is added.

11 isolated protocol tests passed locally against the exact implementation
and test blobs, using mocks of the existing migrators/native builder. This
does not establish a full source-to-LLVM run. P3/P4 project-scale C/C++
translation, ABI, RAII and behavioral equivalence remain OPEN.
`whole_project_blockers_closed=false`.
