# Independent review: returned byte loans stored in local Views

## Verdict and exact scope

**PASS for this finite source-composition slice; no blocking implementation defect found in the reviewed source.** This is not closure of P0–P7, a production Rust authority switch, a whole-language soundness proof, or a backend refinement proof. The optimization policy remains `no_change`.

The independent executions used local commit `31736998decf7fe952617fd219130ee3a5048a9e`, tree `77258df1ea6e855e06d157c4d44013b638de6179`, whose parent is public `b121c9b4a57a8a58e53360d1d67387d953348f57`. The final read-only source review used its child `0d077885cc4be0b8ee96a012d7d6d2e51d1d2ace`, tree `88478a74708cf63edf7f9304c0b4ceb820b04d01`. These execution identities are kept separate. No 317 execution is relabeled as a 0d or later public execution.

The 317→0d production delta is one comment in `hepta/hia_program_source.py`; the complete parsed production AST is identical, while file bytes are different. The other two changed files correct a negative test's premise and its documentation. The final source checker, ResourceIR, primitive Core checker, Rust Machine, LLVM backend and production authority routes are not modified by this source-adapter slice.

## What was reviewed

The adapter admits explicit v8 calls returning a byte loan from exactly one same-mode borrowed formal, selected by its declared return origin. Other formals must be primitive scalar values; the origin is a direct named byte place. Stored local-view origins, nested returned argument calls, additional borrowed formals, aggregate borrowed formals and external calls remain outside this profile.

The source state retains each hidden argument parent through `borrow_parents` before pruning a CFG interface. Existing block construction renames resource aliases and their loan atoms together. Edges check the parent binding and existing alias/consumption conditions. Shared copies retain the complete child/parent obligation until the last lexical alias ends; cleanup ends the child first. An exclusive move transfers and clears the parent list, and explicit drop consumes the child and parent. Early returns do not acquire an implicit exclusive destructor.

All 340 prior safety selectors and all 36 capabilities and guarantee strings remain. Exactly nine selectors are added, making 349 unique declarations. The reviewed canonical contract identity is `7da611f24e957ab113d987bbfb1d812db3234ca1be27cc61a8e743d0c89e4f99`; the actual pretty-printed JSON file SHA256 is `40335f3f18f32e1886d8c50f9b275717de68d05f24fbbdf6f70a44c146b3379a`. This peer review does **not** establish a full 349-method execution.

## Actual independent controls on 317

Three source families were admitted through the fresh checker, ResourceIR and source-to-Core adapter. Each ran with two flags, producing six actual Python executions, six raw Rust processes and six scalar LLVM calls. Only one LLVM shared module was compiled. No Rust process was replayed during completion.

| Family | Flags | Values in Python, Rust and LLVM | Steps | Loans started/ended | Peak requested payload |
| --- | --- | --- | --- | --- | --- |
| Borrowed formal at index 1 with scalar arguments; shared scope then exclusive move/drop | 0, 1 | 26, 26 | 59, 59 | 8/8 each | 3 bytes |
| Two independent shared returned Views of one owner; outer and branch copies | 0, 1 | 57, 57 | 62, 62 | 9/9 each | 2 bytes |
| Outer shared Copy retained while an inner alias changes a scalar label across a loop | 0, 1 | 13, 46 | 27, 50 | 2/2 each | 4 bytes |

Each run allocates and frees one owner; every final live-byte, owner, local-loan and chain count is zero. These logical payload values are not RSS measurements. The two additional source negatives first pass both the fresh checker and ResourceIR, then refuse at the new narrow adapter: an extra nominal value-record formal, and a mutable formal returning a shared loan. Their stage-specific originals are in `admission.json`.

The original Core SHA256 is `fa4d96842feb4ab7fc6087b027b4b09882544274d81948734d71ec9b02c8d60d`. The retained Rust executable is 4,204,464 bytes, SHA256 `090ea31c9631aae744d8a72b3eb1f753bba1a36edf887d564145546865761362`. It is the existing Machine binary, copied byte-identically without a Cargo rebuild. Raw `--owned-run-bound-v4` processes use a child PATH without Python and before/after executable hashes. This is a direct-process, trusted-host observation, not the production wrapper's sealed-memfd custody claim. LLVM uses the retained Ubuntu Clang 20.1.2 and the host Linux x86-64 scalar ABI.

## Owner originals independently checked

The peer auditor reads the original process outputs, method events, Core inputs, compiler artifacts, and source/tool inventories. It does not rerun owner tests or native programs.

| Original directory | Source | Actual methods | Additional recorded observations | Materialized tracked files |
| --- | --- | --- | --- | --- |
| `frozen317-focused9` | 317 | 9/9 ordinary pass | 85 Rust comparisons: 37 returned, 48 budget stops; 5 raw refusals; 33 LLVM calls; 2 allocator calls | 1,454 |
| `frozen317-legacy87` | 317 | 84 pass, 3 import errors | Three original protocol files absent from the sparse checkout | 1,454 |
| `frozen317-legacy87-complete` | 317 | 87/87 ordinary pass | Separate execution after materializing those same-commit protocol blobs | 1,457 |
| `final0d-focused9` | 0d | 9/9 ordinary pass | 86 Rust comparisons: 38 returned, 48 budget stops; 5 raw refusals; 33 LLVM calls; 2 allocator calls | 1,457 |
| `final0d-legacy87` | 0d | 87/87 ordinary pass | Separate final-source execution | 1,457 |

All successful method sets are exact once, with no skipped, expected-failure or unexpected-success outcomes. The Rust observations include deliberately exercised budget stops; a passing test is not a claim that every program returned normally. Owner comparisons use the legacy raw `--owned-run` CLI, which is separately identified from the peer's bound-v4 envelope.

The final owner collector also retains six original bounded Clang observations, including the shared-object and object compilations, with actual argv, timing, stdout/stderr, IR and output bytes. The observer forwards the original arguments to the existing bounded runner and returns its original result. The allocator link and its two actual execution outputs are retained separately. Their results are value 50 with two allocations/two frees and peak payload 10, and value 41 when allocation attempt 2 fails, with one allocation/one free and peak payload 3. Both finish with zero live payload.

The full tracked tree contains 7,699 paths. This review's actual sparse materialization contains 1,457; the other 6,242 paths are not claimed as runtime input coverage. Every materialized file is checked against raw Git bytes and modes, and before/after identities match. The earlier 1,454-file focused run remains explicitly different.

## Findings and corrections preserved

1. **Counterexample premise:** the original `reborrow_suspended_parent` fixture used a shared parent and failed because the extra loan was unclosed at a CFG edge (`E_HIA_RESOURCE`). That actual refusal did not prove that shared reborrowing was illegal. The owner retained a separate three-process 317 diagnostic. The final tests admit a balanced shared neighbor in both Python and Rust, returning 8, and refuse a balanced exclusive-parent reborrow while its mutable child is live. Final diagnostics specifically assert `E_HIA_LOAN: conflicting live borrow` in Python and `E_HIA_LOAN: overlapping incompatible loans` in raw Rust.
2. **Sparse protocol setup:** the original 87-method run's three import errors are preserved. The three missing files were restored from the same original Git commit, with no production change; the successful follow-up has its own directory and 1,457-file inventory. The earlier focused9 was not rerun or relabeled.
3. **Peer low-level API mistake:** after all six Rust controls completed, the original peer collector passed bytes to an LLVM emitter requiring an immutable `VerifiedProgram`. It stopped before any LLVM compile or call. The original collector and traceback remain. Completion reused the six original Rust records and executed only the outstanding LLVM phase.
4. **Peer postprocessing mistakes:** three read-only audit attempts respectively confused raw/canonical contract identity, decoded/serialized Core records, and differing metadata schemas for two otherwise identical source snapshots. Each original script, traceback and partial review remains under `audit-attempt1` through `audit-attempt3`. The final auditor explicitly distinguishes those representations and passes. None of these attempts invoked native programs, reran tests or changed source.

## Retention and remaining boundaries

`final-review/review.json` is the machine-readable conclusion. `final-review/input-manifest.json` binds 139 original input files by path, byte count, SHA256, Git blob and mode; owner raw files stay in the owner's complete evidence package rather than being duplicated here. This peer package retains its own source controls, canonical Core, IR, binary, all six actual Rust records, six LLVM call records, both source inventories, tool identities, collectors, audit attempts and final source/diff review.

No general provenance, arbitrary recursive ADT, escaping stored lifetime, foreign callback/thread contract, async cancellation, process-memory theorem, representative throughput/latency, physical-device qualification or whole-language/backend proof follows from this finite slice. Broad P0–P7 blockers remain open.
