# Exact 608 source custody and remaining implementation owners

## Result and scope

The official source artifact for `608157e52b0b94e0d294f6b99c4e809869f183aa`, tree `e7c29a60796a1a78946a2c667aa80df86529e532`, passed this independent **bare-object source audit**. Every original ZIP member was read and checked. Every packed object was decoded, independently hashed and connected to the original commit and complete canonical tree. This did not execute product tests, the formal package consumer, or an independent working clone. The original GitHub reconstruction report is preserved as a separate prior execution, not substituted for the actual object reads in this audit.

The implementation audit finds **no basis to delete the remaining Python/Rust stack**. HIA kernels have substantial implemented scope, but an installed Python package, hosted foreign bridges, ordinary domain algorithms, build/publication machinery, and an external Rust MCP/process owner remain. Source counts measure coverage, not semantic replacement.

### Independently verified source identity

| Item | Actual observation |
| --- | --- |
| Official workflow | `43055736977`, attempt 1 |
| Official artifact | `13870963554` |
| Original ZIP | 300,074,958 bytes; SHA256 `837e8fecfa42012d0749ef7464a083e8a46743e49915ee0b99ebb6bf00df45c2` |
| Original ZIP members | 8; every CRC, size and SHA256 checked |
| Source pack | 294,622,374 bytes; SHA256 `3a23e076466a963864790c144b8f7ffa5e41ed960fb954480fc32b5e067eb233` |
| Raw Git objects | 4,194; independently checked type, size, Git SHA1 and SHA256 |
| Tree records | 4,462; canonical byte ordering, path/mode/duplicate/graph checks |
| File leaves | 3,925; 400,417,773 bytes; every mode, size, blob SHA1 and content SHA256 checked |
| Empty tree paths | None observed |
| Raw commit | 914 bytes; SHA256 `0076479cf0f8544ea1df57e1a8b5752bc826ce5bf092a65fe5956f00402a5e1f` |
| Manifest | SHA256 `cec14d50ede38a6bcd11595476975cc376b3606d211098a565a5b1593249e3af` |
| Auditor execution | Exit 0; 7.623294594 seconds inside the auditor |

The original commit has five parent headers, in this exact order:

1. `be4ea0a40c246dca98bf80556d6c1a55b14b62df`
2. `3037846d6f8e823aeeea0b63e53957b0adf9fe20`
3. `d246d41418883684afc1a18acb5906ec23017de8`
4. `438d7d4c466e40ee2c80d7cdb35bdb26e58f32e3`
5. `fbddbc5f2a6991a9a9b3bd501c2a910904f7a7bb`

The export has an explicit shallow boundary at the original commit. Parent headers were preserved; absent historical parent objects were not rewritten into a synthetic root or represented as an audited complete history. The private audit bare repository has no alternates, promisors or grafts. The original ZIP and its contents were unchanged after the reads. The complete raw observations are in the adjacent audit JSON and archived original reports.

## Semantic inventory method

`remaining-owners.json` records all **161 installed `hepta/*.py` modules**, all **481 non-experiment Python source files** (including tools, formal/example helpers and setup), and all **48 repository Rust source files**. Every listed file was read in full and checked against the canonical SHA1/SHA256 inventory. Python ASTs were parsed. Each installed module has its actual declarations, imported modules, selected-native/foreign calls, literal selectors, source hashes and an owner classification. Rust entries preserve module documentation and actual function declarations. The 161-row TSV is a compact index of the JSON.

This is a structural and focused semantic audit, not a claim that static inspection proves every path equivalent. The focused traces follow ordinary CLI/worker entry, primitive and nominal normalization, direct code generation, mutable assembler state, ELF output, service/store/journal boundaries, and build/runtime custody. All test, benchmark and experiment bytes were covered by the object audit; those directories are excluded from the 481-file production/tooling semantic count. Rust test/reference files remain explicitly identified as such. The external `hepta-runtime` implementation is not present in this repository and was not silently included in the Rust-file count.

## Ordinary entry and default behavior

`pyproject.toml` installs `hia = hepta.cli:hia_main` and requires Python. The build backend is setuptools. `setup.py` reads the source-resource contracts and copies pinned HIA/runtime resources into the wheel. It is a Python build-resource hook; it does not implement a complete HIA-native build/install driver.

In `hepta/cli.py`, absence of `HEPTA_HIA_CLI_MANIFEST` takes `_reference_hia_main`. The selected `hia_cli_native.CliSession` owns argv/control/presentation through HIA, but its foreign-effect dispatcher calls the ordinary API bodies. All fifteen actions still depend on the corresponding retained APIs:

| Action group | Retained domain work |
| --- | --- |
| capabilities/catalog | Python contract and installation metadata construction |
| import/render/check assembly | Ordinary assembly parsing, rendering, diagnostics and Core validation |
| verify/inspect/normalize | Full verifier, shape/interface reports, canonical structured objects |
| build | General backend lowering, object layout, linking and artifact inspection |
| patch/impact | Snapshot patch interface, call-graph impact and full fresh verification |
| edit-query/edit-apply | Context/slice object construction, bounded patches, fresh admission |
| edit-batch-query/edit-batch-apply | Batch conflict/context semantics and ordinary publication |

A selected CLI controller therefore does not establish that all fifteen domain implementations have been rewritten. The Python entry and source-backed installed wheel must remain until the whole selected path is replaced and independently qualified.

The ordinary worker has separately selected report and request owners. HIA can own those selected continuations and canonical/report bytes, while `argparse`, foreign callbacks, the service instance, store, I/O and installation source observations remain hosted. The default report path is `_reference_run`; selected report does not automatically select every request/service kernel.

## Core verification, normalization and execution

`hia_program.verify_program` still performs bounded decode/snapshot, schema dispatch, module/interface construction and body/resource checking. `_BlockCheck` is a live ordinary owner of instructions, capabilities, borrows, calls, control-flow joins and exit conditions. Selected instruction/shape/admission kernels are explicit portions of the larger verification path. A verified wrapper is rechecked rather than treated as authority merely because a previous call succeeded.

`hia_program_composite._Types` and `_Elaborator` retain ordinary nominal types and lowering. Selected HIA type, constructor, helper, function and outer kernels cover declared parts and issue tokens/materialization facts. The hosted object interface, remaining reference paths and fresh primitive verification still matter. Whole function lowering is a significant component completion, not permission to remove the primitive verifier or every constructor/outer reference route.

`hia_program_runtime._Machine` remains the finite direct Python interpreter for public standalone Core execution. `hia_routes` exposes explicit machine, LLVM and reference/research routes rather than an implicit fallback. Removing a route simply because another route is native would reduce the supported API. Proof/resource/optimization modules also remain Python: static bounds, initialization coverage, scalar totality, SMT translation validation, guarded rewrites, call expansion, narrowing, specialization and economic selection require their own replacements or an explicitly changed public contract.

## Machine backend: exact remaining boundaries

The 37-command HIA instruction owner is selected through `HEPTA_HIA_MACHINE_ENCODING_MANIFEST`. It emits instruction bytes. It does not yet own the full backend state or object layout.

`hia_machine_x64.Code` exposes mutable `data`, `labels`, `fixups` and `relocations`. The hosted class retains scratch-register permutation/options validation, append bounds, labels, branch/call mutation order and finalization. `NativeEncodedCode` inherits this state. Its finalization still snapshots the bytearray, reads labels and fixups, computes patch positions and copies relocation records; HIA supplies the four-byte displacement encoding. A future hidden HIA shadow state cannot replace these fields without observing caller mutation and partial-failure ordering.

The exact general backend classes are `_Function` and `_Emitter` in `hia_program_native.py`; this tree has no class named `_Backend`. They still own SSA/operation lowering, stack frames, local locations, CFG edge copies, argument/result marshaling, bounds and byte/chains support, block layout and native wrappers. The object is built only after fresh verification and explicit plan/ABI handling. Python also hashes implementation inputs, invokes the linker under its process owner, inspects objects/shared-library exports and publishes artifacts.

`hia_machine_elf.write_elf_object` is a particularly useful next whole owner. It is a bounded deterministic ET_REL API used by the general backend. Its complete policy and formatting remain Python: record admission, names, ranges, ordering, relocation matching, symbol/string tables, offsets, alignment, section headers and ELF header. The existing selfhost packer is a different restricted surface and cannot stand in for this API.

### Accepted next implementation slice

Move the complete general ELF writer into HIA, retaining the original AST as an independent oracle. Preserve these actual semantics:

- 64 MiB object budget, fewer than 65,536 initial definitions, complete defined/undefined symbol limit, all alignments 16/32/64.
- Exact Python type checks and rejection precedence, including name validation before later row checks and range-overlap rejection before relocation admission.
- The original number and order of foreign dictionary/list observations, including custom key equality/hash exceptions or mutation. The bridge may report facts and move buffers; it must not precompute the whole layout for HIA to approve.
- Deterministic local/public/undefined symbol ordering, string offsets, hidden local visibility, symbol indexes and all seven sections.
- Explicit `E8` plus four zero bytes, nonoverlapping five-byte relocation spans, PLT32 type 4 and signed RELA addend -4.
- Exact returned bytes, ordinary backend return-object metadata, repeated calls and failure behavior.

Validation must disable the retained writer in actual general callers, compare all outputs with the independently retained full AST oracle, inspect/disassemble real objects, link and load actual exports, and execute the installed wheel with `-I -S -B`. This is an independent development slice, not a modification of frozen 608 or a claim to complete the machine lowering stack.

## Agent persistence and runtime effects

`AgentStore` still owns durable profiles and identities, references/URI authority, private file handling, SQLite structure and connections, query results, state/lease effects and custody. The selected HIA journal owns its declared transition policy and byte decisions through a mechanical SQLite bridge. SQLite execution and transaction machinery remain Python/native-library foreign effects. Artifact publication has a native policy/syscall adapter, but that does not replace all store methods or ordinary service methods.

`HIAAgentService` contains the eleven domain tool implementations. The unfinished page experiment is preserved as five completed cases out of forty-two plus executor continuity UNKNOWN; it has not replaced the frozen ordinary `_hia_read`. CLI r4 custody success is distinct from its original product failure and from the separate r5 wrapper UNKNOWN. None of these original results is relabelled by this static audit.

Stateful runtimes, immutable generation selection, leases, quiescence, cancellation, queue commit, rollback and native retirement also remain live Python owners. Rewriting arithmetic kernels or a file publisher cannot substitute for preserving these effect/lifetime obligations.

## Rust and foreign boundaries

The local Rust tree contains a separate Core shadow/explicit finite raw-Core execution family and NDU adapters, models/planners and workload/reference fixtures. Their real Rust semantics are not HIA. Some are deliberately independent crosschecks, others implement explicit Rust-only public profiles or call upstream NDU algorithms. Native Rust output is not HIA-native output. The inventory binds every local Rust source but does not infer production authority from comments or count them as safe to delete.

The checked Agent contract pins a **separate** `hepta-runtime` at `02c390876d4681ddfb90bb9dd6269bbf4e6f6419`. The worker documentation assigns it MCP negotiation, caller authorization, durable job identity, cancellation and terminal-report validation. The contract describes reuse of the existing rmcp/jobs transport and observation of an original unknown operation. This external source and live deployment were not audited here. They remain an explicit closure/deletion blocker; no deployment cutover or proof of continuity is asserted.

Python also remains at the boundaries to ctypes/OS files/processes, SQLite, Z3, LLVM/Clang on explicit routes, Rust NDU, Lean evidence and wheel packaging. A final native distribution needs a declared machine/OS interface, source-bound self-rebuild path, immutable installation/activation, recovery/retirement, and real end-to-end process/MCP qualification. It cannot be obtained by deleting these implementations prematurely.

## Dependency order and deletion decision

| Order | Work | Why it is the next dependency |
| --- | --- | --- |
| 1 | Whole general ELF writer | Complete bounded API; closes layout/format policy after real HIA instruction bytes without touching store ownership |
| 2 | Mutable `Code` state/fixups and general `_Function`/`_Emitter` | Removes hosted sequencing/lowering only after preserving public state and failure observations |
| 3 | Ordinary full Core admission/normalization/edit APIs and remaining CLI bodies | Required for default `hia` behavior rather than just selected protocol/control components |
| 4 | Store/service/read authority, durable effects and stateful lifetime owners | Required to retain ordinary tools, persistence, leases and recovery; independent work already assigned |
| 5 | Native build/installation/default activation and external process/MCP owner | Requires the earlier real whole paths and preserves in-flight operation continuity |
| 6 | Retained route/reference retirement under explicit policy | Delete only once replacement behavior, environment/ABI and full gates are observed; independent oracles may be retained as tests without being a runtime fallback |

The current deletion decision is **HOLD**. The raw source custody audit is PASS, but neither full retained qualification nor whole-native delivery follows from it. All original failures and UNKNOWNs remain their original results.
