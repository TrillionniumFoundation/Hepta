# Hepta

Hepta is an experimental native systems language and compiler toolchain for
human and coding-agent collaboration. Its checked ownership model, explicit
effects, source-bound interfaces, and transaction protocol make resource and
interface obligations visible to tools.

The standalone **HIA program v1** accepts AI-authored typed SSA programs
without original high-level source. `python -m hepta hia verify`, `run`,
`build`, and `patch` share an independent ownership/effect verifier. Its direct
LLVM path does not invoke Rust. Existing executable Core operations and HIA
scalar SSA can both be imported into this same executable authority. The
[HIA program specification](docs/HIA_PROGRAM.md) defines the exact instruction,
resource, ABI and target scope; the broader hosted language remains separate.

The reference backend emits Rust and requires **Rust 1.90.0** for
native type/borrow validation. A separate C11 backend supports a narrower
hosted subset. This repository contains working implementations and native
qualification tools; it does not claim a production-complete language,
whole-compiler soundness, or universal performance superiority over Rust.

The [unified candidate](docs/UNIFIED_CANDIDATE.md) defines the current semantic
authority, explicit backend/migration scopes and repeatable acceptance entry.
An additional `build-llvm-ssa` command emits native code from verified i32/u32
SSA with exact source-origin rechecks. `build-llvm-owned` directly lowers a
separate Buffer/owned-ADT/Result/borrow/cleanup profile to LLVM on Linux x86-64.
Both require a native Rust reference check; neither silently falls back to
Rust machine-code generation. Hosted task/I/O runtimes remain outside LLVM.

The standalone optimization path now includes
[independently proved guarded reductions](docs/HIA_GUARDED_OPTIMIZATION.md),
[captured multi-unit C++ owner transfer](docs/CPP_COMPOSED_PROJECT_MIGRATION.md),
and [verified version switching with a persistent native owner](docs/HIA_OWNED_STATE_RUNTIME.md).
The [registered follow-up evaluation](experiments/hia_optimizer_eval/next_20261028/README.md)
keeps original HIA, strong native baselines, actual model maintenance tasks,
upgrades and all optimization costs visible. These finite implementations and
measurements do not grant a universal safety, performance or productivity claim.

## Implemented capabilities

The table describes the union of the explicitly qualified profiles in this
repository. It does not imply that every feature is available in standalone
HIA or in every native backend.

| Area | Current implementation |
| --- | --- |
| Ownership | Buffer-bearing structs/enums, `Result<Owned, Error>`, nested named-field moves and restoration, explicit recursive drops, checked normal/early exits, fallible byte allocation |
| Generics | Finite `Copy` / `Owned` function constraints, checked unused generic bodies, owned aggregate substitution and transfer |
| Borrowing | Read/mutable parameters, disjoint field borrows, explicit returned origins, bounded lifetime-parameterized stored shared/mutable view records, native Rust region validation |
| Resource IR | Independent v3 ownership/place CFG and v4 local stored-slice loans, fresh source/native replay, plus a separate task/group lifecycle CFG; explicit unproved refinement boundaries |
| Modules | Imports, privacy, local packages, content locks and frozen dependency identities |
| Concurrency | Hosted tasks/channels, monotonic deadlines, event-driven two-group selection, shared reservations and bounded parent/child task trees with transitive cancel/fail/join |
| Hosted I/O | Bounded single-owner local-stream reactor, nonblocking reads/writes, explicit poll, deadlines/cancellation and owned completion tickets on qualified Linux x86-64 GNU hosts |
| Board execution | Volatile integer access, explicit unsafe Rust exports, a linked no_std Cortex-M4 BSP with UART/timer IRQ execution under the pinned QEMU system model |
| Native backends | Reference Rust, independent C11 owned lowering, scalar SSA LLVM and a direct owned-byte LLVM host profile; explicit supported scopes and mandatory resource gates |
| Debugging | Unoptimized debug builds, retained generated sources, C source line tables and Rust statement mapping, actual GDB breakpoint/local/stack/step qualification |
| C | Host ABI declarations/probes; compilation-database capture; bounded module translation; complete active-declaration inventory; record/buffer views and restricted allocation/free migration |
| C++ | Direct/span/handle/constructor/scoped bridges; actual selected scalar-class and exclusive-byte-owner implementation migration; two-version upstream library upgrade observations |
| Agent tools | Snapshot-bound semantic edits, explicit interface migration, whole-import-graph native validation, crash-recoverable publication and source-level native diagnostics |
| Evaluation | Five cross-file tasks in a four-arm Rust/Hepta study, real workspace v4 and per-task publication deaths, strict namespaces, frozen adapter identity, receipt/cost accounting and independent native oracles |

See [ownership and returned borrows](docs/OWNED_TYPES.md),
[C project migration](docs/C_MIGRATION.md),
[stateful C record views](docs/C_RECORD_VIEWS.md),
[C++ interface contracts](docs/CPP_INTEROP.md),
[typed C++ constructors](docs/CPP_CONSTRUCTORS.md), and
[Agent workspace transactions](docs/AGENT_WORKSPACE.md).
The [exclusive C++ owner migration](docs/CPP_OWNED_MIGRATION.md),
[direct owned-byte LLVM backend](docs/LLVM_OWNED_BYTES.md),
[local stored-loan verifier](docs/LOCAL_STORED_RESOURCE_VIEWS.md) and
[real upstream library upgrade](docs/CPP_UPSTREAM_UPGRADE.md) describe the
resource extension and its remaining boundaries.
The [resource IR](docs/RESOURCE_IR.md),
[partial owned places](docs/PARTIAL_PLACES.md),
[concurrent resource protocol](docs/CONCURRENT_IR.md),
[shared runtime reservations](docs/SHARED_RUNTIME.md),
[stored borrowed records](docs/BORROWED_STORAGE.md),
[structured task trees](docs/TASK_TREES.md),
[bounded hosted I/O](docs/ASYNC_IO.md),
[Cortex-M4 startup and MMIO](docs/SYSTEM_BOARD.md),
[owned C backend](docs/C_OWNED_BACKEND.md),
[native debugging](docs/DEBUGGING.md),
[owned application costs](docs/APPLICATION_BENCHMARKS.md),
[four-arm cross-file evaluation](docs/CROSSFILE_AGENT_EVAL.md) and
[next-stage acceptance map](docs/NEXT_STAGE_EXECUTION.md) describe their exact scopes.

## Build and run

The independent HIA entry works with Python and a qualified Clang for native
builds; no Rust installation or original source is needed:

```sh
python -m hepta hia verify examples/hia_program/counter.hia
python -m hepta hia run examples/hia_program/counter.hia --function increment --arguments '[40]'
python -m hepta hia build examples/hia_program/counter.hia --clang clang -o /tmp/counter.so
python -m hepta hia patch examples/hia_program/counter.hia \
  --request examples/hia_program/add_two.patch.json -o /tmp/counter-v2.hia
```

The bootstrap compiler uses Python's standard library. Install the pinned Rust
components with the repository's checksum-checked installer, or set `RUSTC` to
an existing matching compiler:

```sh
python tools/bootstrap_toolchain.py
python -m hepta doctor
python -m hepta run examples/owned/main.hepta --json
python -m hepta check examples/packages/app --locked
python -m hepta run examples/c_owned_backend/main.hepta --backend c --json
python -m hepta build examples/debug/main.hepta --debug -o artifacts/debug-program
```

Native Rust checking is the default. `--frontend-only` deliberately produces
an incomplete qualification result. The generated C ABI and foreign libraries
retain explicit caller/implementation assumptions.

## Migrate and integrate

```sh
python -m hepta migrate-c-project compile_commands.json \
  --contracts contracts.json --output /tmp/c-migration
python -m hepta migrate-cpp-class examples/cpp/class_migration/scalar_state.cpp \
  --output /tmp/scalar_state.hepta
python -m hepta migrate-cpp-owned examples/cpp/owned_migration/owned_bytes.cpp \
  --output /tmp/owned_bytes.hepta
python -m hepta build-llvm-owned examples/llvm_owned/main.hepta \
  --output /tmp/owned-native.so --clang clang
python -m hepta bridge-cpp-contract examples/cpp/stdlib/foreign.hpp \
  --contract examples/cpp/stdlib/contract.json --output-dir /tmp/cpp-bridge
python -m hepta bridge-cpp-contract examples/cpp/scoped/foreign.hpp \
  --contract examples/cpp/scoped/contract.json --output-dir /tmp/cpp-scoped-bridge
python tools/qualify_c_migration.py --output /tmp/c-migration-evidence.json
python tools/qualify_c_algorithms.py --output /tmp/upstream-c-evidence.json
python tools/validate_cpp.py --output /tmp/cpp-evidence.json
python tools/validate_cpp_constructors.py --output /tmp/cpp-constructor-evidence.json
```

C migration supports the explicitly documented profile and rejects unsupported
active declarations even if no selected function uses them. The compiler does
not translate arbitrary C++ implementations into safe Hepta. Selected complete
scalar value classes can be translated into actual Hepta implementations;
nontrivial C++ libraries use generated, native-checked interfaces. Pointer validity, retention,
foreign synchronization and undefined behavior cannot be established by
declaring a contract.

## Agent transactions

```sh
python -m hepta workspace init /tmp/owned-workspace \
  --root examples/owned --entry main.hepta
python -m hepta workspace inspect /tmp/owned-workspace
python -m hepta workspace patch /tmp/owned-workspace \
  --request /tmp/patch.json --apply
python -m hepta workspace recover /tmp/owned-workspace
```

Readers pin a complete immutable version. Writers publish one reference after
checking all edits together. This protocol does not promise atomic writes to
arbitrary mutable editor checkouts. Version identities include source content,
compiler identity, native toolchain and target profile.

## Verification and limits

```sh
python -m unittest discover -s tests -v
python -m hepta resource-ir examples/owned/main.hepta
python -m hepta concurrent-ir examples/groups/select_pipeline.hepta
python -m tools.validate_resources --output /tmp/resource-evidence.json
python -m tools.qualify_places --output /tmp/places-evidence.json
python tools/validate_c_owned.py --output /tmp/c-owned-evidence.json
python tools/validate_shared_runtime.py --repeats 3 --output /tmp/shared-runtime-evidence.json
python tools/validate_concurrent_ir.py --output /tmp/concurrent-ir-evidence.json
python tools/qualify_borrowed_storage.py --output /tmp/stored-borrows-evidence.json
python tools/validate_task_tree.py --repeats 3 --output /tmp/task-tree-evidence.json
python tools/validate_io.py --repeats 3 --output /tmp/async-io-evidence.json
python tools/validate_board.py --output /tmp/board-evidence.json
python tools/verify_memory.py --output /tmp/memory-proof-evidence.json
python tools/validate_native_host.py --output /tmp/native-host-evidence.json
python tools/validate_debugger.py --output /tmp/debugger-evidence.json
python tools/benchmark_applications.py --output /tmp/application-evidence.json
python tools/validate_sandbox.py --output /tmp/namespace-evidence.json
python -m experiments.crossfile_eval qualify-fixtures --output /tmp/crossfile-fixtures.json
python -m experiments.crossfile_eval qualify-workspace --output /tmp/workspace-evidence.json
python -m experiments.crossfile_eval qualify-workspace-crashes --output /tmp/workspace-crashes.json
python tools/qualify_c_ring_buffer.py --output /tmp/ring-buffer-evidence.json
python tools/release_check.py
```

Full release qualification additionally requires a supported Linux x86-64 host
with working Bubblewrap namespaces, GCC/G++, Clang, GDB/child-process debugging and Boost development
headers, local socket writes and QEMU 8.2.2 `qemu-system-arm`. Fixed Lean/QEMU user-mode tools are installed by
`tools/bootstrap_verification.py`; Lean extraction also needs `zstandard`.
The qualification workflow provisions these dependencies and rejects skips.
Native tests, allocator failure injection, ABI execution, observed machine
code, timings, and abstract formal proofs have different scopes. The
[blocker ledger](docs/BLOCKERS.md) keeps these boundaries explicit.

The [OpenAI reference adapter](tools/provider_adapter/README.md) implements
real usage receipts, explicit failed attempts, and standalone export. Its
transport tests are offline. Real model comparisons require explicitly
configured model revisions, API access and budgets, plus a qualified isolated
execution environment. No real model comparison has been run. Trusted fixture
runs and strict namespace script runs test the evaluator and native tasks;
they are not AI productivity evidence.

The original integration qualification is preserved in
[evidence/next_stage](evidence/next_stage/manifest.json). Qualification after
the production v4 experiment integration is retained in
[evidence/production_v4](evidence/production_v4/manifest.json). The subsequent
complete qualification, including the provider HTTP response-completion fix,
is in [evidence/production_v4_final](evidence/production_v4_final/manifest.json).
The subsequent finite Owned generics, stateful upstream C module, typed C++
construction, channel deadline and per-task crash integration is archived in
[evidence/next_blockers_final](evidence/next_blockers_final/manifest.json).
The subsequent partial-place, owned-C, shared-runtime, concurrent-IR,
provenance/type-core and debugger integration is archived in
[evidence/production_progress_final](evidence/production_progress_final/manifest.json).
The subsequent stored-borrow, structured-tree, bounded-I/O and Cortex-M4 system
execution integration is archived in
[evidence/runtime_storage_board_final](evidence/runtime_storage_board_final/manifest.json).
Each archive binds its own exact source snapshot, logs and native evidence.

The [credential-free runtime audit](evidence/audits/provider-runtime-022ed82.json)
loaded the system CA store inside the adapter capsule, but DNS resolution of
the API host failed in both parent and capsule. TLS/HTTP access and actual
provider accounting therefore remain unqualified in this environment.
