# Hepta

Hepta is an experimental native systems language and compiler toolchain for
human and coding-agent collaboration. Its checked ownership model, explicit
effects, source-bound interfaces, and transaction protocol make resource and
interface obligations visible to tools.

The current reference backend emits Rust and requires **Rust 1.90.0** for
native type/borrow validation. A separate C11 backend supports a narrower
hosted subset. This repository contains working implementations and native
qualification tools; it does not claim a production-complete language,
whole-compiler soundness, or universal performance superiority over Rust.

## Implemented capabilities

| Area | Current implementation |
| --- | --- |
| Ownership | Buffer-bearing structs/enums, `Result<Owned, Error>`, nested named-field moves and restoration, explicit recursive drops, checked normal/early exits, fallible byte allocation |
| Generics | Finite `Copy` / `Owned` function constraints, checked unused generic bodies, owned aggregate substitution and transfer |
| Borrowing | Read/mutable parameter modes, disjoint field borrows, explicit returned origin among several inputs, native Rust validation |
| Resource IR | Independent v3 ownership/place CFG plus a separate task/group lifecycle CFG; abstract generic bodies, retained graphs and explicit unproved refinement boundaries |
| Modules | Imports, privacy, local packages, content locks and frozen dependency identities |
| Concurrency | Hosted tasks/channels, monotonic deadlines, event-driven two-group selection, shared thread/input/queue/requested-stack reservations, explicit cancel/join and cooperative failure reporting |
| Native backends | Reference Rust plus independent C11 owned ADT/Result/Buffer lowering, bounded monomorphization and a mandatory independent resource gate for its ownership profile |
| Debugging | Unoptimized debug builds, retained generated sources, C source line tables and Rust statement mapping, actual GDB breakpoint/local/stack/step qualification |
| C | Host ABI declarations/probes; compilation-database capture; bounded module translation; complete active-declaration inventory; record/buffer views and restricted allocation/free migration |
| C++ | Direct scalar/POD calls, checked call-scoped spans, dynamically protected handles, typed constructors, C++ template instantiation, exception/thread/destructor contracts |
| Agent tools | Snapshot-bound semantic edits, explicit interface migration, whole-import-graph native validation, crash-recoverable publication and source-level native diagnostics |
| Evaluation | Five cross-file tasks in a four-arm Rust/Hepta study, real workspace v4 and per-task publication deaths, strict namespaces, frozen adapter identity, receipt/cost accounting and independent native oracles |

See [ownership and returned borrows](docs/OWNED_TYPES.md),
[C project migration](docs/C_MIGRATION.md),
[stateful C record views](docs/C_RECORD_VIEWS.md),
[C++ interface contracts](docs/CPP_INTEROP.md),
[typed C++ constructors](docs/CPP_CONSTRUCTORS.md), and
[Agent workspace transactions](docs/AGENT_WORKSPACE.md).
The [resource IR](docs/RESOURCE_IR.md),
[partial owned places](docs/PARTIAL_PLACES.md),
[concurrent resource protocol](docs/CONCURRENT_IR.md),
[shared runtime reservations](docs/SHARED_RUNTIME.md),
[owned C backend](docs/C_OWNED_BACKEND.md),
[native debugging](docs/DEBUGGING.md),
[owned application costs](docs/APPLICATION_BENCHMARKS.md),
[four-arm cross-file evaluation](docs/CROSSFILE_AGENT_EVAL.md) and
[next-stage acceptance map](docs/NEXT_STAGE_EXECUTION.md) describe their exact scopes.

## Build and run

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
python -m hepta bridge-cpp-contract examples/cpp/stdlib/foreign.hpp \
  --contract examples/cpp/stdlib/contract.json --output-dir /tmp/cpp-bridge
python tools/qualify_c_migration.py --output /tmp/c-migration-evidence.json
python tools/qualify_c_algorithms.py --output /tmp/upstream-c-evidence.json
python tools/validate_cpp.py --output /tmp/cpp-evidence.json
python tools/validate_cpp_constructors.py --output /tmp/cpp-constructor-evidence.json
```

C migration supports the explicitly documented profile and rejects unsupported
active declarations even if no selected function uses them. The compiler does
not translate arbitrary C++ implementations into safe Hepta; C++ libraries stay
behind generated, native-checked interfaces. Pointer validity, retention,
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
headers. Fixed Lean/QEMU tools are installed by
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
Each archive binds its own exact source snapshot, logs and native evidence.

The [credential-free runtime audit](evidence/audits/provider-runtime-022ed82.json)
loaded the system CA store inside the adapter capsule, but DNS resolution of
the API host failed in both parent and capsule. TLS/HTTP access and actual
provider accounting therefore remain unqualified in this environment.
