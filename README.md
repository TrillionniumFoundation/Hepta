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
| Ownership | Buffer-bearing structs/enums, `Result<Owned, Error>`, explicit moves and recursive drops, checked normal/early exits, fallible byte allocation |
| Borrowing | Read/mutable parameter modes, disjoint field borrows, single-origin returned borrows, native Rust validation |
| Resource IR | Independently verified typed JSON CFG, explicit moves/loans/drops, exact resource-state joins and retained foreign obligations |
| Modules | Imports, privacy, local packages, content locks and frozen dependency identities |
| Concurrency | Hosted tasks, bounded task groups/channels, explicit join, cooperative cancellation and failure reporting |
| C | Host ABI declarations/probes; compilation-database capture; bounded module translation; complete active-declaration inventory; explicit buffer contracts and restricted allocation/free migration |
| C++ | Direct scalar/POD calls, checked call-scoped spans, dynamically protected handles, C++ template instantiation, exception/thread/destructor contracts |
| Agent tools | Snapshot-bound semantic edits, explicit interface migration, whole-import-graph native validation, crash-recoverable publication and source-level native diagnostics |
| Evaluation | Five cross-file tasks in a four-arm Rust/Hepta study, real workspace v4 in the fourth arm, strict namespace qualification, frozen adapter identity, receipt/cost accounting and independent native oracles |

See [ownership and returned borrows](docs/OWNED_TYPES.md),
[C project migration](docs/C_MIGRATION.md),
[C++ interface contracts](docs/CPP_INTEROP.md), and
[Agent workspace transactions](docs/AGENT_WORKSPACE.md).
The [resource IR](docs/RESOURCE_IR.md),
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
python -m tools.validate_resources --output /tmp/resource-evidence.json
python tools/validate_sandbox.py --output /tmp/namespace-evidence.json
python -m experiments.crossfile_eval qualify-fixtures --output /tmp/crossfile-fixtures.json
python -m experiments.crossfile_eval qualify-workspace --output /tmp/workspace-evidence.json
python tools/release_check.py
```

Optional fixed Lean/QEMU tools are installed by
`tools/bootstrap_verification.py`; Lean extraction also needs `zstandard`.
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
Each archive binds its own exact source snapshot, logs and native evidence.

The [credential-free runtime audit](evidence/audits/provider-runtime-022ed82.json)
loaded the system CA store inside the adapter capsule, but DNS resolution of
the API host failed in both parent and capsule. TLS/HTTP access and actual
provider accounting therefore remain unqualified in this environment.
