# HIA Core

Typed abstract assembly and structured Core for AI agents. HIA checks explicit
control flow, types, capabilities, ownership and borrowed resources before
machine-code generation. There is no high-level source language or migration
frontend in this tree.

All retained HIA source files use the lowercase `.hepta` suffix. Assembly keeps
the `hia-asm.v1` header; structured Core keeps its explicit primitive or composite
schema. Paired JSON projections use `.core.hepta` to avoid filename collisions.
The `hia` command and `hepta.hia.*` protocol schemas retain their names.
See [source naming and migration](docs/HIA_SOURCE_SUFFIX.md).

The [current implementation and acceptance status](docs/CURRENT.md) is the
single current-state index. Historical observations retain their exact commit
identities and do not qualify a later candidate.

The current worker-policy candidate composes native request/report/wire images
under an explicit administrator bundle pin; its hosted custody and durable
service/runtime dependencies are not yet retired. See
[worker policy and custody](docs/HIA_WORKER_REPORT_NATIVE.md).

## Agent entry

```sh
python -m pip install .
hia capabilities
hia check-assembly examples/hia_bootstrap/bytesum.hepta
hia verify examples/hia_program/counter.hepta
```

The `hia` entry is currently a Python-hosted bridge. An explicitly selected
[two-image HIA CLI owner](docs/HIA_NATIVE_CLI_CONTROL_RECOVERY_20261111.md)
now controls all fifteen actions, argument/help/error presentation, sequencing
and current selfhost-build selection. Semantic action bodies, file policy and
successful JSON presentation remain named foreign owners; this is not a
standalone wholly native CLI.
The independently built
HIA-native stdio application supports `capabilities`, `verify`, `compile`,
`render-assembly` and direct HIA-source `assemble` on
Linux x86-64 without Python at runtime; see [native stdio](docs/HIA_AGENT_STDIO_NATIVE.md).
The ordinary `hia build --backend selfhost` route can explicitly select an
operator-pinned HIA compiler for bounded primitive Core v8 ELF objects. Its
native frontend and code generator execute without the Python emitter or an
external linker; the CLI, admission and publication bridge remain hosted.
See [native compiler selection and its supported profile](docs/HIA_PROGRAM_SELFHOST_BUILD.md).
The separate [native patch application](docs/HIA_CORE_PATCH_CLI.md) performs
snapshot-bound edits with native whole-Core checks of both base and candidate.
The [native patch-result application](docs/HIA_CORE_PATCH_RESULT_CLI.md) also
constructs the complete diagnostic bytes. Its explicit ordinary Agent route
consumes and stores opaque payload bytes, preserving the existing request journal.
An explicitly selected [native nominal type session](docs/HIA_COMPOSITE_TYPES_NATIVE.md)
owns declaration checks, generic binding, finite layouts and partial-record
obligations for all four composite versions, source-level returned-loan origins,
parameter admission and task-protocol checks. A separately selected
[native task-helper generator](docs/HIA_TASK_HELPERS_NATIVE.md) constructs the
complete start, poll, cancel, join and close Core functions. The selected
[complete function bundle](docs/HIA_COMPOSITE_FUNCTION_NATIVE_DESIGN.md) owns
nominal SSA/CFG, record/enum/partial/task operations, terminators and generated
entry-name loan binding in HIA. The [complete selected nominal route](docs/HIA_COMPOSITE_NATIVE_INTEGRATION.md)
also moves constructor admission, ordered signatures, complete function/helper
aggregation, late limits, exports and primitive schema selection into HIA.
Its five explicit owners use eleven images; the surrounding bridge retains
foreign-object and packet custody. The default route and durable Agent remain
hosted. Native normalization preserves the existing primitive Core recheck.
An explicitly selected [native worker request kernel](docs/HIA_WORKER_REQUEST_NATIVE.md)
owns ordinary JSON, finite binary64 canonical bytes, request digests and envelope
admission while preserving the existing service's durable request identity.
An explicit [native journal owner](docs/HIA_AGENT_JOURNAL_NATIVE.md) supplies
reservation, replay, conflict and unknown decisions and canonical response/cost
instructions; SQLite durability and tool effects retain their existing owners.
The [pinned helper bundle](docs/HIA_NATIVE_HELPER_WORKER.md) selects existing
kernels and that journal through ordinary worker callers. Selected
[execution budgets](docs/HIA_EXECUTION_BUDGET_NATIVE.md) preserve the original
SQLite accounting and unknown-outcome fencing. Selected
[candidate attempt budgets](docs/HIA_CANDIDATE_BUDGET_NATIVE.md) preserve the
original context counter, request replay and committed charges. Selected
[slot and lease state](docs/HIA_SLOT_LEDGER_NATIVE.md) also owns adoption's
evaluation-completion, outcome and net-benefit decisions, while the existing
store retains SQLite effects, receipt binding and request replay. Selected
[retirement state](docs/HIA_RETIREMENT_STATE_NATIVE.md) owns release decisions
while the original process retains actual foreign resources and system calls.
The separate [native release installer](docs/HIA_RELEASE_INSTALL_NATIVE.md)
checks and publishes a bounded immutable release from an operator-pinned bundle.
It does not select the active worker or replace the service journal.
The [native release selector](docs/HIA_RELEASE_SELECTION_NATIVE.md) verifies
installed release bytes and provides explicit status, compare-and-swap
activation and previous-release rollback. Its durable selection is independent
of the ordinary worker; default service migration remains open.
Full native Agent editing/persistence, modules/build, runtime and installation
acceptance are still open. No interpreter, Rust or LLVM fallback is selected by
the Agent entry. Standalone Core research backends remain explicitly scoped.

## Source and native qualification

```sh
python -B tools/check_hia_core_only.py
python -B tools/generate_hia_selfhost_contract.py --check
python -B tools/replay_hia_selfhost_cold.py --output /var/tmp/NEW-hia-cold.json
python -B tests/test_hia_selfhost_language_coverage.py --output /var/tmp/NEW-hia-language.json
```

Cold qualification preserves original and modified-source native fixed points,
independent reference controls and resource refusal witnesses. Source contracts
are identities, not correctness or release approvals. Old high-level-specific
CI projections are retired, not reported as passed. [Scope](docs/HIA_CORE_ONLY_SCOPE.md).

Repository cleanup: [current audit](docs/CURRENT.md#repository-cleanup-and-parallel-work).
Native rewrite: [current implementation and remaining owners](docs/CURRENT.md).
Runtime integration: [compatibility and upgrade requirements](docs/CURRENT.md#remaining-product-acceptance).

The selected [HIA JSON wire](docs/HIA_JSON_WIRE_NATIVE.md) owns bounded graph and encoding decisions, with explicit foreign-object transport and unclosed option domains. See [current status](docs/CURRENT.md) for source-bound qualification and remaining whole-product owners.
