# HIA Core

Typed abstract assembly and structured Core for AI agents. HIA checks explicit
control flow, types, capabilities, ownership and borrowed resources before
machine-code generation. There is no high-level source language or migration
frontend in this tree.

## Agent entry

```sh
python -m pip install .
hia capabilities
hia check-assembly examples/hia_bootstrap/bytesum.hiaasm
hia verify examples/hia_program/counter.hia
```

The `hia` entry is currently a Python-hosted bridge. The independently built
HIA-native stdio application supports `capabilities`, `verify`, `compile`,
`render-assembly` and direct HIA-source `assemble` on
Linux x86-64 without Python at runtime; see [native stdio](docs/HIA_AGENT_STDIO_NATIVE.md).
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
complete start, poll, cancel, join and close Core functions. Two explicit
native nominal routes are retained during integration: the
[complete function bundle](docs/HIA_COMPOSITE_FUNCTION_NATIVE_DESIGN.md) and
the [individual nominal owners](docs/HIA_NOMINAL_FUNCTION_NATIVE.md).
The [complete selected nominal route](docs/HIA_COMPOSITE_NATIVE_INTEGRATION.md)
moves constructor admission, ordered signatures, complete function/helper
aggregation, late limits, exports and primitive schema selection into HIA.
An explicitly selected [native worker request kernel](docs/HIA_WORKER_REQUEST_NATIVE.md)
owns ordinary JSON, finite binary64 canonical bytes, request digests and envelope
admission. Separate native request journal and execution budget owners retain
the existing service's transaction and foreign-resource boundaries.
The [native release installer](docs/HIA_RELEASE_INSTALL_NATIVE.md) checks and
publishes a bounded immutable release from an operator-pinned bundle.
Default selection and whole-stack delivery remain unqualified; the old owners
are retained until the corresponding complete replacement is qualified.
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

Repository cleanup: [current audit](docs/HIA_REPOSITORY_CLEANUP_20261110.md).
Native rewrite: [current audit, implementation and remaining owners](docs/HIA_NATIVE_SELF_REWRITE_AUDIT_20261111.md).
Earlier source-bound observations remain in the [rewrite history](docs/HIA_NATIVE_REWRITE_STATUS_20261111.md).
The selected [native enum-match owner](docs/HIA_ENUM_MATCH_NATIVE.md) produces
complete match control flow; other nominal operations remain separate owners.
The [native release selector](docs/HIA_RELEASE_SELECTION_NATIVE.md) implements
explicit status, compare-and-swap activation and previous-version rollback for
verified immutable releases. Ordinary CLI/service migration remains open.
Runtime integration: [compatibility and upgrade requirements](docs/HIA_RUNTIME_COMPATIBILITY_AUDIT_20261110.md).
