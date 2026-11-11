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
Runtime integration: [compatibility and upgrade requirements](docs/HIA_RUNTIME_COMPATIBILITY_AUDIT_20261110.md).
