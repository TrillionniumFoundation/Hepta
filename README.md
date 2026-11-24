# HIA Core

Typed abstract assembly and structured Core for AI agents. HIA checks explicit
control flow, types, capabilities, ownership and borrowed resources before
machine-code generation. There is no high-level source language or migration
frontend in this tree.

HIA source files use the lowercase `.hepta` suffix. Assembly retains the
`hia-asm.v1` header; structured Core retains its explicit primitive or composite
schema. Paired JSON projections use `.core.hepta`. The `hia` command and
`hepta.hia.*` protocol names keep their identities.
See [source naming](docs/HIA_SOURCE_SUFFIX.md).

## Native Linux x86-64 distribution

The ordinary distribution supplies the native `hia` dispatcher, its public
Core companions, scalar NDU, MCP service programs and system Jobctl. It also
contains the complete source-attested `store.hiapack` and its matching
`hia-release` installer. The same package supplies the Worker and controller
installation, including their pinned program sets.

The production wheel contains executable HIA programs and their required data.
It has no Python import package, Python entry point, Rust executable or CPython
extension. Its executable members come from the admitted current source,
compiler and cold report. Public companion bytes are checked against the
complete package; the public dispatcher uses the HIA wheel-layout owner to
admit pip's scripts-directory permissions.

The [current implementation and acceptance index](docs/CURRENT.md) records
completed qualification, remaining requirements and active deployment. Results
belong to their exact source identities. The
[distribution contract](docs/HIA_DEFAULT_NATIVE_RELEASE.md) describes package
construction, installed validation and the separate reference profile.

## Install a native release

Use the package and checksum inventory from a trusted, source-identified build.
Install its exact bytes into a new private directory:

```sh
sha256sum --check SHA256SUMS
chmod 500 hia-release
mkdir -m 700 hia-install
digest=$(sha256sum store.hiapack | cut -d ' ' -f 1)
env -i PATH= ./hia-release install "$PWD/hia-install" "$digest" < store.hiapack
env -i PATH= ./hia-release verify "$PWD/hia-install" "$digest" < store.hiapack
env -i PATH= "$PWD/hia-install/$digest/hia" --version
```

The resulting digest directory holds the complete immutable package.
`hia-worker-install` constructs the private Worker and controller installation
from those members. MCP configuration, durable-state custody and service
activation have their own admission and lifecycle requirements.

[Native installation](docs/HIA_RELEASE_INSTALL_NATIVE.md) ·
[Selection and rollback](docs/HIA_RELEASE_SELECTION_NATIVE.md) ·
[Source rebuild](docs/HIA_NATIVE_SOURCE_BUILD.md)

## Build from admitted source

The installed native release builder consumes the matching compiler and cold
report and builds the complete package with an empty PATH:

```sh
env -i PATH= /installed/release/hia-release-build \
  --source /checkout/hia \
  --output /new/private/release \
  --compiler /qualified/current/B3.image.bin \
  --cold-report /qualified/current/cold.json \
  --timeout-seconds 1800
```

The HIA release owner captures the registered source, compiles the declared
programs, checks their complete layouts and bindings, and publishes the exact
member set. Its ordered build graphs release temporary descriptors between
groups while preserving published members. Installation and source rebuild
are checked against the actual final bytes.

The source-packaging entry point is also available:

```sh
python -m pip install .
hia capabilities
hia check-assembly examples/hia_bootstrap/bytesum.hepta
hia verify examples/hia_program/counter.hepta
```

This source build runs cold qualification and constructs the native package
before producing the wheel. Python and the independent qualification tools
are build prerequisites; the installed production commands execute the native
programs. For an already qualified compiler and cold report, use the
[explicit package builder](docs/HIA_DEFAULT_NATIVE_RELEASE.md).

## Program and interface contracts

| Area | Contract |
| --- | --- |
| Native command execution and source build | [Executable release construction](docs/HIA_EXEC_RELEASE_NATIVE.md) and [native source rebuild](docs/HIA_NATIVE_SOURCE_BUILD.md) |
| Core and nominal lowering | [Native Core application](docs/HIA_AGENT_STDIO_NATIVE.md) and [complete nominal integration](docs/HIA_COMPOSITE_NATIVE_INTEGRATION.md) |
| Checked scalar and SIMD code | [Verified kernels](docs/HIA_VERIFIED_KERNELS.md) |
| Worker policy and captured custody | [Worker execution](docs/HIA_WORKER_REPORT_NATIVE.md) |
| Native package and independent reference artifacts | [Distribution profiles](docs/HIA_DEFAULT_NATIVE_RELEASE.md) |
| Installation, selection and rollback | [Installer](docs/HIA_RELEASE_INSTALL_NATIVE.md) and [release selection](docs/HIA_RELEASE_SELECTION_NATIVE.md) |

Component contracts define their input domains, foreign effects and refusal
behavior. Whole-product acceptance additionally checks the complete installed
entry points, durable request identity, replay, UNKNOWN outcomes, worker
handoff and retirement of old references.

## Source qualification and independent controls

The development checkout retains authoring tools, original fixtures and
independent semantic references. They reproduce and test the HIA source and
native products. Hosted API and editable builds use the explicit reference
or development profile described in the distribution contract.

```sh
python -B tools/check_hia_core_only.py
python -B tools/generate_hia_selfhost_contract.py --check
python -B tools/replay_hia_selfhost_cold.py --output /var/tmp/NEW-hia-cold.json
python -B tests/test_hia_selfhost_language_coverage.py --output /var/tmp/NEW-hia-language.json
```

Cold qualification checks the original and modified-source native fixed
points, independent reference controls and resource refusals. Source contracts
identify inputs and supported domains. Acceptance records include the actual
execution result, complete retained observations and original limits.

[Current status and repository cleanup](docs/CURRENT.md) ·
[Core scope](docs/HIA_CORE_ONLY_SCOPE.md)
