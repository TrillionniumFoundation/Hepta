# HIA unified candidate and entry-point preflight

`tools/hia_candidate_preflight.py` binds one exact Hepta source commit to one
exact `hepta-runtime` commit. It prepares a private runtime configuration copy
using the installed worker's actual identities and checks the complete MCP
entry point. The current companion runtime is
`9f60a30530f47925f4f6ae495660a1d68bb6947d` (runtime PR #109).

The runtime process owner, request recovery, host policy and public gateway
remain the existing implementations. This helper does not install a service,
grant permissions, switch a deployed configuration or publish the HIA tools to
ChatGPT. A source candidate and a working operator entry point are separate
qualification results.

## 1. Prepare the exact source pair

Use an existing administrator-reviewed runtime configuration. Its `hosts` and
`hia_worker` must already name the intended Linux worker, interpreter,
installation, capture roots and private state root. The helper replaces only
the three source pins and makes the existing HIA defaults explicit. It retains
all other configuration fields.

Both checkouts must be at the supplied full commit IDs and clean. The runtime
checkout needs `deploy`, `src/mcp` and its root files. The helper reads the
selected runtime's existing contract and descriptor-relative snapshot helpers;
it checks their actual bytes against that exact runtime commit before loading
them. It does not copy those policies into a second runtime.

Example, with reviewed installation paths and the chosen Hepta commit supplied
by the operator:

```sh
python3 -B tools/hia_candidate_preflight.py prepare \
  --hepta-root /opt/Hepta \
  --hepta-revision "$HIA_SOURCE_COMMIT" \
  --runtime-checkout /opt/hepta-runtime \
  --runtime-revision 9f60a30530f47925f4f6ae495660a1d68bb6947d \
  --config /etc/hepta-runtime/reviewed-runtime.json \
  --worker-python /opt/hepta-venv/bin/python3 \
  --output-directory /var/lib/hepta-preflight/candidate
```

The output directory must not already exist; its parent must already be trusted
and writable by the operator. Generated files are mode 0600 under a mode-0700
directory. Existing directories are not chmodded or repaired. The input
configuration is never overwritten. Keep generated configuration copies outside
the source checkouts so they do not alter the selected revisions.

The two files are:

- `candidate.json`: the exact commit pair, independently measured worker source
  inventory, actual worker/backend/catalog identities, private configuration
  digest and normalized HIA profile digest.
- `runtime-config.json`: the existing configuration with measured source pins.

The worker is queried only with `--installation-manifest`; preparation does not
open its writable service store. The independent source inventory includes all
`hepta/**/*.py` and every document in the literal `DISCOVERY_FILES` tuple in
`hepta/hia_agent_contract.py`. The helper reads that tuple using Python's AST
and literal parser, without importing the contract to decide its trusted file
closure. It compares actual worker files with their Git blobs, including ignored
or `assume-unchanged` files that a normal `git status` can omit. The backend pin
comes from the selected worker's own current implementation-hash algorithm.

`--allow-dirty` is for development inventories. Its output cannot pass the
installation qualification. A changed source file, guidance document or security
repair must receive a new measured worker pin; an unchanged catalog or backend
is allowed to retain its measured digest.

## 2. Check retained observations

Capture the actual worker's installation manifest and the complete configured
server's `tools/list` response. A paginated response with a remaining
`nextCursor` is refused. If discovery uses multiple pages, retain those original
pages and supply their complete combined `{"tools": [...]}` value.

The private full-operator consumer must separately review and pin a contract
covering that **whole server catalog**, using the runtime's
`deploy/mcp_tool_contract.py` representation. The eleven-tool family contract at
`deploy/contracts/hepta-hia-agent-native-v1.json` does not satisfy that check.
The helper compares every full-catalog tool definition and independently checks
the HIA definitions, both schemas and operation annotations against the selected
runtime's source catalog. A change to any non-HIA tool also invalidates the
whole-server pin.

```sh
python3 -B tools/hia_candidate_preflight.py verify \
  --runtime-checkout /opt/hepta-runtime \
  --candidate /var/lib/hepta-preflight/candidate/candidate.json \
  --candidate-sha256 "$HIA_CANDIDATE_SHA256" \
  --config /var/lib/hepta-preflight/candidate/runtime-config.json \
  --worker-manifest /var/lib/hepta-preflight/observed-worker.json \
  --native-tools /var/lib/hepta-preflight/observed-tools-list.json \
  --full-contract /var/lib/hepta-preflight/reviewed-full-contract.json \
  --full-contract-sha256 "$HIA_FULL_CONTRACT_SHA256" \
  --output-directory /var/lib/hepta-preflight/capture-check
```

`verify` records `origin: operator_supplied_captures` and
`entrypoint_observed: false`. Passing this command validates the binding of
those supplied observations; it does not prove a current server is reachable.

## 3. Probe the actual configured stdio entry point

`probe` starts the explicitly supplied, SHA-pinned runtime binary with fixed
arguments `mcp --runtime-config <candidate config>`. It reuses the HIA
qualification client and calls only discovery, `hia_describe` and `hia_read`.
The runtime's existing process owner selects and launches the configured worker.
The probe checks the immutable manifest's content digest and all three actual
installation identities. It never emits a candidate, runs candidate machine
code, adopts a generation or creates another worker owner.

```sh
python3 -B tools/hia_candidate_preflight.py probe \
  --runtime-checkout /opt/hepta-runtime \
  --candidate /var/lib/hepta-preflight/candidate/candidate.json \
  --candidate-sha256 "$HIA_CANDIDATE_SHA256" \
  --config /var/lib/hepta-preflight/candidate/runtime-config.json \
  --runtime-binary /opt/hepta-runtime/bin/hepta-runtime \
  --runtime-binary-sha256 "$HIA_RUNTIME_BINARY_SHA256" \
  --full-contract /var/lib/hepta-preflight/reviewed-full-contract.json \
  --full-contract-sha256 "$HIA_FULL_CONTRACT_SHA256" \
  --output-directory /var/lib/hepta-preflight/entrypoint-check
```

A successful probe retains the actual catalog, worker manifest, protocol
transcript, binary digest and source pair. It records
`entrypoint_observed: true` and `production_deployed: false`. The binary digest
identifies the selected executable; build provenance, the Python interpreter,
OS, linker and firmware are not attested by these source pins. Keep the actual
build and deployment receipts separately.

An accepted or unknown HIA response cannot become a successful probe. The error
retains the original tool, unchanged arguments and operation identity, with
`retry_action: observe_original`. The normal runtime recovery interface remains
the way to observe that operation. Pin mismatches do not authorize executing a
replacement request.

## Qualification commands

```sh
python3 -B -m unittest tests.test_hia_candidate_preflight -v
python3 -B tests/hia_candidate_preflight_integration.py \
  --runtime-checkout /absolute/path/to/the/pinned/runtime -v
```

The first suite is self-contained. The second loads the real pinned runtime
contract/snapshot helpers and uses committed worker fixtures and local MCP
protocol fixtures for adversarial tests. Those fixtures establish source-pair,
pin, schema, recovery and publication behavior. They are not production endpoint
observations or evidence of backend self-hosting, optimization benefit or gateway
deployment.
