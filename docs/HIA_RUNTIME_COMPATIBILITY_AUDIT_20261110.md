# HeptaRuntime / Core-only HIA compatibility audit

Observed 2026-11-10, 13:47 UTC. This is a read-only installation/source audit,
not a runtime rollout, a live request replay or a native-only delivery approval.

## Actual deployment, not the repository default branch

The Mac controller's configured HIA worker is the X230 installation at Hepta
`2598f4309791d3a023cd5df585ad26810b20c744`. Its installed manifest was read with
`--installation-manifest`, which exits before creating service state. All three
returned identities match the controller's configured pins. That package has
209 Python modules and 81 `.hepta` files, including the old AST, lexer, parser,
checker, pipeline and source adapter. It is **not** the Core-only candidate.

The Runtime base is `09464736e815940ee4c5bf91d36f6c84a3faee2c` plus separately
manifested timeout patches. At capture, the running process mapped the r3
binary while `current` named r4. Both release manifests bind identical HIA
provider, contract, catalog and HIA test source hashes. A current symlink is
not proof of which binary a running process executes; no restart was performed.
This audit makes no channel-recovery claim.

## Upgrade matrix

| Component | Finding | Required action |
| --- | --- | --- |
| Eleven-tool MCP catalog | Actual Runtime, deployed worker and Core-only candidate catalog bytes are identical: SHA-256 `61325aadc2fa6740c84037227c9410f5e299267d908cfbbd0be6b05eedfbfbf8` | No tool/schema rewrite or catalog-hash change is needed solely for the Core-only transition. Preserve full-operator catalog pins too. |
| Hosted worker request/report | Still `hia-agent-worker-request-v1` / `hia-agent-worker-report-v1`, with public contract `hepta.hia.agent-native.v1`; fixed `python -B -E -s -m hepta.hia_agent_worker` and expected worker/backend/catalog arguments | Existing provider can address a separately qualified Core-only hosted installation. This is source compatibility, not an executed production migration. |
| Installed worker and discovery resources | Live package contains the removed language; candidate has package-owned discovery and native-app source resources | Install the qualified Core-only wheel in a separate immutable root, recompute actual installed pins, then qualify through the real SSH/MCP owner before any cutover. Do not copy old pins or mutate the live root. |
| Worker/backend identities | Source and backend closure changed; a Git commit or matching catalog cannot establish these identities | Update worker/backend pins from the new installation manifest. Keep the existing exact-match refusal. |
| Example worker configuration | Its sample catalog pin is the obsolete `8b880c…`; the actual registered catalog is `61325a…` | Update the example pin; keep worker/backend placeholders until an actual new installed manifest is available. The live config already has the correct catalog pin. |
| Runtime installation documentation | Old inventory description only names three discovery documents and advertises an obsolete CLI distinction | Document all current `DISCOVERY_FILES`, both packaged HIA app sources, package resource lookup, and sole `hia` CLI. Do not retain the deleted high-level entry as a compatibility fallback. |
| Native identity / SSA-CFG helper selection | The current `HiaWorkerProfile` has no typed native-helper manifest fields; its fixed child environment supplies `LC_ALL` and `HIA_TRANSPORT_ARGUMENTS_SHA256`, not `HEPTA_HIA_AGENT_IDENTITY_MANIFEST` / `HEPTA_HIA_AGENT_SLICE_MANIFEST` | Replacing the wheel does not demonstrate native-helper activation. To enable those helpers through Runtime, upgrade the administrator-owned profile/manifest/path-policy and exact execution-identity binding. Do not rely on ambient environment or expose executable selection as model arguments. No eleven-tool MCP schema change is implied. |
| Native Agent execution | The native stdio application's capabilities/verify/compile protocol is not the eleven-tool worker request/report protocol; full native editing/persistence is unfinished | A future native-worker mode needs an explicit executable/ABI/source-image binding and complete worker/report support. Do not substitute its path for `python_executable` or bypass the durable process owner. |
| Existing durable operator state | Exact request keys and source/profile pins bind original operations | Preserve stores, request identities and uncertain jobs. Qualify readable old state and changed-installation conflicts before promotion; do not erase/replay state to make an upgrade pass. |

## Preserved boundaries

No Mac/X230 service, launch configuration, worker pin, store, request, tunnel or
release lock was changed. No new high-level compatibility package is proposed.
The Python namespace `hepta` and `hepta.hia.*` wire names identify HIA interfaces;
renaming them is not necessary to remove the old language.

Raw file captures, exact release-manifest identities and the read-only collector
are retained separately in the task evidence, not packaged as product modules.
The upstream default branch is not the deployed patched Runtime and was not used
as a substitute for the deployed HIA contract.

## Original-operation continuity at cutover

`hia_provider` prepares requests from its single current configured worker
profile; terminal reports must match that exact worker/backend/profile. Its
existing changed-installation tests keep the same mutation key rather than
allocating another execution. Merely changing the configured pins does not
qualify typed observation of original jobs bound to the old installation.
A migration must account for every original operation, with a validated
observation/drain or explicit versioned read-only observation support. Never
solve an identity conflict by inventing new request keys, clearing the durable
store or accepting an old report under new code identity.

## Separate installed smoke

On the qualified Core-only wheel, an actual fixed-argv v1 discovery request
completed under freshly computed worker/backend pins. Reusing the live old pins
returned failure before creating the new private state root. These were local
isolated observations, not a live Runtime/SSH/MCP migration or old-store replay.
