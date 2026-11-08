# Hepta / HIA

HIA provides a typed Core language, explicit resource checks, direct native code
generation and scoped verification for Agent-authored programs.

## Start from the selected release

Use the single release entry, **`python3 -B tools/hia_release.py`**, and its
[version contract](releases/hia-current.json). The contract selects exact Hepta
and runtime commits, file inventories, worker identity, backend and tool catalog.
The [release guide](docs/HIA_RELEASE_ENTRY.md) records the selected release and
its acceptance evidence.

On Linux x86-64, install Git, Python 3.11 or newer and GNU binutils, then use new
absolute paths for the three directories below:

```sh
git clone --depth=1 --filter=blob:none --sparse https://github.com/TrillionniumFoundation/Hepta.git /absolute/new/hia-entry
git -C /absolute/new/hia-entry sparse-checkout set tools docs releases
cd /absolute/new/hia-entry
python3 -m venv /absolute/new/hia-python
/absolute/new/hia-python/bin/python -m pip install 'jsonschema==4.25.1' 'z3-solver==4.15.4.0'
HIA_RELEASE_PYTHON=/absolute/new/hia-python/bin/python
"$HIA_RELEASE_PYTHON" -B tools/hia_release.py describe
"$HIA_RELEASE_PYTHON" -B tools/hia_release.py materialize --directory /absolute/new/hia-release
"$HIA_RELEASE_PYTHON" -B tools/hia_release.py check \
  --hepta-root /absolute/new/hia-release/hepta \
  --runtime-checkout /absolute/new/hia-release/runtime
"$HIA_RELEASE_PYTHON" -B /absolute/new/hia-release/hepta/tools/qualify_hia_direct_native.py \
  --output /absolute/new/hia-native.json
```

`describe` prints the contract and its SHA256. `materialize` obtains the exact
public commits; `check` rechecks the selected source and installation identities.
The native qualification command executes the examples and records its result.
The metadata checkout and the materialized implementation have separate roles.
Live runtime deployment and endpoint readback have their own acceptance receipts.

## Read proof results by scope

A `proved` result applies to the subject, property, profile, assumptions and
checker identity in that result. Read its unproved obligations before using it.
Verification does not grant execution authority. The current
[proof/Core/machine status](docs/HIA_PROOF_CORE_MACHINE_STATUS.json) records the
qualified profiles and remaining limits; the
[six-gap record](docs/HIA_SIXGAP_20261108.json) binds their evidence to source and
runtime identities.

The materialized source contains `docs/HIA_SELFHOST_CORE_SUPPORT.json`, the
selfhost support matrix, and `docs/HIA_AGENT_PROOF_RESULTS.md`, the proof-result
contract. Follow `docs/HIA_REPOSITORY_AGENT_TRIAL.md` there for the repository-task
recorder and its public task package. A passing source qualification alone does
not establish a completed fresh-Agent task or stable NDU economic benefit.
