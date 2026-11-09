# Hepta / HIA

HIA provides a typed Core language, explicit resource checks, direct native code
generation and scoped verification for Agent-authored programs.

## Inspect the entry catalog

Run `python3 -B tools/hia_entry_catalog.py` before writing a program. This
standard-library adapter verifies the original public lock and helper bytes,
then reports both exact source/runtime selections, syntax, target, proof
profile and the minimal example. It never installs or activates a worker.

Use `--development-root /absolute/source` to report a checkout's actual commit,
tree, dirty status and support digest without inferring release qualification.
Use `--online-manifest /absolute/manifest.json` to compare a retained manifest's
three installation digests; this offline comparison establishes no freshness.
Discover online profiles with `hia_describe` and `hia_read` before using them.
The [entry and scope handoff](docs/HIA_AGENT_ENTRY_SCOPE_20261109.md) records the
fresh online launch failure separately from historical installation success.

CLI `hia build` defaults to LLVM and CLI `hia emit` emits LLVM text. Select
`--backend native` for a direct CLI build; MCP `hia_emit` uses `hia-direct`.
The public-installation workflow checks this adapter and actually builds and
calls the selected minimal scalar image for each locked source.

The catalog distinguishes text assembly `hia-asm.v1` (primitive schemas v6/v7/v8),
the bounded selfhost input schema v8, and the minimum example's Core JSON
schema `hepta.hia.program.v1`. A selfhost profile such as v9 or v16 names a
compiler support contract; it is not a language schema number.

## Pin a reviewed metadata entry

The installation example below clones the default metadata branch. If your
given entry is a commit or pull-request URL, first clone it as shown, then
select that entry's full 40-character commit before running its tools:

```sh
HIA_ENTRY_COMMIT=FULL_40_CHARACTER_COMMIT_FROM_THE_ENTRY_URL
git -C /absolute/new/hia-entry fetch --depth=1 origin "$HIA_ENTRY_COMMIT"
git -C /absolute/new/hia-entry checkout --detach "$HIA_ENTRY_COMMIT"
git -C /absolute/new/hia-entry rev-parse HEAD
```

Replace the placeholder with the exact reviewed metadata commit. This identifies
the entry tools and instructions; the release lock separately identifies the
materialized Hepta/runtime source. A candidate PR's tools may not yet exist on
the default branch.

## Start from the selected release

Use the default release entry, **`python3 -B tools/hia_release.py`**, and its
[version contract](releases/hia-current.json). The contract selects exact Hepta
and runtime commits, file inventories, worker identity, backend and tool catalog.
The [release guide](docs/HIA_RELEASE_ENTRY.md) records the selected release and
its acceptance evidence.

The selected public source is `2598f4309791d3a023cd5df585ad26810b20c744`,
with the bounded `selfhost-core-linux-x86_64-v9` profile. The
[current release reconciliation](review-evidence/hia-online-release-2598-20261108-e5ee/REPORT.md)
records its original source-CI lock and the matching captured online identity.
The named v16 source release below has a separate immutable lock and qualification scope.

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

## Install the named v16 source release

The explicit entry **`python3 -B tools/hia_release_v16_6ecd802.py`** uses the
[v16 source lock](releases/hia-v16-6ecd802.json) for Hepta
`6ecd8023615a6e0b2dc269379fb059c656b38b6f`, tree
`4c51962e030e9ea39c6498224c99eb40fbdd2f35`, and the bounded
`selfhost-core-linux-x86_64-v16` profile. The runtime remains
`4cd85c99c5f5a480832c48fbde8561bb365f67a9`.

The lock is the unchanged 47,762-byte original from this source's
[exact-source CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565807355).
Its SHA256 is `b3c3725e183d98bec2819155f2d4cd525c3f45305d04ec8fa686e13f454e50e0`.
The default command and `hia-current.json` continue to select v9.

From the metadata checkout above, on Linux x86-64 with the same Git, Python and
GNU binutils prerequisites, use a new temporary destination:

```bash
HIA_V16_WORK="$(mktemp -d)"
python3 -m venv "$HIA_V16_WORK/python"
HIA_V16_PYTHON="$HIA_V16_WORK/python/bin/python"
"$HIA_V16_PYTHON" -m pip install 'jsonschema==4.25.1' 'z3-solver==4.15.4.0'
HIA_V16_LOCK="$PWD/releases/hia-v16-6ecd802.json"
HIA_V16_LOCK_SHA256=b3c3725e183d98bec2819155f2d4cd525c3f45305d04ec8fa686e13f454e50e0
"$HIA_V16_PYTHON" -B tools/hia_release_v16_6ecd802.py \
  --lock "$HIA_V16_LOCK" --lock-sha256 "$HIA_V16_LOCK_SHA256" describe
"$HIA_V16_PYTHON" -B tools/hia_release_v16_6ecd802.py \
  --lock "$HIA_V16_LOCK" --lock-sha256 "$HIA_V16_LOCK_SHA256" \
  materialize --directory "$HIA_V16_WORK/release"
"$HIA_V16_PYTHON" -B tools/hia_release_v16_6ecd802.py \
  --lock "$HIA_V16_LOCK" --lock-sha256 "$HIA_V16_LOCK_SHA256" check \
  --hepta-root "$HIA_V16_WORK/release/hepta" \
  --runtime-checkout "$HIA_V16_WORK/release/runtime"
"$HIA_V16_PYTHON" -B "$HIA_V16_WORK/release/hepta/tools/qualify_hia_direct_native.py" \
  --output "$HIA_V16_WORK/native.json"
```

Pass the displayed lock and digest to the versioned entry. The release retains
its original source-only qualification flags. Publishing and installing this
named source does not change the online service's selected installation or
establish full Core selfhosting, general machine correctness, external Agent
adoption or stable NDU economic value. The
[release guide](docs/HIA_RELEASE_ENTRY.md#named-v16-source-release--2026-11-09)
records the source and public-entry validation boundaries.

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

## Prove and execute the same minimum image

After materializing either selected source, run this adapter from the metadata
checkout with its published Python dependencies:

```sh
HIA_PYTHON=/absolute/new/hia-python/bin/python
"$HIA_PYTHON" -B tools/qualify_hia_entry_proof.py \
  --selection current \
  --hepta-root /absolute/new/hia-release/hepta \
  --runtime-checkout /absolute/new/hia-release/runtime \
  --output /absolute/new/hia-minimum-proof
```

For the named release, use `--selection v16` with that release's materialized
roots. The output must be a new directory outside both source checkouts.
The adapter checks the original locks and source identities before and after,
verifies/interprets the locked example, emits one direct object, links one
explicit both-hash ELF, runs the selected supplied-byte checker, and calls
that same proven image for five arithmetic cases. This handles the documented
GNU-ld hash-section difference and avoids the newer-only `--profile-version`
option. Every command, stderr, failed attempt, proof query and artifact identity
is retained. The result is a bounded model proof and finite native observation;
it grants no adoption authority and is no general compiler or hardware proof.
Both public-installation CI rows execute this additional gate.

## Agent entry and scope handoff

Use the [Agent entry and proof-scope handoff](docs/HIA_AGENT_ENTRY_SCOPE_20261109.md)
to distinguish current, named, development and online installations, CLI/MCP
backends, the minimum program and the remaining P0-P5 acceptance gates.
