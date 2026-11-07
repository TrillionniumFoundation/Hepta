# One HIA release entry and version contract

`python3 -B tools/hia_release.py` is the candidate's default release entry.
`releases/hia-current.json` selects immutable commits from **both** repositories;
branch names, PR numbers and a compatible-looking tool list are not substitutes.
The lock is repository release metadata, not a signed attestation or a grant to
publish a service. Its hash is printed by every command.

The source commit deliberately precedes the metadata commit that contains its
lock. This avoids a self-referential Git commit hash. Entry and preflight bytes
must be identical to those in the pinned source; changing either requires a new
source release. The metadata checkout is not the worker installation.

## Bound identities

| Contract component | Measured identity and acceptance |
| --- | --- |
| Hepta and runtime | Full commit and tree; clean checkout; actual file bytes checked against Git blobs |
| Worker | Complete Python and discoverable language-contract inventory, measured independently of the worker's returned manifest |
| Backend and catalog | Actual worker manifest; byte equality of worker/runtime HIA catalogs; exactly eleven HIA tools |
| Target and ABI | `x86_64-unknown-linux-gnu`, ELF64/AMD64/LP64, System V AMD64 scalar and explicit borrowed-byte profiles; constants read from the pinned source |
| Selfhost-Core | Versioned support matrix, compiler assembly, loader, seed implementation, limits and ABI; all included in the source inventory |
| Complete server catalog | A separately reviewed whole-server contract is required for a live probe; eleven HIA definitions alone cannot replace it |
| Native binary | Explicit SHA256 on each live probe; this identifies executable bytes and does not manufacture build provenance |

Neither the source lock nor the release script upgrades an empirical result.
Production deployment, default-branch adoption, actual current-Agent discovery,
first-use success and Native NDU value each remain explicit independent gates.

Use the documented **source-file** entry, `python3 -B tools/hia_release.py`.
The entry executes its preflight helper from source bytes, bypassing cached
bytecode. Local worker admission rejects `__pycache__`, `.pyc`, `.pyo` and native
extension shadows inside `hepta` before running its manifest command. `-B`
alone only stops cache writes and does not prevent reading an existing cache.
The fixed runtime still uses its existing Python worker launch: this release
does not claim a source-only runtime loader, immunity to concurrent privileged
source changes, or a pinned Python/system dependency environment. Retain an
independent cache inventory of the actual remote worker when qualifying it.

## New environment

Obtain this release entry and its default lock from the same reviewed metadata
commit. `describe` is a read-only inspection of the contract:

```sh
python3 -B tools/hia_release.py describe
python3 -B tools/hia_release.py materialize --directory /absolute/new/hia-release
python3 -B tools/hia_release.py check \
  --hepta-root /absolute/new/hia-release/hepta \
  --runtime-checkout /absolute/new/hia-release/runtime
```

`materialize` creates two new clean source checkouts and checks their actual
installed capabilities. Its explicit Hepta sparse-directory list includes the
Hepta implementation, examples, tests, tooling and the selected qualification
fixtures. Unrelated historical campaigns and artifact/report archives remain
outside this release's qualified source closure. The full tree identity
remains pinned. This also supports local partial Git caches without disguising
missing executable files. It never replaces an existing directory. For an offline cold
replay, `--hepta-repository /path/to/existing/Hepta` and
`--runtime-repository /path/to/existing/runtime` select local Git transports;
the commit, tree, file and capability requirements remain identical. Failed
materializations remain available for diagnosis and are not silently reused.
Dependencies, runtime binaries, credentials and service configuration must be
provisioned by the environment's existing setup. The script does not install
them or infer permission from a contract.

## Prepare the reviewed worker configuration

The supplied configuration already has to select an authorized Linux worker,
interpreter, read/capture roots and a writable private state root. Preparation
reuses `hia_candidate_preflight` and writes a new private configuration with the
measured source pins. It preserves all other policy. The configured worker may
be remote; the eventual endpoint probe checks that worker's actual installation.

```sh
python3 -B tools/hia_release.py prepare \
  --hepta-root /absolute/new/hia-release/hepta \
  --runtime-checkout /absolute/new/hia-release/runtime \
  --config /absolute/reviewed/runtime.json \
  --worker-python /absolute/python3 \
  --output-directory /absolute/new/prepared
```

Keep this output outside both checkouts. It contains `candidate.json`, a private
`runtime-config.json` and `release-binding.json`. Preparation never changes a
running service. Retain the printed candidate/configuration digests for the next
step; do not replace them with digests from a different preparation.

## Observe the configured runtime entry

After building/qualifying the selected runtime, supply the executable identity
and the reviewed **whole-server** MCP contract:

```sh
python3 -B tools/hia_release.py probe \
  --hepta-root /absolute/new/hia-release/hepta \
  --runtime-checkout /absolute/new/hia-release/runtime \
  --config /absolute/new/prepared/runtime-config.json \
  --candidate /absolute/new/prepared/candidate.json \
  --candidate-sha256 "$HIA_CANDIDATE_SHA256" \
  --runtime-binary /absolute/qualified/hepta-runtime \
  --runtime-binary-sha256 "$HIA_RUNTIME_BINARY_SHA256" \
  --full-contract /absolute/reviewed/whole-server-contract.json \
  --full-contract-sha256 "$HIA_WHOLE_CONTRACT_SHA256" \
  --output-directory /absolute/new/entrypoint-probe
```

The selected runtime runs its existing `mcp --runtime-config` entry. This probe
discovers tools and reads the immutable installation manifest; it retains the
original protocol transcript, actual catalog, worker manifest and binary digest.
An accepted/unknown operation remains unresolved and returns the original tool
arguments and recovery identity. It does not trigger a replacement execution.

This stdio observation does not establish the formal HTTP gateway, the
current conversation's tools or a complete adoption/cancellation lifecycle.
Formal endpoint acceptance must capture those observations at the actual
deployment. Use an explicit persistent campaign identity and isolated slot for
the lifecycle client; keep the same identity when reconnecting.

## Cold Selfhost-Core replay

Use the materialized source's versioned support matrix and qualification entry:

```sh
cd /absolute/new/hia-release/hepta
python3 -B tools/qualify_hia_selfhost.py --output /absolute/new/selfhost.json
python3 -B tools/replay_hia_selfhost_cold.py --output /absolute/new/selfhost-cold.json
```

The cold replay exports only the pinned source into a fresh directory, uses a
fresh child home/tmp and CPython `-I -S -B`, and imports no existing seed,
successor image or bytecode cache. It shares the host's declared kernel, linker,
libc and Python executable; it is not a fresh VM. The native successor compiler,
input source, output images and loader receipts
must demonstrate B1=B2=B3 and a changed source reaching M2=M3 with M2 different
from B2. B0's binary and linker identities are measured by that actual cold build;
the release lock only pins the seed implementation before a binary exists.
The matrix separately records unsupported owned resources, recursive calls,
external relocations and general object linking. The explicit `selfhost_elf`
profile emits bounded ELF64 ET_REL objects in HIA and has independent system
linker and execution checks. Success for that subset cannot close broader gates.

## Release engineering

Commit and review all source changes first. With both exact source checkouts
clean, freeze the next lock into a new file, review it, and only then update the
metadata pointer:

```sh
python3 -B tools/hia_release.py freeze \
  --hepta-root /absolute/clean/Hepta --hepta-revision "$HIA_COMMIT" \
  --runtime-checkout /absolute/clean/runtime --runtime-revision "$HIA_RUNTIME_COMMIT" \
  --release-id hia-candidate-YYYYMMDD-rN \
  --output /absolute/new/hia-current.json
```

All output publication is create-only. Live config/link/plist changes use the
existing reviewed runtime deployment and conditional rollback procedures after
their exact-byte gates pass. The release entry adds no second worker scheduler,
gateway, compiler checker or process owner.
