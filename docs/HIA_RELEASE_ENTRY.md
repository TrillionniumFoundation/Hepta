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
installed capabilities. The default public GitHub transport fetches the exact
locked commit with depth one and blob filtering, then obtains the declared
source files at checkout. It never substitutes a branch tip or another remote
when that fetch fails. Its explicit Hepta sparse-directory list includes the
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
The v6 matrix admits direct tail self calls with no additional native stack
frames. Non-tail recursion, mutual recursion, owned resources, external
relocations and general object linking remain unsupported. The explicit `selfhost_elf`
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

## Qualification supplement: 2026-11-07

The later observations below update the qualification summary for entry commit
`e40daf900556fcc57941e0601d073ec46b340047`. The original release lock, source
pins and earlier receipts remain unchanged. The machine-readable record is
[HIA_FOLLOWTHROUGH_20261107.json](HIA_FOLLOWTHROUGH_20261107.json); it binds each
statement to retained evidence by SHA256 and states the scope of each result.

### Source and runtime results now observed

| Subject | New result | Qualification boundary |
| --- | --- | --- |
| Hepta `3ead0f535c271b07766c5d7c5d15ca69f0f3e8df` | One frozen run: 37 selectors, 513 unique test IDs passed, including all 7 signed-UID controls; no failures, errors or skips | Exact selected source and test scope. This is a new run with complete raw evidence; the earlier lost 506-test logs remain lost. |
| Selfhost-Core v6 | The retained 224-file cold closure passes 10 outer and 189 inner gates. All 224 file sizes, SHA256 values and Git blob IDs match the same paths in `3ead` | The actual new cold replay names source `7316`; its declared Core closure is inherited by byte identity. This does not claim a full `3ead` cold checkout, a fresh VM or whole-language selfhosting. |
| Runtime `c53917f4d147fbdb3ce0e094bc9c32a305411866` | [CI run 42395715600](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/42395715600): exact-head job completed with 26/26 steps successful | The prospective-merge job was skipped. Exact-head CI does not qualify a production switch or restore the currently missing native candidate binary. |

The cold evidence contains and compares the complete B0–B3 and M1–M3 images.
B1=B2=B3; M2=M3; M1 differs from M2, and M3 differs from B3. The declared
source mutation changes one wrapper value from 64 to 80, with all other source
bytes unchanged. The seed, loader and shared host dependencies retain their
explicit trust boundaries.

The complete new 513-test evidence archive is 4,081,243 bytes, with SHA256
`3a0a580942e7413b293b8a663450f5c3badfda2d633f9c023a6693b5c03c32f2`.
It includes original receipts and independent review. Its preservation does
not imply that the pinned Hepta commit is available through public GitHub.

### Actual root Agent and live service

The original root tool lists at **17:23:37 UTC** and **18:17:39 UTC** contain
the same eleven native HIA tool names. The 17:23 record's derived `hia_tools=[]`
field omitted names already present in its full `h_tools` list. This supplement
corrects that specific counting error. These observations do not establish a
catalog refresh at 18:17, a registration or deployment action, or tool absence
in other earlier observations that have not been reviewed.

Actual invocation is separate evidence: the root conversation has now invoked
all eleven tools through the formal connector. The retained ordinary workflow
covers describe/read, artifact and context creation, candidate import,
inspection, verification, emission, evaluation, adoption, stale-generation
rejection and rollback. This does not assert identical tool registration in
every subagent or future CLI session.

The isolated trial evaluated 256 fixed cases. Baseline and candidate each
measured 13,712 artifact bytes, so the outcome is `unchanged`. In
**generation/epoch** order, the observed sequence is `0/0 → 1/1 → 0/2`:
adoption selected generation 1 at epoch 1, a stale request was rejected with
`E_HIA_GENERATION_STALE`, and rollback restored baseline generation 0 at epoch 2
for future calls. Rollback does not reverse past effects.

The current service returns a different installation from the release lock:

| Identity | Observed live service | Unchanged release lock |
| --- | --- | --- |
| Worker SHA256 prefix | `b75a689c159b` | `3bb4047afa8c` |
| Backend SHA256 prefix | `1fd7feedfd68` | `929d12c5e99c` |
| Catalog SHA256 prefix | `8b880cc02efc` | `1cecf09b55eb` |

The machine record contains all three full hashes. Successful calls to the live
service therefore do not establish deployment or formal acceptance of the
locked `3ead`/`c539` candidate.

Strict lifecycle acceptance remains open. Both global and host-filtered first
inventory pages were rejected with `durable inventory total source byte bound
exceeded`; complete current before/after inventories are absent. The earlier
copied-registry snapshot is a separate result and cannot fill this gap. Recovery
of an already-terminal original operation does not prove reconnecting to a
running task. Genuine in-flight reconnect/cancel acceptance remains a separate
gate; the ordinary workflow above does not close it.
The cited independent r2 audit is a hash-bound working snapshot, retained while
the separate cancellation review remains open; this supplement does not seal it.

The retained cost ledger is complete for its own one-page artifact, but marks
full search cost and external model/discovery cost incomplete. Unscoped entries
include historical activity and cannot all be assigned to this trial. Native
child wall time is nested inside evaluation wall time. Unknown model usage and
billing remain unknown. These results do not establish net optimization
benefit, fresh unseen maintenance success or Native NDU incremental value.

### Publication and deployment still open

The `e40` entry and `c539` runtime are published on review branches. The entry's
local-override `describe`, `materialize` and `check` results are retained. The
default `main` branch was observed unchanged, and default public-URL
materialization has not passed.

The latest bounded observation completed at **2026-11-07 18:49:11 UTC**. The
existing GitHub identity reported `gist`, `read:org` and `repo` scopes, with no
`workflow` scope. The exact repository commit request for `3ead` returned
HTTP 422, “No commit found”. This is the observed repository/API result, not a
claim about every private object or repository. The prior workflow-dependent
push failure remains retained; no credential change or permissions workaround
is part of this supplement.

No production deployment, default-branch adoption, source publication or default
URL success is asserted by this documentation update. The release-lock flags
for Agent first use, Native NDU value and production deployment stay unchanged.
Historical failures and unknown operations remain separate from these new
observations.
