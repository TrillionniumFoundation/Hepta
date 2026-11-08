# One HIA release entry and version contract

> Assembly purpose: `release-candidate`. Reviewable metadata candidate for the exact verified source. Public entry CI, adoption of this candidate and live identity readback remain separate observations; earlier adopted releases retain their original status.

`python3 -B tools/hia_release.py` is the candidate's default release entry.
`releases/hia-current.json` selects immutable commits from **both** repositories;
branch names, PR numbers and a compatible-looking tool list are not substitutes.
The lock is repository release metadata, not a signed attestation or a grant to
publish a service. Its hash is printed by every command.

The source commit deliberately precedes the metadata commit that contains its
lock. This avoids a self-referential Git commit hash. Entry and preflight bytes
must be identical to those in the pinned source; changing either requires a new
source release. The metadata checkout is not the worker installation.

## Selected unified source — 2026-11-08

This metadata candidate selects Hepta `c821ec40e3112396c1586ac8949bfa5ded121464`, runtime
`4cd85c99c5f5a480832c48fbde8561bb365f67a9`, and the exact CI-produced release lock
SHA256 `2dadd1d327e4c43d86e61a2f9c40f4fac544ad91b2586a06c4c71482f5615860`. The release identifier is `hia-sixgap-ci-c821ec40e3112396c1586ac8949bfa5ded121464`.

The [source CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42492173843)
and [native scalar integration CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42492173613)
qualify the same selected source SHA. The source job retains the original
`release-lock.json`, successful `freeze` and `check`, native/SMT qualification,
cold selfhost replay and declared input-language coverage. The scalar job retains
the exact native build receipt and actual wire response, and requires all named
integration tests plus the named native regression to finish with zero skips.

This source includes the Safe Core loader allocation-flag binding repair and
an explicit caller policy for ambiguous scalar Pareto ties. The native response
and caller selection remain separate. These are scoped software repairs; no
universal Core-to-machine theorem, complete general-Core bootstrap, new Agent
maintenance task, or stable NDU economic advantage follows from them. Model
billing and complete costs remain unknown, and no new provider campaign ran.

The root README links to this guide and `releases/hia-current.json`. The metadata
baseline is observed main `df70e807be715819570ddef4e9caa9cf4d5ba0f1`, tree `6313534639fecb3041347bb38d04127b35c0835a`.
Public materialization, branch adoption and live endpoint identity for this
new metadata candidate each need their own observations. This assembly has no
live endpoint/worker identity observation for the selected source. Its pending state does
not reverse acceptance of an earlier release already adopted on main. Metadata
and materialized-source README bytes can differ; the frozen source lock measures
the materialized source. The original source-only qualification fields remain
unchanged. Read the [six-gap record](HIA_SIXGAP_20261108.json) for exact evidence
and remaining obligations. Earlier dated snapshots below retain their original
versions and scope.

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

## Current proof contract and machine validation

Every check carries the exact subject, property, validation profile, assumptions,
checker/source/solver identity and unproved obligations. Receipt consumption and
idempotent verification replay recheck those bindings. Legacy unscoped receipts
cannot satisfy a required proof. A check does not grant execution authority.

For the declared Safe Core profile, native lowering validation reads the actual
retained object and shared-image bytes, independently decodes them and retains
its SMT obligations. It does not call the producer to reconstruct the subject.
Unsupported language, resource, linking or output profiles remain explicit.
The complete Core compiler has no universal machine-refinement theorem. Read
`docs/HIA_AGENT_PROOF_RESULTS.md` and `docs/HIA_SAFE_CORE_MACHINE_VALIDATION.md`
in the materialized source for the exact ABI, FFI, loader and resource premises.

The current measured [six-gap record](HIA_SIXGAP_20261108.json) supersedes the
historical operational snapshots below for the new selected release. The
snapshots and their failed/unknown outcomes remain historical evidence.

## New environment

Obtain this release entry and its default lock from the same reviewed metadata
commit. `describe` is a read-only inspection of the contract:

On Linux x86-64, use Python 3.11+, Git and the system linker/binutils. Prepare a
new Python environment for the source checker and the independent validator:

```sh
cd /absolute/new/hia-entry
python3 -m venv /absolute/new/hia-python
/absolute/new/hia-python/bin/python -m pip install 'jsonschema==4.25.1' 'z3-solver==4.15.4.0'
HIA_PYTHON=/absolute/new/hia-python/bin/python
"$HIA_PYTHON" -B tools/hia_release.py describe
"$HIA_PYTHON" -B tools/hia_release.py materialize --directory /absolute/new/hia-release
"$HIA_PYTHON" -B tools/hia_release.py check \
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
remains pinned. Runtime materialization retains its complete tree, including
historical evidence still read by release gates; its checkout has a 600-second
bound, while the smaller Hepta source closure retains 120 seconds. A failed
Git operation reports the repository role, exact pinned commit, stage, failure
kind and timeout without exposing transport URLs or credentials. This also
supports local partial Git caches without disguising
missing executable files. It never replaces an existing directory. For an offline cold
replay, `--hepta-repository /path/to/existing/Hepta` and
`--runtime-repository /path/to/existing/runtime` select local Git transports;
the commit, tree, file and capability requirements remain identical. Failed
materializations remain available for diagnosis and are not silently reused.
Dependencies, runtime binaries, credentials and service configuration must be
provisioned by the environment's existing setup. The script does not install
them or infer permission from a contract.

### Run the actual native examples

After materialization, run the finite native/SMT qualification from the selected
source. Both output locations must be new:

```sh
cd /absolute/new/hia-release/hepta
"$HIA_PYTHON" -B tools/qualify_hia_direct_native.py --output /absolute/new/direct-native.json
"$HIA_PYTHON" -B tools/qualify_hia_safe_core.py --output /absolute/new/safe-core-evidence
```

The latter retains actual object/shared-image bytes, independent validation,
negative mutations, solver queries and native scalar/borrowed-buffer calls.
Use the original metadata checkout and its selected lock for release commands;
the historical lock embedded in an immutable source snapshot is not the current
metadata pointer.

## Prepare the reviewed worker configuration

The supplied configuration already has to select an authorized Linux worker,
interpreter, read/capture roots and a writable private state root. Preparation
reuses `hia_candidate_preflight` and writes a new private configuration with the
measured source pins. It preserves all other policy. The configured worker may
be remote; the eventual endpoint probe checks that worker's actual installation.
The `--worker-python` option below selects the local interpreter used to measure
the materialized source; it preserves the remote worker interpreter already
selected by the supplied configuration.

```sh
cd /absolute/new/hia-entry
"$HIA_PYTHON" -B tools/hia_release.py prepare \
  --hepta-root /absolute/new/hia-release/hepta \
  --runtime-checkout /absolute/new/hia-release/runtime \
  --config /absolute/reviewed/runtime.json \
  --worker-python "$HIA_PYTHON" \
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
cd /absolute/new/hia-entry
"$HIA_PYTHON" -B tools/hia_release.py probe \
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
"$HIA_PYTHON" -B tools/qualify_hia_selfhost.py --output /absolute/new/selfhost.json
"$HIA_PYTHON" -B tools/replay_hia_selfhost_cold.py --output /absolute/new/selfhost-cold.json
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
cd /absolute/new/hia-entry
"$HIA_PYTHON" -B tools/hia_release.py freeze \
  --hepta-root /absolute/clean/Hepta --hepta-revision "$HIA_COMMIT" \
  --runtime-checkout /absolute/clean/runtime --runtime-revision "$HIA_RUNTIME_COMMIT" \
  --release-id hia-candidate-YYYYMMDD-rN \
  --output /absolute/new/hia-current.json
```

All output publication is create-only. Live config/link/plist changes use the
existing reviewed runtime deployment and conditional rollback procedures after
their exact-byte gates pass. The release entry adds no second worker scheduler,
gateway, compiler checker or process owner.

## Historical qualification supplement — 2026-11-07

This section records the 2026-11-07 observation. Its service, binary and invocation
statements refer to that date; current-candidate observations are recorded above.

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
| Runtime `c53917f4d147fbdb3ce0e094bc9c32a305411866` | [CI run 42395715600](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/42395715600): exact-head job completed with 26/26 steps successful | The prospective-merge job was skipped. At the 2026-11-07 observation the native candidate binary was missing; exact-head CI did not qualify a production switch. |

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

At the 2026-11-07 observation, the root conversation had invoked
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

The service observed on 2026-11-07 returned a different installation from that historical release lock:

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


## Historical measured follow-through snapshot — 2026-11-07

The machine-readable [final snapshot](HIA_FOLLOWTHROUGH_20261107_FINAL.json)
records the newer qualification results and their exact limits. It supplements
the earlier dated snapshot above. The release lock remains unchanged, and
default-branch adoption and production deployment remain open.

| Work package | New measured result | Remaining qualification limit |
| --- | --- | --- |
| Public entry/version contract | Published entry metadata binds source 3ead, runtime c539, installation, target, ABI and Selfhost-Core v6; local-override reconstruction passed. | The one default-URL materialize actually failed with exit 2 after a successful describe; check was not run. Source publication and default-branch adoption remain HOLD. The generic checkout error does not prove its unique cause. Use the entry's own 34,740-byte lock; the source checkout's 34,400-byte lock is different. |
| Formal HIA MCP | Root actually discovered and invoked all 11 HIA kinds; 46 normal plus 11 running-lifecycle observations. Adoption 0/0→1/1, stale refusal and rollback 0/2 verified. Original running worker was cancelled with durable terminal output. | The 20:32 global inventory observation again refused the cumulative source-byte bound; strict global no-duplicate acceptance remains HOLD. It precedes the later default-URL trial and publication. Original-operation reobservation does not establish a distinct transport-session handshake. Cancelled business evaluation remains unknown. |
| Fixed Selfhost-Core | v6 fixed-scope replay passed 10 outer / 189 inner gates; B1=B2=B3 and M1≠M2=M3≠B3. All 224 source files match the corresponding 3ead closure. | Shared host kernel/toolchain; no fresh-VM claim. Public source release remains pending. |
| General Core expansion | Borrowed-resource subset, direct acyclic calls, tail self recursion and bounded ELF64 ET_REL observations passed, with differential/refusal/trap controls. | Owned allocation/free/transfer, new or returned loans, general recursion/checker, external relocations and general ELF remain open. |
| Fresh Agent first use | New synthetic maintenance task completed 256-case equivalence, 256+256 actual native results, adoption and rollback within 48 HIA calls. | Complete public interaction/model-cost evidence and original task-file byte copies remain incomplete. Learner stopped at 12 measurement pages; separate custodian reads later recovered the full original artifact without extending its budget. |
| Explicit machine plans | New actual native RIP profile contains 1,885 samples; 3 sampling compiles match B3. Five plans completed 15 full-compilation measurements and 51 consumer native calls, with preservation/refusal checks. | Three fixed-order rounds do not establish general speedup. The r8/r9 v4 plans did not beat their paired v3 medians. Full model/preparation/transfer/monetary cost remains incomplete. |
| NDU incremental value | Prior incomplete four-arm result retained; no benefit conclusion upgraded. | Strongest Ordinary control and a successful matched new four-arm study are still required. |

The fresh task reduced Core operations 10→4 and linked text 410→246 bytes, while
both shared libraries remained 13,712 bytes; its declared artifact-size objective
therefore returned `unchanged`. The observed trial window was 37m48.045s,
the context request-to-last-response window 27m0.265s, and native-child wall
236.294956ms. These are different cost scopes.

For the new plan batch, median complete native f0 self-compilation times were
623.986153ms (canonical), 570.220186ms (v3-two), 510.274372ms (v3-five),
580.462156ms (v4-two) and 513.295275ms (v4-seven). These timed calls exclude
process startup, image loading, buffer preparation, output writing and plan/build
costs. The entire measured batch took 19.779614404s; nested phase/native timings
are not added again. No NDU advantage follows from this machine-plan campaign.

The exact default remote URL observation, source/installation mismatch,
remaining authorization step and evidence hashes are retained in the final
snapshot. Earlier failures and unknown provider effects retain their original
status. The documentation snapshot is not an adoption or deployment receipt.
