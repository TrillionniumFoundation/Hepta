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

On Linux x86-64, use Python 3.11 or newer, Git and GNU binutils. The verification
environment uses `jsonschema==4.25.1` and `z3-solver==4.15.4.0`; install them in
a new Python environment before materialization. The historical lock embedded
in a pinned source revision is not the metadata checkout's current release
pointer. Use the selected metadata entry and lock together.

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
remains pinned. Runtime materialization retains its complete tree, including
historical evidence read by its release gates; the runtime checkout has a
600-second bound, while the smaller Hepta source closure retains 120 seconds.
A failed Git operation records the repository role, pinned commit, stage,
failure kind and timeout without printing private transport URLs or credentials.
This also supports local partial Git caches without disguising
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
`--worker-python` selects the local interpreter used to measure the materialized
source. The remote worker interpreter remains the one explicitly selected in
the supplied configuration.

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
The v13 matrix admits direct tail self calls with no additional native stack
frames. Its flat profile covers 40 of the 50 Core operation names. The explicit
`selfhost_elf` profile covers all 50, including owned buffers and dynamic chains,
and emits bounded ELF64 ET_REL objects and closed allocator relocations in HIA.
It has separate system-linker, native-execution, ownership-flow and explicit
allocator-failure checks. The shared chain destructor uses constant native stack.

The [allocation-effect node fix](HIA_SELFHOST_ALLOC_NODE_FIX_20261108.md)
counts the optional `alloc` effect in every native parse pass. Its earlier
compiler snapshot has a retained 1,131-check native qualification, 910 language
checks and fresh 10-check cold replay containing that complete qualification.
Both original boundary failures remain historical evidence. Exact-limit and
one-node-over-limit controls cover the effect both present and absent without
raising any resource bound.

The later [CFG worklist repair](HIA_SELFHOST_CFG_WORKLIST_FIX_20261108.md)
retains that accounting and schedules pending blocks by their source offsets.
It avoids reparsing the whole program for each backward CFG discovery while
preserving the strict SSA, graph-join and resource-lifetime checks. Its frozen
250-file closure includes the external-root report repair. This compiler has
its own 1,183-check native qualification, 910 language checks and fresh 10-check
cold replay that again completes all 1,183 checks with matching ordinary and
modified compiler identities. The original slow and CPU-limit failures, an intermediate valid-Core
rejection and all final repairs remain separately retained; no child CPU,
workspace or cold-replay limit was increased.

The later [cold scheduling repair](HIA_SELFHOST_COLD_PARALLEL_OWNER_FIX_20261108.md)
retains those exact compiler bytes and all 1,183 native checks. After the fresh
B0 and ordinary/modified generation chains complete in dependency order, it
schedules 20 independent groups of reference checks in separate directories, with
at most two fresh Python workers. Each worker binds its inputs and source
manifest; the parent refuses missing, duplicate, unexpected or malformed phase
results and preserves failures from every scheduled worker. The retained
1,699-call logical inventory, non-path request inputs, selected behavior fields
and every B/M generation hash match the earlier successful CI. Host-linked
shared objects retain their actual, separately recorded toolchain identities;
their bytes are not represented as equal across different linker versions.

Its frozen 252-file closure has a complete local native qualification and a
fresh cold replay: the latter completed all 11 outer checks and all 1,183 nested
checks in 88.084 seconds. These are observations for that run, not a runtime
performance promise. The [dedicated Linux process owner](HIA_SELFHOST_COLD_PROCESS_OWNER_20261108.md)
requires the qualification leader to finish within the unchanged 180-second
budget. It then confirms ordinary descendant cleanup with a separate budget of
at most three seconds, including descendants that created a new session. A
timeout or unconfirmed cleanup cannot admit a nested result. The additional
cleanup check is reported separately from the unchanged native check count.
The earlier 180-second CI timeout and its incomplete report remain retained.

The separate [machine-plan header oracle repair](HIA_SELFHOST_MACHINE_PLAN_HEADER_REPAIR_20261108.md)
retains equality for all 17 observed workspace header words, including word
248. This finite observation does not cover the unobserved workspace tail.

Operation-name coverage is not complete general-Core acceptance. The fixed
canonical grammar, finite resource limits, restricted function results and
internal call ABI still exclude valid general Core inputs. Non-tail recursion,
mutual recursion, generic multi-result or returned-resource call/return shapes,
arbitrary FFI, imports and general linking remain outside this profile. Read the
versioned support matrix and its valid-Core refusal cases for the exact boundary.

Successor compilation after B0 runs in native HIA. The qualification harness also
uses Python for independent reference code generation, a host C compiler and
assembler for the separate allocator witness, and the system linker for explicit
ELF tests. These dependencies are recorded separately from the successor chain;
the report does not label the whole qualification process host-codegen-free.

The borrowed-buffer Agent ABI can invoke the original frozen compiler and run
the separately scoped same-Core lifecycle. Its
[external-root report repair](HIA_AGENT_EXTERNAL_ROOT_REPORT_REPAIR_20261108.md)
preserves the actual caller bytes and active local loan when a reborrowed entry
traps or reaches its execution budget. These caller-owned buffers remain outside
Core-owned heap accounting; the raw/native default and normal-return rules are
unchanged. A successful same-Core stopped-state evaluation does not establish
the original compiler delta's required proofs. The real original select extension
has its own strict replay in `docs/HIA_AGENT_ORIGINAL_SELECT_DELTA_20261108.md`:
its required semantic claims remain unproved, evaluation is refused and no
adoption occurs. A successful refusal regression is not positive task acceptance.
The [prepared NDU replayer](HIA_NDU_PREPARED_RANKING.md) now reconstructs all
reported paired costs and summary statistics from the retained cell ledgers;
the original corrupted-analysis acceptance and the repaired refusal are both
retained. Prepared and persistent NDU transport qualification does not establish
economic benefit; stronger ordinary controls and incomplete costs remain part
of the recorded result. These finite qualifications do not close the universal
compiler, ABI, resource, FFI, ISA or loader proof obligations.

The independent supplied-artifact checker also admits the existing producer's
64-bit register-register `CMOVNE` leaf within the unchanged Safe Core profile.
Its [qualification](HIA_SAFE_CORE_CMOVNE_20261108.md) retains exact scalar
subjects, solver queries, real refutations, unsupported forms and native
witnesses. This instruction-model extension does not qualify the complete
three-buffer compiler or replace the original select task's missing proofs.

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
