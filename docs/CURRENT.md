# HIA: current implementation and acceptance

This is the current-state index for `TrillionniumFoundation/Hepta`. The language
is HIA; the canonical source suffix is lowercase `.hepta`.

**The suffix migration is complete. Whole-product native replacement is not.**
`whole_native_delivery_qualified=false`, `old_stack_can_be_removed=false`, and
`production_activated=false`. The ordinary `hia` executable still enters
`hepta.cli:hia_main`. Selected HIA machine-code owners do not replace the
remaining hosted service, storage, proof, process and runtime owners.

## Source naming and inventory

Main was independently read at
[`f33d8da316de8fdf27b504371f1a5310997ff548`](https://github.com/TrillionniumFoundation/Hepta/commit/f33d8da316de8fdf27b504371f1a5310997ff548),
tree `378bc0dc613befc7006f1514bd2229357ae0d07c`, on 2026-11-14 UTC.
The canonical suffix entered main at
[`51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8`](https://github.com/TrillionniumFoundation/Hepta/commit/51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8).

| Scope | Audited main `f33d8da` | Earlier `0daf86d` | Published parent `ad352ee` | This implementation |
| --- | ---: | ---: | ---: | ---: |
| HIA source files ending in `.hepta` | 178 | 185 | 188 | 190 |
| Physical legacy `.hia`, `.HIA`, `.hiaasm` or `.hia.json` paths, including case variants | 0 | 0 | 0 | 0 |
| Production Python modules directly under `hepta/` | 186 | 191 | 195 | 198 |

These counts describe files, not percentages of behavior. The additional
Python modules are explicit adapters for new native owners; their existence is
part of the remaining hosted boundary. The complete
[indexed-source inventory](HIA_NATIVE_REWRITE_INVENTORY.json) records every
retained file, Python module, static import edge, native selector and source
identity. Its explicit parent HEAD/index/worktree context is not the later
commit's identity. Dynamic and external callers still require separate review.

The [suffix contract](HIA_SOURCE_SUFFIX.md) and
[migration map](HIA_SOURCE_SUFFIX_MIGRATION.json) preserve rename provenance.
Assembly keeps `hia-asm.v1`; structured Core keeps its schema; paired structured
projections use `.core.hepta`. The `hia` command, `hepta.hia.*` schemas, Git
objects and historical receipt bytes retain their original identities.

## Current implementation changes

This revision continues
[PR #896](https://github.com/TrillionniumFoundation/Hepta/pull/896), whose published
`0daf86d0e5b8a8c13c15185d2b2bf553fbb81310` source has tree
`46f5f3b0611a64393ed06fcc9b91221a1d54cabb`. It retains the packer-admission,
source-custody, recursive-chain, Store-initialization and linked-ELF repairs,
and the prior native owners. Published continuation
[`ad352eeb77d804c14d7407713e23d37e7f037cf1`](https://github.com/TrillionniumFoundation/Hepta/commit/ad352eeb77d804c14d7407713e23d37e7f037cf1),
tree `9c56113194795c738d3e7804eb1a89f8a1803cbd`, added full cost, patch impact
and CLI discovery JSON. This revision adds static resources and Store lifecycle;
the five new owners across this continuation are listed first:

| Area | HIA-owned behavior | Retained host boundary |
| --- | --- | --- |
| [Static resources](HIA_STATIC_BUDGET_NATIVE.md) | Stable graph order, exact allocator/tick arithmetic, synchronous call depth, v7/v8 resource profile and ordered numerical policy decisions | Sole Core verification, primitive/policy shape validation, fact projection, independent heap analysis and final report hashing |
| [Store lifecycle](HIA_STORE_LIFECYCLE_NATIVE.md) | Complete constructor and close control, effect ordering, short-circuit/loop branches, original cleanup and exception propagation | Path/OS/SQLite effects, execution-budget provider, Python object protocols and exception delivery |
| [Full cost](HIA_FULL_COST_NATIVE.md) | Eleven one-time cost fields and execution/controller/failure sums, RSS/p99 peaks, ordered baseline/dp/fixed selection, exact signed floor-ppm savings and six ordered refusals | Immutable JSON observation, field validation, identities and final report construction |
| [Patch impact](HIA_PATCH_IMPACT_NATIVE.md) | Direct function/interface changes, old and new call graphs, duplicate elimination and transitive caller closure, including cycles and self calls | Fresh Core/patch verification, receipt checks, canonical fact projection and final report digest |
| [CLI discovery JSON](HIA_CLI_DISCOVERY_JSON.md) | Complete capabilities/catalog JSON, pretty/canonical encoding, schema selection, metadata ordering and catalog SHA-256 | Original CLI entry, explicit selector loading, I/O and other action effects |
| [Mapping admission](../review-evidence/hia-native-cleanup-20261111/native-mapping-integration.json) | Raw mapping grammar, interval ordering, permissions, file extent, unique-match admission and first refusal | Kernel snapshot, Python function objects, descriptor/seal readback and dynamic loader |
| [Publication measurement](../review-evidence/hia-native-cleanup-20261111/publication-measurement-integration.json) | Paired medians/deviations, ordered refusal and exact cost projections, including large intermediate integers | Clock observations, locks/cancellation/CAS, proof/build/load effects and resource custody |
| [Scalar profile](../review-evidence/hia-native-cleanup-20261111/scalar-profile-integration.json) | v1-v7 profile restrictions, explicit/implicit exports, whole-CFG acyclicity and ordered ABI | Fresh Core verification, unchanged per-export Z3 proofs and native compilation |
| [Generation retention](hia-generation-retention-native.md) | Registered-generation exact reference count, one-close lease cells, retired state and unique retirement-task claim | Selection/epoch/CAS, locks, preparation failures before registration, invocation and foreign cleanup |
| [Bounded byte memory](HIA_BOUNDED_MEMORY_NATIVE.md) | Original fill/move admission and refusals, actual in-place fill and overlapping move | Exact Python object facts, buffer export lifetime, allocator and GIL custody |
| [SHA stream](HIA_SHA256_STREAM_NATIVE.md) | Original full-width state transitions with fixed eight-byte word accesses expanded | Original bounded adapter and foreign object lifetime |
| [Execution budget](HIA_EXECUTION_BUDGET_NATIVE.md) and [journal](HIA_AGENT_JOURNAL_NATIVE.md) | Original budget transitions and complete per-request catalog hashing, with fixed word accesses expanded | Actual clock observations, SQLite transactions, durable journal and request dispatch |

Static resources preserve all 1,024 functions, 4,096 blocks per function and
262,144 structural nodes. Event magnitudes use exact variable-width arithmetic;
the maximum-function test produces a 1,026-bit bound. The original seven caller
modules execute 77 methods with all five reference owners forbidden. Only
callee facts named by the current function are transported, avoiding repeated
whole-program copying without narrowing the graph or changing a deadline.

Store lifecycle uses the current `ad352ee` constructor and close bodies as
independent frozen originals. Selection is bound for the instance lifetime.
Cleanup protection starts immediately after connection assignment; failures in
chmod, identity checks, PRAGMA, schema or budget initialization retain the
original cleanup. Unknown external outcomes retain actual resources and fence
replay; confirmed native terminal states alone release custody. Custody grows
before effects without an arbitrary active-Store limit. Fork reinitializes only
the custody lock and retains unknown references. Its four complete original
caller modules execute 50 methods with both reference bodies forbidden.
SQLite and the remaining Store methods are still hosted.

Full cost preserves the original 8..128 trials and exact ratios whose signed
ppm magnitude exceeds 64 bits. Its complete 38-caller gate poisons the original
arithmetic. Patch impact preserves 1..1,024 functions, old/new graph union,
receipt ordering and all 36 callers. The selected adapters refuse invalid
manifests; removing their selector preserves the original default.

The CLI discovery HIA source is byte-identical to exact R20
`26fd6c4c1a71dc970ae11b00c8a9ff74c5c8508d`. Its original four test groups,
61 native request frames and six independent VM labels remain intact. Separate
controls exercise both ordinary and selected native CLI routes. Exact import
provenance and independent parent-response fixtures are retained. This is a
component import, not adoption of R20's entire tree or failed Store gate.

Generation counts retain their growable exact magnitude; generation numbers
and epochs are not narrowed. A known zero-write capacity refusal permits
allocation recovery. An uncertain native return fences the owner and strongly
retains resource custody. The 99-caller qualifier selects generation,
scalar, measurement and mapping policies together and keeps all original
methods and deadlines.

Bounded memory uses an 80-byte request with no new input-length ceiling.
Integer sign and width are observed before transport; out-of-range negative
integers do not create a magnitude-sized temporary. HIA retains the original
refusal order. Native calls hold the GIL, and buffer exports are released in
`finally`, including when an exception traceback is retained. The original
36-caller gate poisons reference bodies and keeps the complete six modules.
The complete VM, allocator and object transport remain hosted.

The shared loader explicitly uses an 8 KiB file buffer and reads images in
8 KiB chunks through the original 1 MiB-plus-one refusal boundary. This fixes
Python 3.14's 128 KiB default-buffer allocation and the old full-limit allocation
on a small image cache miss. Dependencies initialize with the public module,
so a first operation does not lazily import its transport. The original 64 KiB
scratch gate now also exercises fresh public calls, maximum-sized valid
manifests and actual LRU eviction. Source/image hashes, pinned scope, complete
read behavior and the three-entry cache are retained.

The SHA and budget/journal changes preserve full-u64 values, state layout,
byte order, partial-write behavior, original hashes, limits and errors. Pinned
independent originals and full-buffer differential controls remain test inputs;
they are not alternate production versions. No cached catalog identity or
shortened validation path substitutes for the original per-request full hash.
Performance measurements are observations, not new acceptance thresholds.

The [helper bundle](HIA_NATIVE_HELPER_WORKER.md) contains **31** declared
single-image selectors. A source control checks the registry against the
support declaration and verifies every packaged source. Selected paths retain
installed source/image custody and explicit refusal instead of fallback.
Full cost and patch impact have a real pinned two-owner bundle and clean-wheel
tests with their original owners poisoned; source or manifest drift refuses.
CLI discovery is not registered as a worker helper. Its loader refuses an
unregistered active worker scope before reading or mapping an image; its
installed CLI controls do not assert worker adoption.

### Explicit empty-selector compatibility

The audited JSON preflight/decoder, SHA/SHA-stream, snapshot, capability,
JSON-wire, identity, worker-report, artifact-publication, service-journal and
cached-journal preflight entries now reject a present but empty native selector
before reference dispatch or foreign effects. **Remove the environment key**
to request the original default. Nonempty outside-profile behavior is unchanged.

The [empty-selector controls](../tests/test_hia_empty_native_selectors.py)
exercise both refusal and preserved absent-selector behavior. Existing tests
that meant to disable selection now remove the key rather than setting it to
an empty string. This is an explicit configuration-compatibility change; it is
not a claim that every repository selector has the same convention. The
[machine-encoding contract](HIA_MACHINE_ENCODING_NATIVE.md) retains its
documented empty-disable behavior.

## Source-bound qualification

Original observations keep their own source identity. A pass on an earlier
commit, a documentation successor or another branch does not qualify this tree.
Groups overlap and are never added into a unique-test total.

| Exact original source and run | Observed terminal result |
| --- | --- |
| Main `f33d8da`, [43375258419](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43375258419) | SUCCESS. Source: 530 tests in 464.822 seconds. Every declared Native step passed, including cold 11/11, language 1,242 checks plus ten report assertions, 94 journal callers and 89 JSON-wire callers. Both jobs checked out exact `f33d8da`. |
| Main `f33d8da`, [CodeQL 43375258558](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43375258558) | C/C++, Actions, Python and Rust jobs succeeded. |
| Parent `0daf86d`, [push 43541067109](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43541067109) and [PR 43541235838](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43541235838) | Both SUCCESS. All 81 Native API steps completed without a skipped step, including cold 11/11 and language 1,242/1,242. |
| Parent `0daf86d`, [full retained 43541249953](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43541249953) | SUCCESS. All 4,843 planned/started/finished IDs match; zero failures, errors, skips, expected failures or unexpected successes. The original regression took 4,012.647 seconds within 5,400 seconds; source bytes were unchanged before and after. |
| Published parent `ad352ee`, [push 43563651594](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43563651594) and [PR 43563684162](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43563684162) | Partial observation at 2026-11-14 06:22 UTC: both Source jobs succeeded with 645/645 tests; both Native jobs passed cold and the added cost/patch gates. Native jobs and separate [full retained 43563838838](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43563838838) had not reached a terminal result. PR merge checkout `5af2ef6b31b3ccd998fdedb8d23d4869bbe4bd66` has the exact published source tree. These observations do not qualify this successor. |
| `a7710b5`, [push 43475067137](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43475067137) | FAILURE. Source: 585 tests passed. Native failed the accepted 64 MiB `store-put` at its original 60-second subprocess limit; subsequent product steps were skipped. |
| `a7710b5`, [PR 43475077671](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43475077671) | SUCCESS. Source: 585 tests; every declared Native step completed. Actual checkout was merge `05d0cb2130982c4ffd408521650e20298e4c4ac0`, independently verified to have the same `b5618be` tree, with parents main `f33d8da` and `a7710b5`. |
| `fbc34a716e31e72dd492fa926025b04808df339a`, [push 43537843469](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43537843469) and [PR 43538070022](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43538070022) | Both failed. Each Source run executed 619 methods with one failure: the bounded-memory installation fixture lacked ten explicit resource-role declarations. Each Native run passed cold and stages 8-16, including 41 scalar and 99 combined generation callers, then executed all 17 bounded-memory tests with two failures at 148,869 bytes against the original 65,536-byte ceiling. Later native steps were skipped. The PR checkout was `5e443ab300c98cc7702d0992b5423d40d9b54f60`, with the same `590189851a4b37965ed9c6b0abbb43f8d8c3115d` tree. This revision fixes the real loader allocation and explicitly copies all resource roles; those earlier runs remain failures. |
| Product `be36b7cfbe40522ca1b6356e90170aa89aec2bad`, [full retained 43473228901](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43473228901) | FAILURE. All 4,747/4,747 original IDs executed in 5,367.218 seconds, within 5,400 seconds: one failure, one error, zero skips. The 64 MiB operation exceeded 60 seconds; the nested reference-loop test reached its existing three-second context deadline before evaluation. |

The successful parent full run used harness
`91b946f926a030343230d950198062c5abffa05a`; its original v4 invocation took
7,201.767 seconds in total. Scalar, bounded-memory and combined-generation
supplemental callers also passed using the same cold compiler. Artifact
`14096873690` is 345,632,903 ZIP bytes with SHA-256
`178f4a7af37b8a46ccdb4329801f2b8ad78d1c1073fe54f9b917dfdaa39a3127`.
All 19,042 manifest members were checked for hash, size and mode, with no
missing member; 19,043 files including the manifest were examined. This
qualifies the parent, not the new source in this revision. The local harness
commit `439dd75ad3e9bab61fec6300c64fc83673b4f38e` has the same
`f0011fc625c546f30fa141d8643d02202ccad2fa` tree but was not published; it is
not the identity of the executed GitHub run.

The earlier failed `be36b7c` full run used product tree `e32d473fc5ce396b513a6b85e04340fb25d81d12`
and separate harness `59c6e5912c86f6253b68b7a1579dbeef2fe8c111`.
All six real NDU preparations and fixed verification dependencies passed.
Its execution-budget and ordinary journal-caller stages also recorded the
same context failure. These repeated observations are not distinct defects.
Artifact `14074395756` is 267,944,020 ZIP bytes with SHA-256
`f49d4223f5e7cf39e8ef3d7db8d87a74d56e2f14ea481af588137054baaab872`;
the archive and extracted original reports were verified before this audit.
A separate successful same-tree run does not erase either original failure.

The current [.github/workflows/hia-core.yml](../.github/workflows/hia-core.yml)
regenerates the actual sources, checks the support/coverage fixed point, runs
source controls, qualifies the cold compiler, and runs selected native and
complete original-caller gates. The retained
[full qualification entry](../review-evidence/hia-native-rewrite-20261111/README.md)
keeps original source/harness custody, all 35 stages and complete discovery.
New component callers are additional gates, not replacements for that suite.
The workflow now includes full cost, patch impact, static resources, Store
lifecycle and both CLI discovery qualifiers. Final isolated development
observations recorded 13/13 static-resource tests plus 77/77 complete original
callers, and 17/17 Store owner tests (36/36 including shared controls) plus
50/50 complete original callers. These overlapping groups are not a unique
test total and do not qualify the integrated source. Local execution uses an explicitly declared development compiler;
the prior local cold timeout remains a timeout. Matching-source cold and full
remote regression for this new revision are pending until actual terminal
reports exist.

Cold retains **180 seconds plus three seconds cleanup**. Each original
accepted 64 MiB store operation retains **60 seconds**; the context test retains
**three seconds**; full retained discovery retains **5,400 seconds** and exact
planned/started/finished method identities. Failures, errors, skips, expected
failures or unexpected successes prevent qualification. The newly discovered
method count is never capped to the older 4,747 count.

This local managed environment denies `PTRACE_TRACEME`. Its source/component
results cannot stand in for the original ptrace-dependent full suite. The
GitHub runner must perform that unchanged gate on the exact submitted source.
Execution receipts in the corresponding PR and CI artifacts bind the actual
product commit, harness commit, compiler bytes and test identities; this
source declaration is not itself a successful execution receipt.

## Remaining product acceptance

| Area | Existing owner that still requires complete replacement and real caller qualification |
| --- | --- |
| Ordinary CLI and build | `cli.hia_main`, remaining semantic action effects, `verify_program`, default emitter/build routing and complete diagnostics |
| Reference runtime | Complete VM, allocator, object transport, general backend behavior and default machine/plan implementation |
| Eleven-tool worker | `hia_agent_worker`, `HIAAgentService.call`, catalog/dispatch and backend admission |
| Durable state | `AgentStore` SQLite/WAL, atomic multi-table transactions, replay and unknown outcomes |
| Proof authority | Fresh Core verification and original Z3/Lean obligations; component admission does not replace these proofs |
| Native process ownership | Runner setup, environment/limits, snapshots, termination and complete report checking |
| Resident resources | Selection/CAS, actual invocation, libraries, sealed descriptors and confirmed cleanup of outstanding generations |
| Final cutover | Clean install/default startup, old context/request migration, worker restart/handoff, running-image readback and confirmed retirement |

The [selfhost object build](HIA_PROGRAM_SELFHOST_BUILD.md) consumes pinned
native frontend/compiler bytes without a Python-emitter fallback. It remains
a declared bounded Linux x86-64 profile. Default build and `hia_emit` retain
the Python emitter; `hia_evaluate` retains the Python reference VM. The
[native stdio entry](HIA_AGENT_STDIO_NATIVE.md) implements six commands, while
the ordinary CLI has fifteen actions and the service eleven tools.

Source generation, matching-source cold qualification, installed native caller
tests, full retained regression and actual worker adoption are separate gates.
Production Python modules still have live consumers and participate in install
identity. Deleting them now would remove working behavior and break durable
identities. They are retained until replacement and cutover are established.

## Repository cleanup and parallel work

The active tree keeps current source, contracts, consumed fixtures and recovery
ledgers. Numbered source units can be parts of one multi-image program; their
names alone do not make them obsolete versions. Independent original fixtures,
three consumed NDU archives, acquisition locks, original failure records and
the five-deliverables manifest remain active evidence.

The parent continuation retired **424 historical members**: **423 paths deleted**
and one historical README replaced by the current qualification entry.
The original removed/replaced content totals **19,714,542 bytes**. This is the
scope of that continuation, not a cumulative total for all prior cleanups.
This continuation additionally removes **eleven superseded narrative documents,
54,855 original bytes** (nine in `ad352ee`, two in this successor), after checking active references, and records their exact Git
blob, mode, size, SHA-256 and published recovery revision in the existing
process-document ledger. Production implementations, tests and consumed
evidence are not removed by this narrative cleanup. The current
[CLI contract](HIA_CLI_NATIVE.md) replaces its obsolete recovery narrative;
current journal guidance links to the exact archived source. The cumulative
process-document ledger now records 30 retired members and 178,258 original
bytes, including earlier batches.
The three process summaries are in the existing
[development ledger](../review-evidence/hia-native-cleanup-20261111/retired-development-versions.json);
the remaining batches have exact mode, size, SHA-256 and Git-blob identities in:

- [Retired process documents](../review-evidence/hia-native-cleanup-20261111/retired-process-documents.json).
- [Retired historical bundles](../review-evidence/hia-native-cleanup-20261111/retired-historical-bundles.json).
- [Retired rewrite observations](../review-evidence/hia-native-cleanup-20261111/retired-rewrite-observations.json).

Every retired member is recoverable from the recorded published Git revision.
The live `run_hia_qualification_v4.py` and adjacent `workflow_process.py` remain
byte-identical. Cleanup does not erase original failures, rewrite Git history,
or assert that the hosted production stack has been retired.

Separate [#888](https://github.com/TrillionniumFoundation/Hepta/pull/888),
[#889](https://github.com/TrillionniumFoundation/Hepta/pull/889) and
[#893](https://github.com/TrillionniumFoundation/Hepta/pull/893) lines retain
their own source identities. They are not merged wholesale into this tree.
The #889 R20 `26fd6c4` [run 43560753071](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43560753071)
failed Native step 15, the original Store lifecycle namespace callers. Later
CLI discovery, stdio, process and service steps were skipped. Earlier component
passes do not qualify those skipped product steps. R20 has 257 `.hepta`
sources and 271 production Python modules, but lacks five native owners
retained here. The inspected #888 tree retains 155 physical legacy source
paths. Neither tree is an acceptable wholesale replacement. The #893 exact
`831110b8659a48bf9636997212ca67d5360530f9` push passed
[43305434289](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43305434289),
while its separate PR run
[43305453525](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43305453525)
failed at cold. Neither result is relabelled as qualification of this revision.

The [previous exact index](https://github.com/TrillionniumFoundation/Hepta/blob/0daf86d0e5b8a8c13c15185d2b2bf553fbb81310/docs/CURRENT.md)
and [main's exact index](https://github.com/TrillionniumFoundation/Hepta/blob/f33d8da316de8fdf27b504371f1a5310997ff548/docs/CURRENT.md)
preserve the earlier version-by-version narrative, source hashes, failures and
archive references. This current index supersedes that narrative while keeping
the actual incomplete product boundaries explicit.
