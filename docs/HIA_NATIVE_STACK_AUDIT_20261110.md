# HIA native-stack audit — 2026-11-10

## Finding and observation scope

The project has a real bounded HIA self-reproducing compiler and several
substantial native applications. **The entire language, production toolchain
and separate runtime have not been rewritten in HIA. Legacy retirement is not
eligible at this checkpoint.** The eight-component ledger remains three partial
and five open boundaries. File counts are inventories, not completion rates.

This audit read GitHub repository metadata, exact commit trees, release locks,
open PRs, workflow jobs and the original failed job logs. The first GitHub
snapshot ended at **2026-11-10 08:36:32 UTC (03:36:32 America/New_York)**;
release/runtime follow-up reads ended at approximately 08:44 UTC. Queued/running
states below are observations at that time, not predictions of their outcome.
The local baseline is the immutable Git tree of
`e00ae72c110625083445ed4bb110415b6a97d7b7`. Subsequent implementation changes
require their own source identity and execution records.

The public entry, selected language source, selected runtime source, development
compiler and actual loaded service are separate authorities. A green check for
one does not qualify the others. This audit did not activate a service or infer
its currently mapped binary from a GitHub commit or PR description.

## Public entry and source identities

The observed public `main` is
[`e2a4b4b09598e5b03a8d883b62c3cc800c1d5a66`](https://github.com/TrillionniumFoundation/Hepta/commit/e2a4b4b09598e5b03a8d883b62c3cc800c1d5a66),
the merge of PR #828. It is a metadata/installation entry, not a checkout of the
current complete development implementation. Its
[release documentation](https://github.com/TrillionniumFoundation/Hepta/blob/e2a4b4b09598e5b03a8d883b62c3cc800c1d5a66/docs/HIA_RELEASE_ENTRY.md)
explicitly states that the metadata checkout is not the worker installation.

| Selection | Immutable language source | Selfhost profile | Public entry |
| --- | --- | --- | --- |
| Default v9 | `2598f4309791d3a023cd5df585ad26810b20c744`, tree `4c073a29839eff1e75fbcc6dd28db4108c04160c` | `selfhost-core-linux-x86_64-v9` | `python3 -B tools/hia_release.py`, `releases/hia-current.json` |
| Named v16 | `6ecd8023615a6e0b2dc269379fb059c656b38b6f`, tree `4c51962e030e9ea39c6498224c99eb40fbdd2f35` | `selfhost-core-linux-x86_64-v16` | `python3 -B tools/hia_release_v16_6ecd802.py`, `releases/hia-v16-6ecd802.json` |
| Audited development frontend | `f142ab4ef99cde30128bfced0f3d6299fc373b43`, tree `e97eab65ab6dffba156a0340b691a8a993dbb728` | `selfhost-core-linux-x86_64-v32` | Draft PR #851; no public release-lock switch |
| Local performance continuation | `e00ae72c110625083445ed4bb110415b6a97d7b7`, tree `2ce428a0c121dbe5896991933368704d7d724725` | Declared v32; source-closure check fails before native execution | Development baseline, not a qualified release |

Both public release selections pin runtime
`4cd85c99c5f5a480832c48fbde8561bb365f67a9`, tree
`6b78d53b53d51a6c070bb37e8e9f6a15ad26d0e8`. The default lock is 37,527 bytes,
SHA-256 `9000d6eaa089f6bed92ea07a6561d91381a6f913263f0b1016d4f99e8789c1d3`.
The named v16 lock is 47,762 bytes, SHA-256
`b3c3725e183d98bec2819155f2d4cd525c3f45305d04ec8fa686e13f454e50e0`.
Both retain `source_lock_only=true`, `production_deployed=false`,
`runtime_source_only_loading_enforced=false` and
`whole_language_selfhost=false` in their original qualification scopes.
These flags are not changed by a newer source branch.

Sources: [default lock](https://github.com/TrillionniumFoundation/Hepta/blob/e2a4b4b09598e5b03a8d883b62c3cc800c1d5a66/releases/hia-current.json),
[named v16 lock](https://github.com/TrillionniumFoundation/Hepta/blob/e2a4b4b09598e5b03a8d883b62c3cc800c1d5a66/releases/hia-v16-6ecd802.json).

The public homepage README is deliberately empty. The retained
[concurrent-main reconciliation](https://github.com/TrillionniumFoundation/Hepta/blob/e2a4b4b09598e5b03a8d883b62c3cc800c1d5a66/review-evidence/hia-public-entry-concurrent-main-20261109-e5ee/README.md)
records commit `4fd6b62b442e4198f43bf3595fa9e35b0f438102` clearing it and the
subsequent preservation of that choice. Installation instructions live in
`INSTALL.md`; the public CI checks that document. An empty metadata homepage
must not be diagnosed as missing implementation or silently restored.

## Development is split across two stacks

All four latest frontend PRs were open drafts at observation.

| PR | Exact head | Base and implemented scope |
| --- | --- | --- |
| [#848](https://github.com/TrillionniumFoundation/Hepta/pull/848) | `b65a42b8cea1cb7c44df5e58a79b9a2cc98db45c` | `work/hia-integrated-stack-20261110`; complete existing type-prefix grammar with native frames |
| [#850](https://github.com/TrillionniumFoundation/Hepta/pull/850) | `1b5228cc88115d900bf3c2dfd0cab2f6cff404f3` | `work/hia-source-types-20261110`; expression grammar and malformed owner-receipt handling |
| [#851](https://github.com/TrillionniumFoundation/Hepta/pull/851) | `f142ab4ef99cde30128bfced0f3d6299fc373b43` | `work/hia-source-types-20261110`; names/clauses/expressions, exact numeric lexing and a bound frontend bundle |
| [#849](https://github.com/TrillionniumFoundation/Hepta/pull/849) | `a146e0aac16909241614d7093afbe5c04255e612` | `work/hia-type-parser-20261110`; whole-source grammar task machine on the other type-parser chain |

GitHub compare establishes that #851 is one commit ahead of #848. #850 and
#851 diverge at `b65a42b8`: #850 has three unique commits, #851 one. #849 and
#851 diverge at `7e7dc36ccb7798bdffcc30ccc1d03105ddc9d5d4`; the compare reports
#851 ahead 26 and behind 9. These are distinct implementations, not successive
names for one qualified tree.

The whole-source parser implementation is already present in
[`16572b158d0ba12a0f15117e55f000628bbef3af`](https://github.com/TrillionniumFoundation/Hepta/commit/16572b158d0ba12a0f15117e55f000628bbef3af),
followed by metadata commit `a146e0aa`. Its source is 195,658 bytes with 52
functions and 663 blocks. It covers program/module/import, declarations,
statements, expressions, match arms, namespace validation and completed-tree
depth checks. It is not yet part of the audited #851/e00 tree.

Integration must preserve the newer custody and identity controls. In #849,
`hia_source_parser_native.py` imports the other type parser's `KINDS/MAGIC`;
its builder compares source/compiler paths before and after execution but does
not apply #851's actual invocation-receipt binding. Importing it unchanged can
reintroduce a temporary compiler substitution gap. Its selected route also
explicitly falls back to the Python parser outside the 4,096-token/1-MiB packet
or initial-state profile. This is documented bounded compatibility, not native
retirement. The latest bundle captures all seven manifests/images and maps the
captured bytes, confines image paths and rejects conflicting/mixed identities.

Sources: [branch comparison](https://github.com/TrillionniumFoundation/Hepta/compare/a146e0aac16909241614d7093afbe5c04255e612...f142ab4ef99cde30128bfced0f3d6299fc373b43),
[#849 grammar scope](https://github.com/TrillionniumFoundation/Hepta/blob/a146e0aac16909241614d7093afbe5c04255e612/docs/HIA_SOURCE_PARSER_NATIVE.md),
[#851 bundle scope](https://github.com/TrillionniumFoundation/Hepta/blob/f142ab4ef99cde30128bfced0f3d6299fc373b43/docs/HIA_SOURCE_FRONTEND_NATIVE.md).

## Reviewed continuation before frozen-source qualification

A later exact GitHub read found #851 advanced to
[`637d34d9e8164b752f5b6b6fe2bad4802274abc6`](https://github.com/TrillionniumFoundation/Hepta/commit/637d34d9e8164b752f5b6b6fe2bad4802274abc6),
tree `4b65ca5f59c7eff777062f3782778206bef2809b`, still an open draft. Its loader
bytes equal the local e00 continuation. Its name-reference source and tests were
integrated byte-for-byte, preserving all three intermediate full renderer/Core/
text-round-trip checks and their new negative controls. The earlier snapshot
above is retained as historical observation. This continuation does not overwrite
that branch or interpret its queued workflows as passing qualification.

The current v33 continuation adds the default [HIA effect/resource semantic
pass](HIA_EFFECTS_NATIVE.md) and an explicitly selected [HIA ELF
linker](HIA_ELF_LINKER_NATIVE.md). The former removes the old Python closure and
conflict algorithm; the latter generates shared images from the current bounded
selfhost ELF profiles and is usable through existing export/owned qualification
routes. Their remaining bootstrap, transport, libc and platform dependencies are
explicit. Neither closes an entire ledger component.

Compiler, installed-worker, release, cold and active direct/candidate/macro
source inventories now bind nested HIA package bytes. The v20 shared identity has
440 reviewed paths and preserves the exact 412-path v19 projection plus all
older projections. Its 3,563 extra identity bytes are transferred from raw logs
inside the unchanged one-MiB envelope. This is a reviewed identity closure, not
an assertion that every repository test's transitive imports are covered.
Older specialist qualification tools with separate Python-only inventories must
be reviewed before they can establish native-HIA source stability; their old
records are not rewritten or promoted here.

Actual build receipts now bind compiler/source/image bytes, native packer input
and the complete returned output. JSON CLI admission also binds the child
frontend's captured cold-report hash. Tests preserve transient path substitution
and changed-source failures. The Core verifier's ordinary ASCII byte accounting
has a no-copy fast path; every public verification, existing resource bound,
negative witness and cold deadline remains required. Fresh frozen-source
receipts are stored separately from this support/source declaration.

## Implementation authorities, component by component

This table uses the audited pre-continuation source. New partial passes or a
bounded linker must record their actual scope and evidence before this table is
revised; their existence cannot close a whole component automatically.

| Component | HIA implementation present | Remaining authority / closure boundary |
| --- | --- | --- |
| Assembly and source frontend — partial | Bounded assembly grammar, all Core opcode names within their profiles, JSON decoding/canonicalization, source lexer/numeric/type/name/clause/expression applications | Python AST/value/diagnostic construction, code custody and selection, declarations/statements in this stack, complete parser integration and default routing |
| Core verifier and resources — partial | Fixed-profile scalar/resource checks, exact CFG joins, owned results and parameter-bound returned loans | General composite elaboration, full type and signature shapes, all resource combinations and semantic checking |
| Native backend and linker — partial | Linux x86-64 flat images, bounded ELF ET_REL, scalar exports, closed allocator relocations, syscall-only filter | General module/symbol/link graph, shared-image linking, public resource ABI, other backends/targets |
| Execution and standard library — open | SHA-256/streaming, compiled byte operations, native flat-ABI observer and filter entries | General interpreter, task and I/O runtime, independent supervisor, complete production library |
| Modules, packages and build — open | Selected native kernels used by host-driven builds | Module/package resolution, package locks, whole build graph, authoring and installation orchestration |
| Agent tools and persistence — open | Native candidate programs invoked through existing tools | Python worker/service/store and Rust MCP/controller ownership, durability, recovery, cancellation and protocol implementations |
| Optimizer and proof tools — open | Selected compiled kernels and finite proof scopes | Planning, optimization, translation validation, proof construction and solver dependencies; no universal compiler refinement theorem |
| CLI and release — open | Bounded Linux assembly/JSON stdin-to-machine-code filters | Complete production CLI, distribution, installer, release materialization, source/binary provenance and clean-machine full-toolchain bootstrap |

Authorities are enumerated in
[`tools/audit_hia_selfhost_closure.py`](https://github.com/TrillionniumFoundation/Hepta/blob/f142ab4ef99cde30128bfced0f3d6299fc373b43/tools/audit_hia_selfhost_closure.py).
The audited v32 [support contract](https://github.com/TrillionniumFoundation/Hepta/blob/f142ab4ef99cde30128bfced0f3d6299fc373b43/docs/HIA_SELFHOST_CORE_SUPPORT.json) explicitly retains
`whole_HIA_language_self_hosted=false`,
`compiler_correctness_formally_proved=false` and
`native_execution_is_security_sandboxed=false`.

### Exact local baseline inventory

The immutable e00 Git tree contains 10,150 tracked paths. Reading its Git blobs
directly, rather than counting concurrently edited worktree files, gives:

| Source role | Files | Lines / bytes |
| --- | ---: | --- |
| `hepta/**/*.py` | 225 | 77,958 lines / 4,219,029 bytes |
| `tools/**/*.py` | 437 | 136,392 lines / 7,781,353 bytes |
| `rust/**/*.rs` | 39 | 435,478 bytes |
| `tools/**/*.rs` | 7 | 96,627 bytes |
| `tools/**/*.c` | 8 | 28,964 bytes |
| `tools/**/*.S` | 1 | 3,763 bytes |
| `formal/**/*.lean` | 9 | 80,656 bytes |
| `examples/**/*.hiaasm` | 16 | 1,592,926 bytes |

Host qualification tools, independent oracles and historical evidence are not
all live production providers; their counts must not be used as a migration
percentage. The declared final distribution requires actual HIA replacements
for production authorities. Evidence/test fixtures should not be deleted merely
because their implementation language differs.

The #849 documentation's "300 repository sources" is not an established corpus
count: its code uses `[:300]` as an upper bound. The e00 baseline actually has
81 `.hepta` example files; the bundle audit already records that correction.
Tests must report the actual enumerated corpus and its source identity.

## CI and original acceptance evidence

| Subject | Observed result | Interpretation |
| --- | --- | --- |
| Public `main e2a4b4b0` | [42585805111](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42585805111): both `public-release` and `public-release-v16` success | The two existing metadata installation selections passed their gates; does not qualify v32 |
| #845 `d7d1a346` | [42766783539](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42766783539): P2 source/cold/native/language success | Scoped exact-source P2 result |
| Same #845 | [42766783252](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42766783252): unified failure | 595 tests / one failed cold replay; P2 success does not erase it |
| #846 `c635bb5d` | [42767422174](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42767422174): source/native/language success, cold failure | Overall run failed |
| #848 `b65a42b8` | [42775627170](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42775627170): source success, cold queued at observation | Incomplete run |
| Same #848 | [42775627187](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42775627187): unified failure | 595 tests / one failed cold replay |
| #849 `a146e0aa` | Current 16 source workflows queued at first snapshot | No current-head remote success observed |
| #850 `1b5228cc` | Current 16 source workflows queued at first snapshot | No current-head remote success observed |
| #851 `f142ab4e` | Current 16 source workflows queued at first snapshot | No current-head remote success observed |

The original #848 [job 129693353221](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42775627187/job/129693353221)
was read directly. It reports 595 tests in 810.540 seconds and one failure in
`SelfhostColdReplayTests.test_source_only_clean_rebuild_has_original_and_modified_fixed_points`.
The nested run reached `QUALIFICATION_TIMEOUT`, returned -9 after
180.158591644 seconds and completed 28 of 38 phases with zero phase exceptions.
Cleanup completed with kernel `ECHILD` observed. Successful cleanup and partial
fixed points do not satisfy the missing complete qualification.

The original #845 [job 129665019720](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42766783252/job/129665019720)
has the same failed test: 595 tests in 711.447 seconds, nested timeout at
180.100613000 seconds, confirmed cleanup. #846's dedicated cold
[job 129668296600](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42767422174/job/129668296600)
reports `FAIL`, six of eleven outer checks passing. Its later successful native
and language jobs do not change that cold result.

#851's published audit also retains its local frozen-tree cold failure at
180.204743498 seconds after 28 of 38 phases. B1=B2=B3 and M2=M3 were observed in
that incomplete attempt. They do not qualify its unfinished cold replay.

### This task's e00 baseline failed before native execution

The clean e00 baseline attempt stopped in `validate_contract()` with:

```text
ValueError: Selfhost-Core support contract differs from the current source closure
```

The original `baseline-e00-cold.log` is 826 bytes, SHA-256
`009e067c9d099f0426493208b89ad5fbd5970dad8262f5524c9fc424c65d9c96`.
This failure is distinct from the earlier 180-second timeouts: it occurred
before a native run or completed cold report. The local loader performance
change cannot be called qualified until its exact source closure is correctly
bound and the unchanged gates are freshly executed. Regenerating a support
contract alone records new source identities; it does not establish a pass.

The task then froze the same implementation with the two stale source hashes
rebound in an independent baseline at
`c0380515ef4794491227e8b2cbb3e47f714f31a2`. Its fresh, unchanged cold gate
**also failed**: `loader-contract-cold.json` reports 180.222518785 seconds,
six of eleven outer checks passing, `QUALIFICATION_TIMEOUT` and return code
-9. The retained phase index has 28 of 38 phases complete, zero exceptions;
owned-process cleanup completed with `ECHILD` observed and no remaining direct
children. The report is 43,071 bytes, SHA-256
`b0cb234ad087fb0d26c2310fb6fc302c398833b08d64bc9865e88d360631e890`.
The original report and its `loader-contract-cold.cold/` evidence directory
remain retained. This resolves the initial identity mismatch sufficiently to
execute the gate, but confirms that the loader performance change alone does
not meet the unchanged 180-second acceptance deadline.

## Separate runtime: default branch, fixed public lock and newer candidate

The runtime repository's actual default branch is `hepta-runtime-base`, observed
at `ba574f2a6a1b74e85191c58d7bec011720736bb9`. Its latest commit clears the public
README. It is not the fixed `4cd85c99` runtime selected by the language releases.

For the selected runtime `4cd85c99c5f5a480832c48fbde8561bb365f67a9`, GitHub
returned three successful push runs: 42473375581, 42566636892 and
[42612748394](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/42612748394).
In the last run, exact-head job `129145029830` succeeded through Rust formatting,
both feature-mode checks/Clippy/tests, release build, MCP cancellation/recovery
and other declared regression gates. Prospective-merge job `129145031474` was
skipped on that push; it is not counted as an executed pass.

[Runtime PR #114](https://github.com/TrillionniumFoundation/hepta-runtime/pull/114)
is a newer draft based on the same 4cd source, at
`09464736e815940ee4c5bf91d36f6c84a3faee2c`. Its
[PR run 42634535094](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/42634535094)
and push run 42634523183 have now completed successfully; both exact-head and
prospective-merge jobs in the PR actually executed successfully. The PR's older
body still said in progress. It reports a deployed concurrency change, but this
audit did not reobserve that loaded service and does not substitute that report
for the public HIA lock. Rust/Tokio/serde/rmcp/SSH and Python ingress remain
foreign implementations, not HIA rewrites.

[Runtime PR #112](https://github.com/TrillionniumFoundation/hepta-runtime/pull/112),
head `e9aaae6c9687def8af942270dffb7281700a0654`, is a separate draft for optional
private loaded-configuration provenance. Its source-candidate success does not
authenticate an already-running old process or create a new HIA release lock.
The adjacent experimental Mac transition protocol likewise is not a production
activation receipt. These separate candidates must retain independent subjects.

## Platform and distribution gates

| Surface | Existing implementation / contract | Native-rewrite boundary |
| --- | --- | --- |
| Linux x86-64 LP64 | The v32 HIA selfhost compiler, native flat/ELF applications and syscall-only filter | Current cold/source/full-repository acceptance still required; resource limits do not make trusted native code a hostile-code sandbox |
| Linux AArch64 | Python/LLVM lowering plus finite C runtime; distinct QEMU and direct-native modes | Not an HIA selfhosting target; QEMU cannot establish direct native or physical-board qualification |
| macOS AArch64 | Actual-host C/Rust ABI and upstream C++ workflows; separate runtime controller/deployment mechanisms | Linux x86-64 image loader explicitly refuses this host; switching a global checker default requires a valid platform policy |
| Windows x86-64 | Separate Microsoft C and Clang actual-host ABI workflows | These are foreign toolchain interoperability gates, not Windows HIA selfhosting |
| Physical devices / GPU / MCU | Separate hardware-dependent research and qualification scopes | Hosted host/ABI tests do not prove device startup, MMIO, DMA, IRQ or GPU behavior |

These distinctions are explicit in [actual host ABI qualification](NATIVE_HOSTS.md),
[native AArch64 scope](HIA_AARCH64_NATIVE_HOST.md),
`hepta/hia_json_preflight_native.py` and the exact-source workflows. Earlier
successful platform jobs cannot qualify changed default routes in this task.

The audited baseline `pyproject.toml` ships only package `hepta`, exposes
`hepta = hepta.cli:main`, requires Python >=3.11 and uses setuptools. Native
source programs under `examples/hia_bootstrap` and builders under `tools` are
not made into an installed native distribution merely by importing a new
Python bridge. A default native pass must be qualified from an actual built
wheel/sdist or the declared source-only installation route, including image
and source availability, identities, permissions and failure behavior. Testing
inside the repository does not establish installed-package behavior.

## Required retirement decision

The user's requested final state is the complete HIA-native stack. Reaching it
requires each live implementation authority to have an actual HIA replacement,
followed by ordinary default execution without a legacy fallback. Before the
old production stack can be removed, retain evidence for:

1. Full declared source/Core conformance, including negative inputs, diagnostics,
   exact type/resource effects, failure ordering and required platform behavior.
2. Native source parsing, semantic analysis, module/build/link composition,
   production runtime and durable Agent/service/store paths; passing a leaf or
   finite graph algorithm is insufficient to close its entire parent component.
3. Source-only and genuinely modified-source full-toolchain bootstrap, with
   exact seed/tool/loader identities and complete owned-process cleanup.
4. Fresh full regressions, ABI/platform gates, allocation/I/O/cancellation and
   recovery failures on one frozen integrated candidate; no transfer of old or
   adjacent-branch results to changed bytes.
5. Clean installation and real project builds from the final distribution with
   the retired production compiler/runtime absent. Audit final package contents
   and actual executed providers, rather than only environment selector names.

Old Git history and nonshipped review evidence are not live providers. Removing
them does not replace a compiler or runtime and can destroy the ability to
check regression claims. Production retirement must follow replacement and
qualification, with the exact removed paths and their native successors recorded.

## Current continuation evidence

The initial e00 preflight failure and the source-bound c038 cold timeout above
are the new execution conclusions added by this audit revision. The current
task is implementing additional native
semantic and linker components separately. Their final exact source, build,
positive/negative execution, packaging and platform results must be recorded
after they actually complete. No new production switch, general linker closure,
whole-stack pass or legacy deletion is claimed here.
