# Independent entry usability trial — 2026-11-09

## Observed result

This one Agent started independently at the public INSTALL entry, resolved the default pinned sources, materialized and checked them, verified/interpreted the documented minimum program, generated direct native ELF, and made real native calls. A separate supplied-artifact checker completed its all-input independent-model proof after an explicit linker-flag recovery. The original default CLI shared image did **not** pass that proof. Both actual failures remain retained.

This is one finite usability observation, not a fresh-Agent population study, productivity/adoption claim, deployed-endpoint attestation or general compiler/hardware correctness result. No online mutation, activation, adoption, commit or publication occurred.

## Independence and environment

Entry: `https://github.com/TrillionniumFoundation/Hepta/blob/main/INSTALL.md`, fetched through connected GitHub (`github-install-fetch.json`). Own isolated metadata worktree: `entry`, detached at `e2a4b4b09598e5b03a8d883b62c3cc800c1d5a66`, tree `e800d0f3858a916628269d4b29aad0f5d5c2e111`. Only that worktree and its own exact materialized sources were used. No other Agent's implementation worktree or trial report was inspected.

Authorized existing interpreter: `/workspace/scratch/3977a84d79eb/hia-venv/bin/python`; CPython 3.12.14, Linux x86-64 LP64/glibc 2.41, Git 2.52.0, GNU ld 2.44. **Dependency deviation:** jsonschema is 4.26.0, whereas INSTALL asks for 4.25.1; z3-solver is the requested 4.15.4.0. Shared environment unchanged. This is therefore not an exact dependency-install reproduction.

`commands.jsonl` indexes full argv, cwd, UTC start/end, exit code and original separate `.stdout`/`.stderr` files, recorded by `run.py`. Initial Git/read/worktree exploration preceded the recorder. An early metadata-tree proof-doc read returned `cat: docs/HIA_AGENT_PROOF_RESULTS.md: No such file or directory`; INSTALL explicitly directs these reads to the materialized source, where they succeeded.

## Installation and interface facts

`python3 -B tools/hia_entry_catalog.py` succeeded before program work and checked both unchanged lock/helper sets. Default `tools/hia_release.py describe`, `materialize` and `check` all succeeded; original outputs are retained.

| Item | Default/current |
| --- | --- |
| Release | `hia-sixgap-ci-2598f4309791d3a023cd5df585ad26810b20c744` |
| Hepta commit | `2598f4309791d3a023cd5df585ad26810b20c744` |
| Hepta tree | `4c073a29839eff1e75fbcc6dd28db4108c04160c` |
| Runtime commit | `4cd85c99c5f5a480832c48fbde8561bb365f67a9` |
| Runtime tree | `6b78d53b53d51a6c070bb37e8e9f6a15ad26d0e8` |
| Lock SHA256 | `9000d6eaa089f6bed92ea07a6561d91381a6f913263f0b1016d4f99e8789c1d3` |
| Selfhost profile | `selfhost-core-linux-x86_64-v9`, bounded, whole-language false |
| Worker SHA256 | `7f767953145e722f4cf62cbb4e3617fa2f9b388f3940ad926b5bb9a7309ae642` |
| Backend SHA256 | `929d12c5e99c8df5cc8c138aad7e9d527560b31dd8953126beec0a2920f0febe` |
| MCP catalog SHA256 | `61325aadc2fa6740c84037227c9410f5e299267d908cfbbd0be6b05eedfbfbf8` |

The separate named v16 entry selects Hepta `6ecd8023615a6e0b2dc269379fb059c656b38b6f`, tree `4c51962e030e9ea39c6498224c99eb40fbdd2f35`, profile `selfhost-core-linux-x86_64-v16`, and the same runtime. Its lock is `b3c3725e183d98bec2819155f2d4cd525c3f45305d04ec8fa686e13f454e50e0`. It was discovered, not installed or substituted for current.

CLI `python -m hepta hia build` defaults to LLVM; explicit `--backend native` selects direct HIA generation. CLI `hia emit` produces LLVM text. MCP `hia_emit` uses `hia-direct` under discovered worker/backend/catalog/profile identity. No live MCP identity was established here; source catalog facts do not attest a live endpoint.

Direct target: `x86_64-unknown-linux-gnu`, ELF64/AMD64, little-endian LP64, SysV AMD64; scalar ABI `hepta.hia.program.direct-linux-x86_64.v1`. Borrowed-byte entry has a separate ABI.

## Minimum syntax and actual native program

The selected `examples/hia_safe_core/scalar_add.hia.json` is primitive Core **v1**, independent of selfhost profile v9. It defines one `calculate(a:u32,z:u32)->u32`, one entry block repeating the function parameters, `int.add.wrap`, and `ret`. Functions/blocks explicitly declare names/types/effects/params/ops/term; attributes are `{}`. Exact file SHA256: `a4b603a4aab5b62e90b8109290f2e69d7310d36cd4188be54f5985cc83185db3`; canonical Core SHA256: `18e87ce97ca8473508ccf95b8554aec10c04ebd2f8df2b3a77af627a1595ee8a`.

`hia-asm.v1` also spells explicit primitive Core v6/v7/v8; types/casts/resources/cleanup are never inferred. Entry catalog's latest primitive schema is v8; the actual minimum example remains valid v1.

`hia catalog --schema hepta.hia.program.v1` and `hia verify` passed. `hia run --function calculate --arguments '[35,7]'` returned 42. Object/shared builds explicitly selected native/target/kind and `--linker ld`. Receipts report direct machine generation without LLVM, assembler, C or Rust codegen/fallback.

| Artifact | Bytes | SHA256 |
| --- | ---: | --- |
| `native/calculate.o` | 992 | `59f74cdcf2ffe1690c5b61913c6521b1e8d1e37178a3298cdfe532b999037158` |
| Default CLI `native/calculate.so` | 13656 | `b783dd88a23b529dc39117656ac43ce7ac0ff00440264fd61bbcb46ba9f72aeb` |
| Recovery `native/calculate-hash-both.so` | 13720 | `b505bd0d35d3c773f528e3a5cfafa3c45885ddce4b38f73913f800472a2ed72a` |

Real ctypes/CDLL calls used `calculate(uint32_t,uint32_t)->uint32_t` and an independent Python `(a+b)&0xffffffff` oracle. **Both images** passed `(35,7)->42`, `(0,0)->0`, `(2,3)->5`, `(4294967295,1)->0`, `(4294967295,4294967295)->4294967294`; file hashes were unchanged before/after calls. Original results: `native-real-call.stdout`, `native-real-call-hash-both.stdout`.

## Actual proof failures and recovery

1. The metadata handoff's proof command included `--profile-version 1`. Exact current-v9 checker rejected it with exit 2: `error: unrecognized arguments: --profile-version 1`. See `proof-document-command.stderr` and supported `proof-help.stdout`. The metadata owner was informed after discovery.
2. Supported retry against the original default CLI image exited 1: `E_HIA_SAFE_CORE_ELF: missing section .hash`. `native/proof/attempt.json` retains exact failed source/object/image snapshots. `elf-sections.stdout` confirms GNU ld 2.44's default image has `.gnu.hash` without `.hash`. Pinned builder does not select hash style; pinned checker requires both.
3. Recovery explicitly relinked the **same retained direct-generated object** with recorded CLI GNU-ld flags plus `--hash-style=both`. It created a new final artifact without changing source/locks/runtime/checker or replacing failures. `relink-hash-both.*` records full argv.
4. Unchanged independent consumer successfully checked the exact source/object/recovery-image triple. It did not invoke compiler/linker or producer reemission: all three corresponding fields are false. `native/proof-hash-both/attempt.json` and `queries/` retain complete input/subject/solver/checker identities, assumptions, queries, outcomes and open obligations.

Raw supplied profile: `hia.safe-core.unsigned-acyclic-single-borrow.supplied-elf.x86_64.v1`. Available Agent projection: `hia.agent.safe-core.scalar-supplied-elf.x86_64.v1`, one unsigned scalar acyclic function, final shared ELF, no borrowed/foreign entries. This trial exercised the raw supplied-byte CLI, not a live MCP proof call.

| Independent-model obligation | Observed |
| --- | --- |
| Caller-contract nonvacuity | SAT |
| Machine memory bounds violation | UNSAT |
| SysV stack alignment/preservation violation | UNSAT |
| Missing terminal Core/machine-model outcome | UNSAT |
| Core/final return-abort-caller-byte disagreement | UNSAT |

Positive result is all-input refinement **inside identified trusted Python Core/x86/ELF models and Z3 4.15.4**. Caller/stack/loader/abort validity remain assumptions; full hardware ISA refinement, checker soundness, whole-language correctness, concurrency/signals/faults/resources/side channels remain open. Neither proof nor report grants execution/adoption authority. Task execution was separately authorized and observed.

## Final source condition

Both materialized repositories retained exact pinned HEAD/tree and empty `git status --porcelain --untracked-files=all` (`final-*-identity.*`, `final-*-revision.*`). All outputs are outside source trees; source-only lock qualification flags remain unchanged.

The INSTALL direct-native qualification command additionally **passed all 173 tests**, no failures/errors/skips, inventory complete and source unchanged. Its terminal original output and complete finite result are retained in `pinned-native-qualification.*` and `hia-native.json` (source digest `cf257a349c3e01fc2437accd93c2e90ac2f56ec23e4a36a51e8251a0ab95474c`). This qualification is separate from the independent supplied-byte proof above.
