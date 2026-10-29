# HIA Core continuation: local views, unit enums and bound Rust execution

This candidate continues PR #352 at
`2f49151ab9d8812eeb02ac2056f224f140099d76`. That source already contains the
earlier #329 integration, v8 returned loans, source partial-field restoration,
owned Rust Machine, finite safety matrix and six-outcome experiments. Those
implementations and historical measurements are retained under their original
identities. This increment does not repeat or relabel them.

## Changes and their execution authority

| Work | Implemented increment | Authority and exclusions |
| --- | --- | --- |
| P0/P1 source convergence | Finite local shared/mutable byte-view records lower to the existing primitive v1/v8 Core | The existing source/Resource IR checks establish the declared local lifetime subset; canonical Core admission checks emitted ownership and loans. No view parameters/returns, arbitrary stored lifetimes, new opcode or second VM |
| P0/P1 finite enums | Concrete enums with 1–32 unit variants, including Copy record fields and Result errors, lower to the existing u32/CFG operations | Fresh nominal checking, exhaustive matching and original public-entry restrictions remain required; payload, generic and recursive enums and enum C ABI remain excluded |
| P2/P7 independent execution | An opt-in Rust envelope binds the actual Core, entry, typed arguments and policy; a public development API freshly executes and compares both VMs | Complete outcomes, ticks and stopped resource ledgers must agree. Python remains production authority; imported success metadata cannot grant admission |
| P2 explicit depth policy | A separate v2 envelope binds a required root-inclusive call-depth policy in 1–32 to the same Machine; v1 remains fixed at 32 | Actual recursion, loans, chains and stopped ledgers are compared under that policy. v3 has a separate finite contract; neither protocol grants production authority |
| P2 explicit frames and v3 budgets | One Machine and ByteMemory ledger now use explicit language frames; v3 accepts up to 256 frames, ten million ticks and 1 GiB logical payload | Finite controls execute every depth, deep returned loans and chains, ten million allowed ticks and a 16 MiB plus one byte allocation. Successful 1 GiB allocation, RSS bounds, complete API parity and production authority are not established |
| P0/P4 migration intake | Existing #349–#356 IR/input fixes converge on this source; all scalar C pilot compiler queries use live bounded capture | CLI and direct API retain input/output separation, source and IR budgets, and whole-source refusal. The original scalar C profile remains limited |
| P4 Windows frozen input | Git attributes preserve the original bytes of the locked C++ upgrade fixtures across autocrlf checkouts | The expected upstream hashes and all host-identity checks remain strict. A checkout reproduction is separate from actual Windows native execution |
| P7 qualification scope | The reviewed safety matrix has an independent canonical identity and is resolved from the checked immutable bytes | Removing capabilities/tests or changing assumptions cannot inherit the reviewed qualification. This is protocol integrity, not a semantic theorem |
| P7 committed source identity | Every main-source snapshot enumerates the original exact HEAD tree and compares each regular working file's raw Git blob identity and executable bit | Index hints, replacement refs and `core.fileMode=false` cannot relabel changed bytes or modes as the original source; this does not authenticate a hostile host |
| P7 external inputs | The persistent NDU stream is a fourth explicitly pinned native dependency, with actual persistent/one-shot controls and before/after external inventories | Synthetic identity probes establish no NDU optimization gain or publication authority |
| P6/P7 research native target | The filecheck research IR retains the actual C frontend CPU and complete positive/negative feature policy through full LTO | Controlled masked-CPU execution checks this finite path; the default backend receipt and `no_change` optimization policy remain separate |
| P7 native failure retention | Differential and maintenance validation run in finite workers so actual signal failures retain progress and a failed qualification report | This does not establish hostile-code isolation or normal resource cleanup after a signal |

Detailed implementation contracts:

- [Finite source local views](HIA_SOURCE_LOCAL_VIEWS.md)
- [Finite source unit enums](HIA_SOURCE_UNIT_ENUMS.md)
- [Bound Rust execution](HIA_RUST_BOUND_EXECUTION.md)
- [Explicit finite Rust call-depth policy](HIA_RUST_BOUND_DEPTH_V2.md)
- [Explicit frames and finite v3 budget policy](HIA_RUST_BOUND_BUDGET_V3.md)
- [Rust subprocess ownership and cleanup](HIA_RUST_SHADOW_PROCESS_OWNERSHIP.md)
- [Migration input and compiler-process boundaries](P0_P4_MIGRATION_BOUNDARIES_20261028.md)
- [Reviewed safety contract](HIA_SAFETY_CONTRACT.md)
- [Research target policy and native failure retention](HIA_FILECHECK_NATIVE_TARGET_AND_FAILURES.md)

The C migration integration selects the existing fixes from #349, #350, #351,
#353, #354, #355 and #356, whose final source is
`a14291c804814c83d69a2def9e8df442d2091d62`. The newer compiler selection in
this candidate is retained; the old #347 backend and old workflows are not
copied over it.

The first published continuation at `a9e22f96d3bf67181bbb92c286bfd5e07cfa11e4`
exposed a real Windows CI failure before C++ compilation: Git newline conversion
changed locked nlohmann/json header bytes. The corrected checkout policy keeps
both pinned versions, licenses and the lock/notice files byte-identical. The
same original hash checks still reject an edited header or license. Original
failed host logs remain evidence for their own source commit; only a new actual
Windows host run can qualify the corrected source on Windows.

## Source and native qualification

The integrated qualifier is now
`hepta.hia.integrated-contract-qualification.v2`. Its required gates are the
actual tool/kernel capabilities, ranking NDU identity, recursive NDU identity,
finite NDU identity, persistent-stream NDU identity, Rust crate, complete
Python regression, and explicit critical-module coverage. It rejects skipped
or failed tests, missing required modules, source drift and external-input
drift. Test sets overlap; their counts are never summed as independent tasks.

The native inputs are separate and retain their own existing contracts:

| Native dependency | Pinned source |
| --- | --- |
| Ranking bridge | `rust/hia-ndu-bridge/upstream.json` and its checked build receipt |
| Recursive bridge | `2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b` |
| Finite graph bridge | `4b6391e116949af0c7e59776baead67271856bdb` |
| Persistent stream bridge | `c4a1bbed3a39beba43a6abf1a18b6f75c5725c21` |

For the stream, both requests must use one actual process and agree with the
one-shot evaluator; context exit must close it. Its binary, identity receipt,
declared source files and compiler identities enter the same external inventory
as the other native dependencies. Tests additionally retain their own runtime
identity checks. An environment that cannot inspect the actual process image
does not pass by omitting that check.

Source identity is checked against the selected commit's regular Git blobs.
It does not use `git archive`: archive attributes can transform exported bytes,
and a partial clone can unnecessarily fetch unrelated repository blobs before
applying archive path filtering. The tree path set, object type and each raw
source digest must match the declared input inventory. This is the declared
input closure, not a proof of every transitive compiler/sysroot dependency.
Git replacement objects are explicitly disabled during source and upstream
identity reads: a local replacement ref cannot relabel different commit or
blob contents as the frozen source.

Use `python tools/qualify_hia_integrated.py --help` for the explicit source,
tool, bridge, receipt and upstream arguments. The output and Cargo target must
be outside the clean committed source tree. The new stream arguments are
mandatory; an inherited environment variable alone cannot satisfy that gate.
The reviewed safety boundary is independently executable with:

```sh
python tools/qualify_hia_safety_contract.py --output /tmp/new-safety-report.json
```

The workflows select the actual source commit and retain failed as well as
successful observations. A local component test is not a replacement for a
fresh integrated-source result or a host that was not actually executed.

`hepta-qualification.yml` invokes the eight-gate integrated qualifier after its
existing release, standalone HIA and NDU pipeline gates. It passes all four
native bridge/receipt/upstream selections explicitly, including the separate
finite compiler profile and mandatory stream inputs. Its source is a clean
detached sibling worktree at the exact event/PR-head commit: earlier gates keep
their in-checkout observations without those files entering this qualification.
Output, the Cargo build cache and console/worktree logs stay outside that clean
source. Locked Rust dependencies are fetched before the qualifier's offline
Cargo execution. A failing qualifier fails the job even through its log pipe;
the final always-run upload retains the integrated raw records and stream build
identity alongside the existing native records. The wider job watchdog allows
the additional full regression pass without removing or weakening earlier gates.
These are CI execution requirements, not a claim that an unobserved host run has
already passed. The separately invoked safety contract currently selects 95
unique regression methods across 16 capability rows under its canonical hash.
All prior 80 selectors remain present; eight actual v3 execution and refusal
methods extend the existing independent-shadow row; two linker identity/cleanup
methods and four strict qualification-result methods and the exact syscall/timeout control
extend protocol integrity.
Their source-identity additions reject pre-snapshot
byte changes hidden by either index hint and executable-bit changes hidden by
`core.fileMode=false`. The integrated source inventory comes from the raw exact
HEAD tree, independently of the index. A single bounded read computes SHA-256
and the matching Git blob identity for every regular tracked file, while
retaining no-follow and before/open/after-read stability checks. Real temporary
Git regressions also cover unchanged hinted files, clean before/after snapshots,
later hidden changes, missing/nonregular members, raw tree paths, replacement
objects and a mutation during the file read. Directory entries, including empty
subtrees, participate in the same unsafe/duplicate path checks; only regular
blobs enter the existing file-hash dictionary. These tests execute no integrated
native gate by themselves and do not upgrade historical observations.
Its before/after input inventory includes tracked workflow files, checkout
attributes and all frozen C++ upgrade inputs, including licenses and notices.
These controls participate in source stability even when their suffix is not
one of the language-source suffixes.

The subsequent three matrix additions cover actual masked-x86 target-policy
execution and retained `SIGILL`/`SIGABRT` failures in the filecheck validation
workers. Their original motivating failure remains attached to `3d5401c`.
Explicit C frontend target attributes prevent the reproduced raw-IR full-LTO
loss of disabled features without dropping LTO or downgrading the native arm.
The x86 emulator is an explicit actual-tool identity in integrated qualification.
Neither a controlled CPU reproduction nor a later passing host run establishes
the missing CPU identity of the original failed CI runner.

The old workflow watchdog assertion is aligned with the already declared
240-minute job budget for three complete regression passes. Individual
3,600-second unit budgets, native gate collection and failure acceptance remain
unchanged. The original complete run that rejected the stale 180-minute
assertion is retained as a failed run, not a source-qualified success.

The v3 module is required by integrated coverage and the reviewed safety
contract. The same Machine executes all legacy and new envelopes; v1/v2 limits
are unchanged. Complete outcomes, ticks, stopped ledgers, original nominal
entry restrictions and cross-version replay refusal remain part of comparison.
Raising a declared logical-byte ceiling does not establish successful allocation
at that ceiling or a physical-memory bound. The Rust `u64` allocation-failure
index and scalar argument transport remain narrower than the complete Python
API, so the production switch still requires separate qualification.

## Broad P0–P7 closure remains open

| Stage | Remaining strict obligation |
| --- | --- |
| P0 | All legacy source, bridge, local-view and task/I/O execution contracts must converge, beyond the finite adapter added here |
| P1 | General memory/provenance, arbitrary recursive ADTs and partial initialization, escaping/external lifetimes, asynchronous cancellation and complete error cleanup |
| P2 | Production Rust authority switch qualification with the required complete semantics and deployment gates |
| P3 | General direct-LLVM public aggregate/callback ABI, reentrancy, threads and foreign lifetimes |
| P4 | Representative complete historical projects and all build configurations, with measured human migration and maintenance cost |
| P5 | An independent current-source real-task efficiency experiment; reference controls and failed model calibration are not model success |
| P6 | Representative throughput/tail latency, process RSS and physical-device protocols; this increment performs no new performance campaign |
| P7 | Full correspondence from the formal model to the implemented checker, transformations and backends, plus whole-language soundness/refinement |

`whole_project_blockers_closed=false`,
`rust_is_production_admission_authority=false`, and all previously unproved
universal claims remain false. Existing negative model/NDU/performance results
are unchanged. New functionality and finite correctness observations do not
convert `no_change` into an accepted optimization policy.
