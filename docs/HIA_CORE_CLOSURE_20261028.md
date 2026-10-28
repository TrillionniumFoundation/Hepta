# HIA Core continuation: local views, exact Rust execution and migration boundaries

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
| P2/P7 independent execution | An opt-in Rust envelope binds the actual Core, entry, typed arguments and policy; a public development API freshly executes and compares both VMs | Complete outcomes, ticks and stopped resource ledgers must agree. Python remains production authority; imported success metadata cannot grant admission |
| P0/P4 migration intake | Existing #349–#356 IR/input fixes converge on this source; all scalar C pilot compiler queries use live bounded capture | CLI and direct API retain input/output separation, source and IR budgets, and whole-source refusal. The original scalar C profile remains limited |
| P7 qualification scope | The reviewed safety matrix has an independent canonical identity and is resolved from the checked immutable bytes | Removing capabilities/tests or changing assumptions cannot inherit the reviewed qualification. This is protocol integrity, not a semantic theorem |
| P7 external inputs | The persistent NDU stream is a fourth explicitly pinned native dependency, with actual persistent/one-shot controls and before/after external inventories | Synthetic identity probes establish no NDU optimization gain or publication authority |

Detailed implementation contracts:

- [Finite source local views](HIA_SOURCE_LOCAL_VIEWS.md)
- [Bound Rust execution](HIA_RUST_BOUND_EXECUTION.md)
- [Rust subprocess ownership and cleanup](HIA_RUST_SHADOW_PROCESS_OWNERSHIP.md)
- [Migration input and compiler-process boundaries](P0_P4_MIGRATION_BOUNDARIES_20261028.md)
- [Reviewed safety contract](HIA_SAFETY_CONTRACT.md)

The C migration integration selects the existing fixes from #349, #350, #351,
#353, #354, #355 and #356, whose final source is
`a14291c804814c83d69a2def9e8df442d2091d62`. The newer compiler selection in
this candidate is retained; the old #347 backend and old workflows are not
copied over it.

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
