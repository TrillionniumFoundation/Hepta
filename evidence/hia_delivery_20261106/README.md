# HIA deliverable candidate — 2026-11-06

The locally qualified source is **`d21359485776c0a9687e88d0f69c8ec06a3b3b98`**,
tree `a0fdc2913c0170be210f7997b1648414923d76e7`. This evidence commit is a
publication record, not a replacement source pin. Build the candidate from the
source pin, not from the later evidence commit.

HIA is a typed virtual assembly language for AI Agent authoring and verified
optimization, with independent Core semantics, ownership/resource checks,
interpretation and direct LLVM compilation.

## Delivered result

| Workstream | Concrete delivery | Qualification boundary |
| --- | --- | --- |
| One obtainable candidate | Deterministic wheel, full source/manifest identities, offline verifier and downloadable bundle | Experimental installed candidate; main is a discovery entry and historical source integration remains unfinished |
| Specification and implementation | Generated schema/opcode/target/scalar ABI contract, corrected composite v4 and primitive v8 documentation, drift checks | Three real target objects; target execution is qualified on the measured x86-64 Linux host only |
| Complete application | HIA quota accounting plus explicit POSIX host, cancellation, uncertain commit reconciliation, replay and v1→v2 upgrade | One bounded cooperating account, 1,024 journal records; no distributed/external exactly-once or power-loss claim |
| Intelligence goal | Full-cost Agent maintenance objective and proposed model identity/type/effect/resource/failure/replay contract | Model inference, learning and model-state mutation remain proposed extensions |
| Strong separate controls | HIA/interface factorial protocol, NDU/ordinary-planner protocol, strict assessor, frozen adverse history and independent finite-model oracle | No new hosted-model maintenance campaign or native NDU value campaign; no positive productivity or NDU gain claim |

## Exact local acceptance

[`qualification/local-r3/RESULT.json`](qualification/local-r3/RESULT.json) is
`qualified=true`. All eight commands returned zero. Before and after every
command, and at final acceptance, the gate compared the actual bytes of all
9,220 tracked files with the fixed Git tree. A matching `git status` alone is
insufficient. Every child uses a fresh Python bytecode cache prefix.

- 123 registered regression tests, all executed exactly once; zero failures,
  errors, skips, expected failures or unexpected successes.
- 20 quota application tests with the same zero-exception inventory rule,
  including actual native v1/v2 execution, real child-process death between
  publication and acknowledgment, cancellation and upgrade/reopen behavior.
- 1,768 independent integer-oracle cases per version/backend: 7,072 comparisons
  across two versions and two backends. These are test cases, not independent
  maintenance tasks or statistical evidence of productivity.
- Primitive v1–v8 × three targets × eleven scalar types: 264 LLVM emission
  checks. The compatibility native test built actual x86-64, AArch64 and RV64
  ELF objects. Only host x86-64 execution was run here.
- Both clean builds have identical bytes for all seven bundle files. The fresh
  venv qualification has 18 successful observations; it checks all 193 installed
  package/code/data files before and after execution. The installed counter
  compiles directly through LLVM/Clang 20.1.8 and returns 41.
- The offline value audit checks 18 supplied models, 5,141 complete schedules,
  51 budget boundaries and 72 invocation cases; 17 safe-skip cases and eight
  future-compute-sensitive cases are retained. It invokes neither a hosted model
  nor native NDU and establishes no NDU advantage.

See [`regression-summary.json`](qualification/local-r3/regression-summary.json),
[`quota-qualification.json`](qualification/local-r3/quota-qualification.json),
[`installed-native.json`](qualification/local-r3/installed-native.json) and
[`value-controls.json`](qualification/local-r3/value-controls.json) for the
actual inventories, receipts, outcomes and scope flags.

## Candidate identity and download

Version: `0.2.0+hia.gd21359485776.s0ca27dca9ad8`.

Manifest SHA-256:
`4c1e62181f9a611f7e02c00c1b4244e4f343c133b18658260b13bdad8b157a12`.

Wheel SHA-256:
`01a099c2f51f842303be79028fb709285e9c67d63229777e1c39abe8614e6198`.

The [downloadable bundle](../../releases/hia/20261106/candidate-d21359485776.zip)
contains the exact candidate-A bytes; candidate B was equal. Its archive SHA-256
is `a2af74269272b6663481f9f8f68b6fe9e38b6f864d5b0d50da8a2c790f980f51`.
The outer ZIP is a transport artifact. The fixed manifest and wheel identities
remain the candidate authority, not the archive filename.

## Failed attempts remain visible

| Attempt | Source | Outcome |
| --- | --- | --- |
| [local-r1](qualification/local-r1/RESULT.json) | `9bfbfb2a3e60ba8b9577ea9f8017a90480e8be0e` | 122 regression tests passed; one stale-bytecode fixture errored because it inherited the gate's external cache prefix |
| [local-r2](qualification/local-r2/RESULT.json) | `86543acf966473c4e6a1212ed4c4c5bccbacab0c` | 123 regressions and 20 native quota tests passed; the gate failed when a command receipt collided with the value-controls child result filename |
| [local-r3](qualification/local-r3/RESULT.json) | `d21359485776c0a9687e88d0f69c8ec06a3b3b98` | Complete eight-command local acceptance passed |

The bytecode fixture now uses the ordinary checkout cache and first demonstrates
that a normal isolated import reads its injected marker. The builder then has
to ignore that same cache. Command receipts now use `.command.json` and cannot
overwrite child results. Neither failed attempt is relabeled as a pass.

Each local directory retains all original top-level report files. The complete
tracked source snapshot is losslessly compressed as `source-snapshot.json.gz`;
`ORIGINAL_FILES.json` records the original uncompressed SHA-256 and size. The
build command records bind both generated bundles; the archive retains one
copy of their identical payload. Temporary venvs/caches are not release data.

The [application review](review/README.md), [release review](release-review/README.md)
and [toolchain acquisition](toolchain/llvm20-acquisition.json) retain the earlier
fault-injection counterexamples, source snapshots, fixes and provenance. Those
reviews do not substitute for the final exact-source gate.

## CI and remaining claims

The workflow is bound to the source commit. The separately recorded GitHub run
is [42263076114](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42263076114).
Its actual captured state is recorded under `qualification/ci`; a queued run is
not a remote pass. Local qualification and remote CI are distinct observations.

The default branch's README links the fixed candidate and evidence. It does not
merge the entire historical development stack. Production release, whole-language
soundness, cross-target machine execution, HIA Agent productivity gain and NDU
net gain remain unqualified. The existing broader release gates still apply.
