# HIA round6: one-source convergence and explicit qualification

This integration combines the finite implementation contracts developed in
Draft PRs #358, #359 and #360, together with the later scalar C importer guards.
It continues the existing HIA Core, source frontend, canonical verifier,
interpreter, independent Rust Machine and LLVM/native route. It does not add a
second language or let an optimizer replace the verifier.

## Frozen inputs and preserved history

| Input | Exact source | Included work |
| --- | --- | --- |
| #359 | `70179fcc54e2195f9966ca3f98428a6540d50a41` | Composite v4 returned loans, common NDU response admission, native publication/retirement and worker interruption ownership; Windows frozen-input byte preservation |
| #358 | `1669ddc05a918e7c01b17e9262d4461130d44aaa` | Local source views and unit enums, bounded independent Rust execution, strict raw Git/source and canonical matrix identities, eight integrated gates, native CPU-feature and failure evidence |
| #360 | `7511d99b80511b33082a76d71109adf4ecdb1395` | Captured C project views, selected scalar LLVM validation, entry-payload analysis, finite prepared artifact leases, stronger application/Agent/NDU protocols and their original negative evidence |
| C importer audit #370 | `9ff581fe84f8042213269e88be33d5d94e4c416c` | Selected importer and adversarial-test changes for bounded AST/probes, strict AST JSON, process cleanup, frozen source ABA and anchored artifact directories |

The C audit predates the integrated Core tree; only its relevant importer and
test changes are ported. Its older whole-repository workflow and subprocess
implementation are not replacements for the integrated implementation. The
shared bounded subprocess contract and the captured-source contract remain in
use. Tests must exercise the actual resulting implementation and preserve the
attacks, rather than treating a textual merge as qualification.

Integration review also identified shared capture defects: reaping a leader
before its final process-group signal loses its numeric identity reservation;
a swallowed reap timeout cannot certify cleanup; a size check followed by an
unbounded read does not retain a strict memory-read bound. The shared capture
fix retains the POSIX leader through the last owned group signal, rejects an
uncertain reap, and checks reads capped at each stream limit plus one byte.
Windows retains its existing Job Object owner. These controls do not establish
a sandbox, a process-wide memory/disk bound, or that a parent can reap arbitrary
grandchildren.

Historical reports retain their source commits, protocols, timestamps and
denominators. They are not results for this new combination. The #359 source
remains unchanged and its recovered CI evidence is published independently.
Its previous local-only full/component/supervisor records were lost during
workspace maintenance; this integration makes no claim that the missing local
full qualification completed or passed.

## Semantic and admission boundaries

Composite v4 elaborates to primitive v8 and retains returned-loan origins from
parameters or record fields. Owners, enums, tasks and partially initialized
records do not become loan anchors. Source local views and unit enums use the
existing Core forms; the newly combined frontend is checked together with the
verifier, interpreter and applicable independent/native routes.

The safety contract has **25 capabilities and 146 unique selected tests**.
The canonical protocol digest is
`56fc05759a228951a2f6a633ec338593283d7c730171c0d8ca54491f917abdc2`.
The prior 100 selectors remain present. The five added boundaries cover
selected scalar LLVM validation, finite entry-payload analysis, captured C
project views, prepared artifact ownership and prospective optimization-cost
attribution. A matrix is a reviewable implementation contract, not a general
soundness theorem or an executable admission receipt.

Resource legality, functional preservation and native artifact identity remain
separate checks. A candidate with unknown or refuted behavior validation is not
automatically admitted. NDU is a bounded proposal/selection mechanism and gains
no proof authority from a cost estimate, model response or serialized receipt.

The prepared artifact session supports the registered single scalar
`full_lifecycle(usize, u32) -> u64` workload within primitive v1–v7 on the declared
Linux x86-64 profile. It reuses internally issued proofs and sealed images under
bounded leases. Each invocation still uses a fresh child process. It does not
add persistent owner/loan state, composite v4 hot replacement or general
cross-version state migration. Uncertain descriptor releases retain charged
debt and cannot be retried using the same numeric descriptor.

## Qualification on this source

The branch `codex/hia-round6-convergence-20261029` selects the explicit
`integrated` workflow profile. Other branches retain the existing `full`
release profile. The profile is recorded beside the expected and actual source
commit, and a source mismatch fails before the profile is exported.

The integrated profile provisions the existing locked tools and all four
separately identified native NDU bridges. It executes the existing eight-gate
qualifier, including one complete Python discovery pass, the actual Rust crate,
native tool/kernel identity probes and critical-module coverage. It then runs
the complete canonical safety matrix. Missing tools, skipped tests, failures,
source drift or external input drift prevent qualification. Artifact session
native tests are explicitly enabled in both CI and the direct qualifier.

Both integrated and application qualification create clean sibling worktrees
from the exact expected commit. Build caches, upstream checkouts and reports
remain outside those source inventories. Application identity reports use the
same external output directory that the workflow uploads. Existing legacy
release gates are not removed, but they are not executed or claimed by the
integrated-only profile. The profile avoids repeating the complete regression
pass three times; it does not replace discovery with selected tests.

Integrated CI retains source/tool identities, complete execution records and
console streams. Its upload paths exclude upstream checkout directories,
native NDU bridge binaries and Cargo targets. Failures remain artifacts.
Separate host workflows execute the existing seven C/ABI profiles and seven
C++ library profiles on their actual OS/compiler/architecture combinations.
These are two seven-job matrices, not fourteen different architectures.
Branch push triggers the integrated, migration and two host workflows. The
application and verified-optimization workflows are triggered by the new Draft
PR's changed paths; their start depends on that PR being created successfully.

The macOS jobs use Python 3.13 so that the actual non-reaping `os.waitid`
interface is available; Linux and Windows retain Python 3.11 in these host
matrices. [CPython documents macOS support from 3.13](https://docs.python.org/3.13/library/os.html#os.waitid).
The capture runner checks the actual interface and refuses unsupported POSIX
environments instead of falling back to a reaping poll. This is an explicit
host-tool requirement, not inferred evidence that the macOS jobs have passed.

The local workflow checks execute real shell fixtures for profile selection,
source mismatch, clean worktrees, retained failure exit codes and external
identity copies. Those fixture checks do not qualify a compiler or native
artifact. Current-source native results must come from the corresponding
actual CI executions; a previous green run is not inherited.

## Six closure conditions remain distinct

| Track | This integration makes reviewable | Still required before broad closure |
| --- | --- | --- |
| 1. One semantic contract | One combined frontend/Core/registry/checker/runtime tree and strict eight-gate identity | Actual combined-source qualification; broader frontend/backend refinement |
| 2. Resources and Rust differential | Returned loans, composite resources, bounded invocation/depth and refusal cases in one source | Execution over the declared combined subset; broader ownership, concurrency and cancellation semantics |
| 3. Optimization behavior | Separate legality, selected all-input equivalence checks, negative controls and admission identity | Proof coverage outside the finite scalar/guarded profiles and through final native code |
| 4. NDU incremental value | Same-budget protocols, shared artifact-reuse eligibility, strong DP/fixed controls and preserved negative results | Positive measured net value over the preregistered controls; no such result is claimed here |
| 5. C/C++ migration and ABI | Real captured project routes, anchored C intake/output, foreign-library reuse and actual host jobs | General translation, foreign safety obligations, platform coverage and measured engineering cost |
| 6. Runtime/instruction optimization | Finite generation/lease/cancellation/release rules and independently validated candidate search | Positive net gain, broader state compatibility and complete resource-lifetime evidence |

The original prepared-reuse study remains negative: its registered warm costs
were 208.131606 s for strong fixed, 212.495324 s for complete finite DP, and
237.767684 s for NDU. All 148 NDU decisions matched the DP optimum for that
finite model; this did not produce a measured controller advantage. Shared
proof/image reuse cannot be attributed to NDU. These observations belong to
`b53d61cd3cdb522ccd718f3fdc7cd62d1d5964a2`, not this integration.

The existing CRC application median improvement also did not meet the combined
P99/RSS gate. No universal Rust performance superiority, arbitrary C++ safety,
absolute resource safety, whole-language proof or global instruction optimum
is established by the integration or by a green CI run.
