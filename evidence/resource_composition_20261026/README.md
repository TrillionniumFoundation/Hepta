# Resource composition candidate: execution evidence

The implementation and prerequisite repairs are published through
[4ac39e626acd7f78e2f66708be741e78308b4e6a](https://github.com/TrillionniumFoundation/Hepta/commit/4ac39e626acd7f78e2f66708be741e78308b4e6a).
The complete local qualifications below executed the earlier frozen
`3a424e427b378400802c9e3c2fef558c0a352756`. Later commits repair prerequisites,
workflow/test tool selection, host-observation handling, the two C migration
callers and task/I/O observation ordering. Hepta compiler/runtime
bytes and frozen native performance protocols remain identical. Full source
snapshots and workflow results are still bound to their individual commits.

This evidence branch does not move the code candidate. **Archive verification
is not another native execution**, and a successful data verifier does not
turn a retained failed qualification into a pass.
Check out the linked code commit to execute the candidate; this branch carries
the evidence appendices on top of a historical code revision.

## Current frozen repair candidate

The published `4ac39e62` tree is
`99a2273d45a333a1a9cc87110742399e7413d512`, identical to locally tested
`8c88308eb9b6a8acf612ae9e8f7d9a7d89f5a776`. Its
[four-host ABI workflow](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40445065374)
has passed, with [new exact-source reports](../ci_prerequisites_20261026/hosts_4ac39e62/README.md)
retained for all four hosts. Its
[complete source and HIA workflow](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40445065395)
has passed all twelve prerequisite steps and is executing the complete source
qualification. Pending full qualification is not labelled passed.

The [caller ABI repair](../ci_prerequisites_20261026/caller_abi_repair/README.md)
retains actual legacy high-bit return truncation in both C callers, corrected
execution, and strict rejection when the declarations are removed. Its two
frozen local attempts bind `5b1eb709` and `a1ade3cc`, with all six native
files retained. The two, 25, four and 21 test logs describe separate targeted
runs; their counts are not added into a unique-test denominator.

The [task/I/O observation repair](../task_io_observation_fix_20261027/README.md)
preserves the existing runtime and qualifies all ten
planned cases at three repetitions on `8c88308e`: 27 actual executions,
including every expected assertion failure and timeout. Its 12-test suite
also passes without skips. A deterministic held-reference control reproduces
the original premature close assertion; user FDs remain checked immediately,
and wake FDs are checked after notification's last-reference boundary.
Neither repair changes a performance workload, baseline or threshold.

## Complete frozen local qualifications

| Item | Source candidate | Standalone HIA attempt 2 |
| --- | --- | --- |
| Planned / completed gates | 50 / 50 | 15 / 15 |
| Passed / failed gates | 48 / 2 | 14 / 1 |
| Unit and integration tests | 2,093; zero skips/failures/errors | 2,093; zero skips/failures/errors |
| Source snapshot | 920 files, unchanged | Same 920 files, unchanged |
| Performance samples | Scalar 42 + owned 63 | 63 |
| Measurement-quality failures | One scalar and five owned series exceed fixed 5% relative MAD | Four series exceed fixed 5% relative MAD |
| Speed-ratio threshold failures | None | None |
| Aggregate acceptance | Failed | Failed |

The complete source snapshot SHA-256 is
`339ed18eafd41c41e6b1e84f18bec100db5122cf60983c948aa721f54249c10b`.
The four new local-view, task/I/O, C++ composed-migration and direct-LLVM gates
passed, along with every other non-performance source gate.

[source_candidate](source_candidate/README.md) retains 920 source files with
Git-object bindings and 585 run artifacts. Deleted temporary namespaces and
excluded external toolchains are explicitly inventoried. The
[independent source performance review](../composition_performance_review_20261027/README.md)
recomputes every one of the 105 samples and its process-observation association
without calling a compiler, benchmark or production evaluation function.

[hia_candidate](hia_candidate/README.md) retains both local attempts and their
runner records: **729 members**, 15,142,172 raw bytes. The complete second attempt
contains all 63 timing samples, 588 correctness observations and 16 retained
performance files, independently checked against their recorded identities.
Its verifier preserves `qualification_passed: false` despite successful
archive/formula validation.

The first HIA attempt lost its execution session during unit regression. It
has no terminal report or retained performance samples. Its exit code and
completed-test count remain **unknown**, with its original plan, driver log
and interruption observation preserved. It is not a qualified attempt.

## Hosted candidates and actual prerequisites

The four-host Rust/C ABI workflows passed for 19299, 3a, 8dcb, 7ef, d8e and 44cb.
[The 44cb host appendix](../ci_prerequisites_20261026/hosts_44cb3257/README.md)
binds four original provider ZIPs/reports to the exact head and validates them
using LF or Windows CRLF exports. Each host executes 181 calls at `-O0`, 181
at `-O2`, layout checks and a compiled wrong-control rejection. These profiles
do not qualify every LLVM backend on those hosts. The original host archives
retain reports and binary hashes, not the native binaries themselves.

Earlier full CI failures remain in
[ci_prerequisites_20261026](../ci_prerequisites_20261026/README.md), including
separate [19299](../ci_prerequisites_20261026/failed_full_19299c82/README.md),
[3a](../ci_prerequisites_20261026/failed_full_3a424e42/README.md), and
[8dcb](../ci_prerequisites_20261026/failed_full_8dcb0d0d/README.md) appendices.
The 8dcb attempt made four QEMU requests with statuses 500/503/503/503 and
exhausted its bounded retries. Source qualification was skipped. HIA completed
12/15 gates, with three unit skips and two missing-QEMU gates; its complete
63-sample performance qualification passed. The unsuccessful aggregate and
successful finite performance result are both retained.

The completed
[7ef full run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435880235)
reached source **50/50, 48 passed** and HIA **15/15, 14 passed**. Source regression
actually ran 2,099 tests with 15 skips; HIA ran 2,102 with two skips. Neither
regression had assertion failures/errors. The other source failure was optional
host `/proc/1/root/...` metadata raising `PermissionError` and discarding the
boundary return value. All three native performance gates completed and passed
(42 scalar, 63 owned, 63 HIA samples). This does not erase local inconclusive
runs or establish their cause. The
[complete 7ef appendix](../ci_prerequisites_20261026/failed_full_7ef57d1b/README.md)
retains all 1,306 newly supplied files (180,828,498 raw bytes, including 176 ELF
files), the full original log, all 15 named source skips and independent
three-profile performance review. It explicitly distinguishes missing scalar
and owned temporary binaries from HIA's 16 retained performance files; none
was rebuilt or substituted during archival.

The repairs have their own original observations and limits:

- [QEMU source repair](../ci_prerequisites_20261026/qemu_source_repair/README.md):
  actual snapshot HTTP 503, identical locked package from the Ubuntu archive,
  and fresh installed executable identity.
- [Verification environment](../ci_prerequisites_20261026/verification_environment_repair/README.md):
  installed tool exports, PATH resolution, ten final wiring/collector checks,
  five actual native/Lean tests and a separate actual default-PATH control.
  Earlier development failures are preserved too.
- [Host procfs observation](../ci_prerequisites_20261026/sandbox_host_observation_repair/README.md):
  nine configuration regressions and three actual namespace controls. Ordinary
  and denied-host-stat cases pass all ten original checks; deliberately
  exposing a synthetic canary fails the real boundary and release collector.
  Unknown optional host metadata is never labelled absent.

The completed [d8e full CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40438827706)
reached source **50/50, 49 passed**, and HIA **15/15 passed**. Both regression
logs record **2,108 tests with zero skips, failures or errors**. All three
complete performance profiles passed (42 scalar, 63 owned and 63 HIA samples).
The only failed source gate was the optional host procfs metadata
`PermissionError` described above. This closes the observed installed-tool
selection failure for that exact candidate; it does not substitute for the
later candidate's complete qualification.
The [complete d8e appendix](../ci_prerequisites_20261026/failed_full_d8e1b676/README.md)
retains the original reports/logs, all 1,306 newly uploaded files, independent
three-profile arithmetic and the later C-caller finding alongside the original
producer status.

The completed [44cb full CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40439677114)
reached source **50/50, 49 passed**, and HIA **15/15 passed**. Both regression
logs record **2,111 tests with zero skips, failures or errors**. All ten strict
namespace checks passed. The three complete performance protocols passed
with all 42/63/63 samples retained. The only failed source gate is
`task_io_composition`: the positive native control's third repetition checks
the wake FD immediately after worker shutdown, before the cancelling thread
is required to release its final temporary binding reference. Its first two
repetitions passed; the failing repetition is retained with its actual abort.
Runtime source and the existing final-canceller control explicitly allow the
binding to survive until that last reference is released. The observation
must synchronize with that documented destruction boundary.

The [complete 44cb appendix](../ci_prerequisites_20261026/full_44cb3257/README.md)
retains all 1,306 newly uploaded files, the exact three-round task report,
all original source/HIA reports and independently checked performance data.
Its 923-file source snapshot is bound to the actual failed candidate. The
archive verifier preserves its 49/50 aggregate and the later caller findings.

A separate raw-log audit also found missing C prototypes in the standalone
single-owner and composed C++-migration LLVM callers. The original resource
vectors have small results; their recorded success does not qualify a correct
64-bit caller boundary. Actual high-bit probes reproduce the old callers'
truncation and distinguish it from the repaired callers and strict compilation
rejection. Repairs and their deterministic controls require a new frozen
candidate qualification; none of these historical runs was cancelled or
rewritten to remove an unfavourable result.

## Acceptance boundary

The complete seven-stage production goal remains open. See
[BLOCKERS.md](../../docs/BLOCKERS.md) for P01–P12: general lifetime/trait
composition, compiler refinement and soundness, whole-process budgets, broad
services and C/C++ migration, physical hardware/GPU, general performance and
agent productivity, and the production ecosystem remain scoped or unproved.
Historical actual model trials are separately identified; fixture qualification
does not count as a new model trial or a demonstrated agent benefit.
