# Resource composition candidate: execution evidence

The implementation and prerequisite repairs are published through
[44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314](https://github.com/TrillionniumFoundation/Hepta/commit/44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314).
The complete local qualifications below executed the earlier frozen
`3a424e427b378400802c9e3c2fef558c0a352756`. Later commits repair prerequisites,
workflow/test tool selection and host-observation handling. Hepta compiler
bytes and frozen native performance protocols remain identical. Full source
snapshots and workflow results are still bound to their individual commits.

This evidence branch does not move the code candidate. **Archive verification
is not another native execution**, and a successful data verifier does not
turn a retained failed qualification into a pass.

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

The four-host Rust/C ABI workflows passed for 19299, 3a, 8dcb, 7ef and d8e.
[The d8e host appendix](../ci_prerequisites_20261026/hosts_d8e1b676/README.md)
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
runs or establish their cause. The original 7ef artifact remains
[available from its provider](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435880235/artifacts/12704884741)
while its durable appendix is being completed.

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

At this checkpoint, [d8e full CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40438827706)
and [44cb full CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40439677114)
are still running independently. The 44cb four-host run is also separate.
Pending work is not counted as qualification, and no run was cancelled to
remove an unfavourable result.

## Acceptance boundary

The complete seven-stage production goal remains open. See
[BLOCKERS.md](../../docs/BLOCKERS.md) for P01–P12: general lifetime/trait
composition, compiler refinement and soundness, whole-process budgets, broad
services and C/C++ migration, physical hardware/GPU, general performance and
agent productivity, and the production ecosystem remain scoped or unproved.
Historical actual model trials are separately identified; fixture qualification
does not count as a new model trial or a demonstrated agent benefit.
