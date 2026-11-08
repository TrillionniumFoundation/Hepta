# HIA adversarial closure increment, 2026-11-08

Base source: `2598f4309791d3a023cd5df585ad26810b20c744`.
This source increment composes three independently exercised changes. Its final
GitHub commit must pass the exact-source and native-NDU workflows before release
selection. No online deployment or default-release change is performed by it.

## Changes

- The native selfhosting compiler now supports the five explicit Core trap
  codes, preserves effects before a trap, and rejects malformed terminators.
  It enforces the frontend's 16,384-byte line and 16,384-line wire limits before
  output mutation. Profile v10 has four terminators; input opcode support
  remains 32/50. Native traps remain UD2, without structured reason-code output.
- Safe Core checks PT_LOAD virtual-address order in the original program-header
  table before sorting page intervals. The original checker accepted a reordered
  image that failed in an actual disposable native loader process. Shared
  linkage now explicitly requests both SysV and GNU lookup tables, including
  the C-driver path.
- Native NDU acceptance requires a nonempty, complete, unique registered
  episode/arm cohort, complete successful steps, consistent measured costs and
  a matching closed native session. Finalization recomputes acceptance from the
  final observations. This repairs result admission and creates no new
  performance or economic-benefit evidence.

## Recorded validation

| Population | Result | Evidence |
| --- | --- | --- |
| Combined source/contract checks | 24 passed, zero skips | [Log](../review-evidence/hia-sixgap-audit-20261108/combined-source-tests.log) |
| Selfhost increment | cold outer 10/10 and inner 461/461, including 98 new controls | [Complete raw archive and summary](../review-evidence/hia-selfhost-v10-control-20261108/README.md) |
| Safe Core loader increment | 42 tests, 3 positive models, 5 semantic negative controls, 29 SMT replays | [Reproduction and raw archive](../review-evidence/hia-loader-order-20261108/README.md) |
| NDU acceptance increment | 42 tests; original-assessor red cases retained | [Admission scope and logs](HIA_NATIVE_COHORT_GATE_20261108.md) |
| Online identity snapshot | v8 readback matches its exact public lock; independent repeat fails with -32603 | [Point-in-time readback](../review-evidence/hia-online-identity-1925-20261108/README.md) |

These populations overlap and must not be added as unique coverage. The initial
scratch environment disappeared; implementation files were reconstructed from
exact GitHub blobs and the recorded patches. All locally archived test runs
were then executed again. Raw source inventories, object/image hashes, failed
controls and original online responses are retained. The new composition has a
regenerated selfhost source contract, and the release inventory includes its
new control helper and NDU admission tests.

The online readback is historical evidence for the version named in that
capture. Concurrent later deployment of v9 was observed separately; the v8
receipt does not qualify a newer installation or establish endpoint stability.

## Gates still open

This increment does not establish complete Core selfhosting, general compiler
correctness, a machine-checked full ISA/loader/FFI proof, unrestricted resource
semantics, complete unfamiliar-Agent provider interaction/billing, or stable NDU
incremental/economic benefit. The six-gate aggregate remains HOLD. Explicit
profile limits and proof assumptions are retained; passing a narrower gate
does not discharge a different subject or property.
