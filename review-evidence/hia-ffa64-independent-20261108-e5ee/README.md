# Independent inspection of the exact ffa64 candidate

## Result and subject

Independent source, byte-identity and scope reconciliation passed for Hepta
`ffa64c93dd4c51190fda8c0f647481a31ffbcf07`, tree
`67fd66a7690ab007368ade7a7674ab7c82ac19fe`. This metadata-only record does
not select a release, repair or deploy a worker, or qualify any later source.
The six aggregate acceptance tracks remain HOLD.

## Original evidence

The two original GitHub ZIP archives were downloaded and their complete bytes
matched the platform's reported artifact digests before inspection.

| Evidence | Original run / artifact | Original bytes | SHA-256 |
|---|---|---:|---|
| Exact source qualification | [42529894249](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42529894249) / 13636779370 | 30,431,145 | `c4927564fd8aff7bb103b2b7dd31c0aa9fd40b5feb61a8acd5f56e663241b615` |
| Native NDU scalar integration and campaigns | [42529894198](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42529894198) / 13637310955 | 8,087,295 | `bdd5d79ee0c4546e4f0c5ae6ddfb7fcadeb1601a74d1879768ba2a853f04e021` |

Original archives remain GitHub Actions artifacts, subject to their configured
retention. They are not duplicated in this metadata commit. The local report
manifest binds every report and replay log saved here; it is not an attestation
of the host or of elapsed time.

## Core, machine proof and Agent inspection

The read-only audit rehashed original bytes and compared them with the exact Git
source. This is a derived report of segmented read-only ZIP/JSON/hash checks;
no one-command audit tool or replay of the whole audit is claimed. It did not
rerun a solver, compiler, native image or Agent/provider.

- The cold, nested-cold and language reports each have the same 252-file source
  closure. Their separate results are 11/11, 1,183/1,183 and 910/910. These counts
  are not added as distinct tests.
- Nineteen successful machine-proof/independent-recheck reports cover sixteen
  subjects. All nineteen have subject, property, profile, assumptions, checker
  and unproved-obligation fields. Nine checker files, actual Core/object/image
  bytes, and 95 recorded SMT obligations match their stated identities and
  outcomes. This is an audit of recorded queries/results, not fresh solver work.
- Both Agent evidence sets contain 115 original content-addressed objects with
  matching hashes. The scoped lifecycle uses the same canonical Core for the
  baseline and candidate. Its separate lowering claim is unsupported.
- The original select extension remains `HOLD_REAL_DELTA_STRICT_GATE`. For the
  retained distinguishing input C0 returns INVALID and C1 returns 421 bytes;
  evaluation refuses `E_HIA_CLAIM_REQUIRED`, and adoption is not attempted.
  Same-Core reflexivity does not establish the original extension's correctness.

The bounded v13 ELF profile covers 50 operation names, but not all Core inputs.
Remaining language obligations include the full scalar set, returned owners and
loans, general multiple-result calls/returns, identifiers/modules/effects and
general linker/target support. Complete compiler correctness and general
ABI/resource/FFI/ISA/loader refinement remain unproved. Full original provider
interaction and billing evidence remain unavailable.

## Independent NDU replay

The existing exact-source standard-library verifiers independently replayed the
two original CI campaigns. Both returned success: each has 72 cells, 1,020
original native responses and 510 ordinary controls. Original identity, framing,
cleanup, denominators, paired decisions and arithmetic were checked. No new
native evaluation or measurement was performed.

All 24 prepared-vs-one-shot pairs favor prepared transport. Persistent transport
is faster than prepared transport in all eighteen pairs at horizons 4, 16 and
64; at horizon 1 it wins two of six pairs and has a slower median. In both
campaigns the ordinary exact scalar enumerator is faster in all 24 pairs and
selects the same candidate. The separate historical four-pair task campaign is
not overwritten.

| Persistent campaign horizon | Ordinary median ms | Persistent NDU median ms | Prepared NDU median ms |
|---:|---:|---:|---:|
| 1 | 0.1299705 | 7.7260305 | 7.317211 |
| 4 | 0.540588 | 11.436924 | 13.339423 |
| 16 | 2.1407375 | 27.001416 | 43.42902 |
| 64 | 8.3688095 | 85.719596 | 156.0170725 |

These are descriptive six-order medians for a supplied-cost scalar profile, not
new real-user tasks or an economic test. Preparation reuse and process reuse
reduce transport cost; the original measured evidence does not establish
incremental NDU value over the ordinary control. Model cost is unknown, full
lifecycle cost is incomplete, and P2 remains HOLD.

To replay, obtain the exact second archive above, verify its SHA-256, and use
`tools/replay_hia_ndu_prepared_ranker.py` and
`tools/replay_hia_ndu_persistent_ranker.py` from the exact ffa64 commit. Pass each
original `*-mechanism` directory and the corresponding
`*-registration.sha256`; write to new output paths. The saved independent
reports include both registration and verifier identities.
