# V14 source convergence and remaining six-track obligations

This candidate starts from `ffa64c93dd4c51190fda8c0f647481a31ffbcf07`, reconciles
the loader/lease/cohort changes in [PR #816](https://github.com/TrillionniumFoundation/Hepta/pull/816)
with the observation deadlines in [PR #817](https://github.com/TrillionniumFoundation/Hepta/pull/817),
and adds u16 selfhosting and actual-output fragment evidence for the original
unfamiliar Agent task. Public release selection and online activation remain
separate operations. This source change does not replace the default lock.

## Resulting behavior

| Area | Change |
| --- | --- |
| u16 selfhosting | Constants, checked/wrapping arithmetic, comparisons, casts, select, calls, tail calls and CFG values have explicit 16-bit semantics. Existing resource type identifiers stay fixed; closed resource/owner ranges exclude the new scalar. |
| Actual-output evidence | The original frozen C1 produces five typed select programs. Source slots and unchanged 35-byte intervals are bound to actual outputs; an independent checker validates explicitly conditional projections. Whole generated programs have separate finite native observations. |
| Native identity | RELRO authority covers the writable GOT without taking executable pages; original PT_LOAD order and both hash tables are retained. Native call results use the admitted stored lease identity. |
| Cost admission | Finalization reconciles all registered observations, native calls, sessions and required costs. Missing or failed observations and unknown costs cannot be dropped to obtain a positive result. |
| Deadlines | Part04 checks read/select/waitid/wait completion against the existing deadlines, never renews a cleanup window, and binds the result into both v2 replay consumers. |
| Test observations | The timeout fixture waits for actual durable markers; a finite readiness guard preserves empty-prefix timeouts. Descendant termination is observed under the same PID/starttime and original whole-test deadline. Production limits are unchanged. |

## Local evidence and its source identities

These are overlapping, subject-specific reports, not numbers to add into a
single total of independent tests. Exact-head CI must run its own qualification.

| Subject | Result | Source and retained record |
| --- | --- | --- |
| u16 source/contract/reference | 33 methods passed; one additional real IPC discovery method passed | `ba1573ed9a873400a79f7abf0ad81db3e9b38b24` and discovery follow-up; `review-evidence/hia-selfhost-u16-20261108/` |
| u16 cold replay | 11/11; nested qualification 1,215/1,215; original 180-second qualification and three-second cleanup budgets retained | Original cold/nested reports in the u16 archive |
| u16 language | 1,026/1,026 and 1,050 mathematical/reference scalar witnesses | Original language report in the same archive; finite evidence |
| Frozen C1 output fragments with corrected loader checker | Five typed conditional validations, 25 SMT obligations, 200 projection calls and 64 whole-program calls | Clean integrated `1be1f075dab01a56d43ceca286668946dbc9037b`; `review-evidence/hia-original-select-fragments-20261108/` |
| Independent fragment replay | 555 original files checked; same 25 obligations solved again, without executing a compiler or native image | Same integrated source and archive; these are not 25 additional proof obligations |
| Release/contract/lease/cohort/fragment controls | 42/42 methods passed | Frozen `1be1f075`; root integration evidence |
| Descendant observation correction | Capture and deadline regression 49/49 passed; production collector unchanged | `a3944333853926a2c20b422a84f60fd5f1daa8ad`; `review-evidence/part04-descendant-exit-20261108/` |

The five typed compiler outputs contain four distinct complete images: u64 and
usize are byte-identical. The selected intervals have two distinct byte strings.
Typed bindings and duplicate images are not independent statistical samples.

## Independent review and preserved failures

An initial integration run returned one failure and one error among 108 affected
Part04/relocation methods. The complete failed log remains retained. The
source-inode error correctly rejected an integration checkout edited while an
external-source reader was active. The complete inverse-replay method then
passed on unchanged `1be1f075`; the earlier run is not relabeled as successful.

The other failure observed a fixture descendant in `R` where the test expected
an immediate `Z`. A separate 24-run harmless fork observation found two such
transitions; both reached terminal state within approximately 2.24 ms and within
the original total deadline. The test now binds PID plus starttime and requires
that same identity to disappear or become terminal before the original
`started + 1.5 seconds` limit. This is not a general process-tree cleanup proof.

Independent u16 review found three stale NativeTests counts (824/32/240 instead
of 1050/40/300). The CLI previously did not execute those eight test methods.
The corrected CLI now applies all eight assertions to its own freshly produced
report and fails if any assertion fails, skips, or is missing. It does not build
a second compiler chain. The support lock is regenerated after this change.

## Remaining proof and value obligations

The v14 profile covers 50 ELF operation names and 40 flat-image operation names,
with u8/u16/u32/u64/usize/bool scalars. It still does not accept all legal Core
inputs. General scalar types, returned resources and multiple results, wider
module/effect behavior and general linking/targets remain outside its scope.
Fixed points and finite boundary checks do not prove a compiler for arbitrary
inputs.

The copied-fragment wrapper supplies initialized, disjoint, normalized slots.
Its proof does not establish those preconditions in every original surrounding
program, nor prove complete control flow into that interval. Whole-program
observations remain finite. The original Agent C0/C1 differ on the extension
domain; its frozen four-claim contract, strict evaluation refusal and lack of
adoption remain unchanged. Complete original provider interactions and billing
remain unavailable.

No new NDU performance or economic benefit is claimed here. In the prior exact
ffa64 campaigns, ordinary scalar controls selected the same candidate and were
faster in all 24 pairs in each retained campaign. The separate 64-pair
supplied-cost experiment in [PR #812](https://github.com/TrillionniumFoundation/Hepta/pull/812)
also does not establish incremental value. Those experiments retain their own
source identities; they are not new measurements of this candidate. Complete
model and lifecycle costs remain unestablished.

## Six-track decision

| Track | Boundary |
| --- | --- |
| Release consistency | Exact candidate CI, default-lock publication and online identity are separate gates. |
| Proof semantics | New reports retain exact subject, property, profile, assumptions, checker and unproved obligations. |
| Complete Core | u16 is implemented and finitely qualified; complete Core remains HOLD. |
| General machine correctness | Actual-output local lemmas advance; whole compiler, ABI/resources/FFI/ISA/loading remain HOLD. |
| Unfamiliar Agent task | Original strict claims, evaluation/adoption and complete provider evidence remain HOLD. |
| NDU value | Complete-cohort accounting improves; stable incremental and economic benefit remain HOLD. |

Overall acceptance remains **HOLD**. A successful exact-head CI can establish
only its actual scopes; remaining research and external-evidence obligations
cannot be closed by changing the label.
