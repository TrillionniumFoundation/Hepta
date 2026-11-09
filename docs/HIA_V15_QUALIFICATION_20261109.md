# HIA v15 qualification and remaining acceptance gates

The bounded v15 source qualification passed: cold self-host replay, language
coverage, and the current checked-in compiler's borrowed-buffer lifecycle all
completed successfully on one clean, frozen source tree. The six-outcome
acceptance remains **HOLD**. General Core self-hosting, general machine-level
correctness, a new unfamiliar-Agent task with complete provider evidence, and
stable NDU or economic value are not established by these results.

The current public installation also passed a fresh, scoped identity readback.
That observation concerns the already selected `2598f430...` source, not this
v15 candidate. v15 has not been qualified as the installed public service by
this report.

The machine-readable companion is
[qualification-summary.json](../review-evidence/hia-v15-qualification-20261109/qualification-summary.json).
It separates measured source identities, final successes, earlier failures,
preservation limits, and the later clock-fixture test result.

## Exact source and artifact binding

| Identity | Value |
| --- | --- |
| Measured clean local commit | `b11d86085fba8084434ef5755eaea0794541f342` |
| Corresponding public commit | [`e6edab930cceb1216af2a0e2f27878e996879ad3`](https://github.com/TrillionniumFoundation/Hepta/commit/e6edab930cceb1216af2a0e2f27878e996879ad3) |
| Identical Git tree | `5e19c009c81acc86025c81a3dbdab14a4346b80f` |
| Compiler profile | `selfhost-core-linux-x86_64-v15` |
| Compiler source | `examples/hia_bootstrap/selfhost.hiaasm` |
| Compiler source SHA-256 | `db9887401876766ca699691772a7f2248bb319481b80c95dc90d202bc9280af4` |

The public commit's tree was independently read and matched the measured local
tree. The different commit identifiers do not substitute an untested source:
the complete tree is identical. All three final native stages ran serially,
with a clean source checkout before execution and after every stage. The
original internal time and resource limits were preserved.

The [v15 support contract at this exact public source](https://github.com/TrillionniumFoundation/Hepta/blob/e6edab930cceb1216af2a0e2f27878e996879ad3/docs/HIA_SELFHOST_CORE_SUPPORT.json)
defines the applicable syntax, scalar types, resource rules, target, and
capacity bounds. Its support declaration is not itself execution evidence or
a compiler-correctness theorem.

## Final local qualification

| Stage | Result | Observed checks | Wrapper wall time |
| --- | --- | --- | ---: |
| Cold source replay | `COLD_SELFHOST_REPLAY_PASS` | 11/11 outer checks; nested `SELF_HOSTED_FIXED_CORE_PASS`, 1,215/1,215 checks; 20/20 phases; zero exceptions | 94.594995679 s |
| Language coverage | `SELFHOST_LANGUAGE_COVERAGE_PASS`, CLI exit 0 | 1,196/1,196 native checks and 10/10 report assertions; no error, failure, or skip | 88.164416721 s |
| Current v15 compiler lifecycle | `PASS_SCOPED_NONPRODUCTION_LIFECYCLE` | 25 worker calls; six independent consumer processes; three consumer runs; state reopened for each operation; identical adoption replay | 89.350469815 s |

The cold replay retained its 180-second qualification deadline and three-second
cleanup allowance. Language coverage exercised both B3 and M3 compilers. Each
compiler handled 112 positive programs, 277 rejected inputs, and 206 trapping
inputs: 150 checked-arithmetic traps, 36 checked-cast traps, and 20 shift traps.
The scalar witness count was 1,183.

The lifecycle result's exact acceptance scope is:

> same frozen Core activation; exact buffer workload, owned local worker and consumer generations only

It verifies the current compiler under that local lifecycle. It does not
constitute a new unfamiliar-Agent study, production adoption, remote endpoint
qualification, complete provider billing, or universal compiler or machine
refinement. The report retains `full_cost_complete=false`,
`full_provider_interaction_available=false`, and null provider fees and tokens.
No consumer authority-state contents are included in this public summary.

The [source workflow](https://github.com/TrillionniumFoundation/Hepta/blob/e6edab930cceb1216af2a0e2f27878e996879ad3/.github/workflows/hia-sixgap-source.yml)
preserves the earlier frozen-compiler lifecycle step and adds a separate
current-compiler step. The latter derives the SHA-256 of the checked-in
compiler, passes it to the same lifecycle qualifier, and writes separate
output and logs. This report records the local observations above; it does
not claim a CI result that has not been observed for a later head.

## Current public installation readback

A distinct formal-connector describe request completed after an earlier
same-argument timeout. The retained read response was bound to the exact
manifest digest and checked using the checker from the pinned public source.
The checker exited zero. Worker, backend, and catalog digests all matched the
public release lock.

| Public selection | Commit |
| --- | --- |
| Hepta | `2598f4309791d3a023cd5df585ad26810b20c744` |
| Runtime | `4cd85c99c5f5a480832c48fbde8561bb365f67a9` |
| Release lock SHA-256 | `9000d6eaa089f6bed92ea07a6561d91381a6f913263f0b1016d4f99e8789c1d3` |

This closes the captured worker/backend/catalog identity readback for that
current selection. It does not establish runtime executable provenance,
source-only loading, continuous availability, a later installation state,
or installation of v15. The separate
[installation check](../review-evidence/hia-v15-qualification-20261109/current-public-installation-check.json)
and [observation receipt](../review-evidence/hia-v15-qualification-20261109/current-public-installation-observation.json)
retain the exact scope and capture bindings.

## Earlier attempts remain part of the record

These are the attempts made during this v15 source-integration sequence. A
later success does not change an earlier failure or its preservation status.
Previously committed historical studies and their failures retain their
original source and scope.

| Source and attempt | Actual outcome | Preservation |
| --- | --- | --- |
| `7584bc3b758520b61d2bec350b7529a9b2fb5956`, first cold replay | Failed after 68.408425888 s with `ENOSPC`; 6/11 outer checks. It was not a deadline timeout; process cleanup completed. | Complete original archive retained. |
| Same `7584bc3b...` source, recovery cold replay | Passed after 95.223993072 s: 11/11 outer and 1,215/1,215 nested checks. Only clean, fully committed task worktrees were removed to recover space; the failed record was retained. The 180+3-second limits were unchanged. | Separate complete original archive retained. |
| Same `7584bc3b...` source, first language run | Native report passed 1,196/1,196 checks, but the CLI exited 1 after 89.058235353 s: only 9/10 report assertions passed. The expected scalar count was still 1,050 while the report contained 1,183. | Complete original archive retained. This is not recorded as a successful CLI qualification. |
| `49904f90a0ada6c8063208bd8d5e4b2cb3ea16be`, first cold replay on that source | Failed after 79.480402455 s. The child returned `-9` (SIGKILL), `timed_out=false`, and cleanup completed. The outer wrapper returned 1 with 6/11 checks; 11/20 phases were observed complete. | Outer/process-owner report, attempt receipt, and logs survive. The unarchived temporary raw directory was lost during environment recovery. Original raw preservation is **incomplete**. |
| `b11d8608...`, final serial qualification | All three stages in the final-results table passed on their first attempt for this exact source. | Complete final archive retained. |

The count correction in `49904f90...` changed the stale expectation to
`1050 + 125 + 8`: 125 checked-cast witnesses are five source types times five
target types times five boundary values; eight Boolean equality witnesses are
two operations times four truth-table inputs. The support pin was regenerated
after the correction. The original 9/10 failure remains available.

The SIGKILL cause is unconfirmed. Available resource observations do not
uniquely establish an out-of-memory kill. The execution service then became
unavailable; restoration preserved the workspace reports but reset temporary
storage. No archival or cleanup action had completed for that temporary raw
directory before the outage. This report does not reconstruct missing raw
files or treat an incomplete attempt as fully preserved.

### Complete retained archives

For each of these four archives, every original member's SHA-256 was checked
after decompression. Each source file was reread and checked before its
expanded copy was removed. The member counts below count original files;
each ZIP additionally contains its archive manifest. These are preservation
receipts, not a claim that the full raw archives have been publicly published.

| Archive | Archive bytes | Original files | Original bytes |
| --- | ---: | ---: | ---: |
| `cold-enospc-7584-originals.zip` | 18,043,393 | 5,383 | 540,460,412 |
| `cold-recovered-7584-originals.zip` | 26,601,643 | 12,620 | 1,042,221,054 |
| `language-count-failure-7584-originals.zip` | 14,168,298 | 11,645 | 700,801,511 |
| `b11d-final-originals.zip` | 32,273,154 | 24,452 | 1,748,389,226 |

| Archive | SHA-256 |
| --- | --- |
| `cold-enospc-7584-originals.zip` | `40daa53b6a71299f4df3e31c1986b5edb21ed1ac46dd4b654956970d119e49c2` |
| `cold-recovered-7584-originals.zip` | `43c77077b988b4b9d47f75307816147586d4afe38244ae304e7f0de3bce2dc3b` |
| `language-count-failure-7584-originals.zip` | `a8e32cda8b92344461019b1c6afede08716fd09373d20b444fc102121903fc33` |
| `b11d-final-originals.zip` | `4d37521b4dc234a4f27468d7449a2a03ccbd9b804f28cbc50586f4846583f5f4` |

This public report includes hashes, counts, and curated outcomes. It does not
include private connection details or authority-state data. The failed
`49904f90...` temporary run has no complete original archive and is not included
in this four-archive list.

## Clock-fixture follow-up has separate qualification

A follow-up patch corrects test clock-origin accounting in
`tests/test_core_seven_relocation_runner.py` and
`tests/test_core_seven_relocation_timeout.py`. Its SHA-256 is
`704dabae16530f090c47470c994d081c781ba13b99d272b705e8fcbc1d12b206`.
It changes no compiler or production file and preserves the production
60-second operation deadline and two-second cleanup budget.

The isolated overlay using `b11d8608...` dependencies passed the three existing
`RelocationTimeoutTests` methods in 35.834 s, with zero skips. The pre-output
test gained a third real subcase with a five-millisecond entry pause; pure
clock controls cover zero-, five-, and fifty-millisecond pauses. Class-level
test-method counts remain 23/8/2/3 for `Part04RunnerTests`,
`Part04ReplayGrammarTests`, `RelocationNumericBoundsTests`, and
`RelocationTimeoutTests`. The documented 23-test runner count remains correct.

The [fixture receipt](../review-evidence/hia-v15-qualification-20261109/clock-fixture-qualification.json),
[deterministic controls](../review-evidence/hia-v15-qualification-20261109/clock-fixture-deterministic.json),
and [targeted log](../review-evidence/hia-v15-qualification-20261109/clock-fixture-timeout.log)
support only this test-fixture result. No full native qualification or full
suite was rerun for the patch. The native results in this report remain bound
to tree `5e19c009...`; a later fixture-only head must record its own source
identity and subsequent CI results without claiming those original native
runs occurred on the later tree.

## NDU result remains a scoped negative finding

The historical [same-pool scalar-control result](HIA_NDU_SCALAR_CONTROL_RESULTS_20261108.md)
retains all 64 registered pairs. Every pair selected the same specified
candidate. NDU was faster in **0/64** pairs. Ordinary complete-call wall time
totaled **4.460608 ms**; native NDU totaled **938.923222 ms**. The paired
Ordinary-minus-NDU median was **−11.809995 ms**. No failed call, sample, warmup,
or pair was removed. There were 128 selector calls, including 64 actual native
calls, and zero model calls.

Those measurements belong to local source
`55fe9e39a3b2c5a1d17536f9f83394f37feb48e0`, public source
`e6cb3f8bd29db14aca786c807e1231844c6ce927`, and their identical tree
`da298c2a04aa27f1f56a7a3a64eef66340dbddfb`. They were not collected on v15.
The original frozen plan and archive remain unchanged. Subsequent defensive
evidence validation passed 15 tests with zero skips and independently replayed
128 scheduled cells and 307 objects without new native or provider calls.
The stricter validator checks the frozen schedule prefix and stop-on-failure
rule, interval containment, and exact nonnegative accounting.

The measured campaign interval was 1.423365758 s: 0.943383830 s in selector
calls and 0.479981928 s in admission, capture, export, and offline checks.
Nested timings are not added again. Source acquisition, compilation,
authorship, final summary writing, upload, and monetary costs lie outside that
interval. Complete lifecycle and economic costs are still unknown.

This single-axis profile gives both controllers the same conservative scalar
cost and tie rule; the ordinary minimum and native frontier therefore choose
the same candidate. The result establishes overhead for this profile, with
no observed downstream choice improvement. It does not establish universal
NDU impossibility. These repeated same-host invocations are not independent
task or training samples. The older four-pair authored-task findings, failures,
and unknown fees remain part of the record. A future version needs a newly
frozen plan, matched task quality, a strong direct-value control, and complete
cost accounting; repeating or filtering these original pairs cannot establish
incremental value.

## Provider attempt and remaining gates

The provider attempt previously marked `UNKNOWN` was reconciled to a failed
request: the inherited `gpt-6.1-sol` model was unsupported for this account;
the response was `model_not_found`, with process exit 1 and observed wall time
23.529 s. It did not complete a task. Fees and tokens remain null; absence of
a successful task is not evidence of zero monetary cost. The sanitized
[reconciliation receipt](../review-evidence/hia-v15-qualification-20261109/provider-reconciliation.json)
binds the original request, complete 795-byte stdout and 114-byte input, CLI,
driver, cleanup result, and preserved prior UNKNOWN observation. No new
provider request was generated during reconciliation. Private connection
context is excluded.

The original unfamiliar-Agent select extension also has a distinct semantic
obligation: its baseline rejects programs that its candidate accepts. Unconditional
whole-input equivalence would therefore be false. A valid extension contract must
separately establish preservation on the old accepted domain and correctness on
the newly accepted domain. The same-Core lifecycle here does not prove either
claim for that original change, and a later provider trial cannot replace the
original missing interaction or billing records.

| Acceptance area | Established result | Remaining boundary |
| --- | --- | --- |
| Release consistency | Current selected `2598f430...` worker, backend, and catalog identities match the exact public lock. | v15 public installation and readback remain to be observed for the candidate. |
| Proof semantics | Results in this report are tied to exact source, artifact, profile, observation, and assumptions. | No unrestricted security or compiler-correctness claim follows. Existing proof results remain confined to their own subject, property, checker, profile, and assumptions. |
| Complete Core self-hosting | The bounded v15 profile passes cold and language qualification and includes all 50 operation names in its bounded ELF coverage. | General Core types and result shapes, module graphs, identifiers, effects and resource combinations, returned loans, and general object linking remain outside the implemented profile. |
| Machine-level proof | Finite native observations and earlier scoped proof artifacts retain their exact bindings. | General compiler, ABI, FFI, allocation, resources, full ISA, and loading correctness remain unproved. No new machine theorem is established by this report. |
| Unfamiliar-Agent real task | The current compiler completes a scoped local lifecycle with independent consumer processes. | This remains the same frozen Core task. A new unfamiliar-Agent task, successful supported-provider interaction, complete provider records and bills, and production adoption remain open. |
| NDU and economic value | Original same-input controls and strict offline evidence replay are retained. | Stable incremental task value and economic benefit remain **HOLD**; 0/64 scalar speed wins and unknown complete monetary cost remain the observed result. |

The v15 support contract explicitly retains
`compiler_correctness_formally_proved=false`,
`whole_HIA_language_self_hosted=false`,
`native_execution_is_security_sandboxed=false`, and
`support_declaration_is_execution_evidence=false`. Operation-name coverage and
finite native success do not remove those boundaries.
