# HIA self-rewrite audit and continuation

## Source and authorization

The product repository is `TrillionniumFoundation/Hepta`. This continuation
audited main `f50b37543d1a379353267ce0ab7111242806b8b4` and the already active
native-closure PR #888 at `93d66bcc3acb88212c9b153d7852ba22eeab24c8`.
Their exact integrated tree is `cfe5a031b99ef664ac2769b8f030fcdfb2f9f7fd`,
published as `d46b1581d8cb2bcaa052886127bb9c6412d81a9c` before this continuation's
additional changes. Both development histories are preserved.

The requested endpoint is the complete HIA-native product, followed by removal
of replaced production implementations. That removal is authorized. Remaining
functional replacements, ordinary-entry compatibility and source-matched
qualification determine when a component can be removed; no further approval
request is substituted for those engineering requirements.

**Whole HIA-native delivery remains unqualified.** No supported operation,
historical failed result, independent reference or live state was deleted to
improve a completion count. The obsolete high-level source language had already
been removed from the active product tree before this work.

## Audit coverage

The main tree was read through GitHub's complete recursive tree response
(`truncated: false`): 2,628 blobs, 1,079 Python files, 148 production Python
modules, 51 HIA assembly files and 12 Core JSON sources. These counts describe
that exact starting tree. New current counts, file bytes, digests, imports,
entry points and direct caller relationships are produced by
`tools/audit_hia_native_rewrite.py` in
`docs/HIA_NATIVE_REWRITE_INVENTORY.json`.

The audit combines this complete static accounting with source review of
compiler/nominal lowering, build/publication custody, packaging, release state,
Agent transaction ownership, current Actions and actual Runtime observation.
Static accounting does not establish semantic equivalence of every module or
prove dynamic/external caller closure. Source-file ratios cannot measure the
remaining product migration.

## Implemented in this continuation

### Build inputs and publication custody

The first audit found six standalone builders bypassing the complete current
source admission used by the shared builder. Some accepted JSON `false` or
`0.0` as a successful zero return code, and SHA/identity builds could accept
the same compiler image with an unrelated source qualification. The expanded
audit also found outer packers and nested manifests absent from final readback.

The repaired paths require the current profile, exact integer zero, all eleven
cold checks, all three compiler generations, the complete current source map
and exact selected asset bytes before starting a build. Publication rechecks
frozen source/compiler/report inputs, complete source identities and the
captured application, packer and nested manifest bytes where applicable.
Existing independent deadline and cleanup limits remain in force.

The new custody tests use explicitly labelled recording compiler/packer stubs.
Their observations establish admission and publication checks, not execution
of HIA machine code. Actual application and cold tests retain separate gates.
Original failing controls and the post-reset reexecution remain distinct.

### Complete enum-match control-flow generation

[The native enum-match owner](HIA_ENUM_MATCH_NATIVE.md) consumes lossless
resolved descriptors and the existing nominal environment. HIA performs case
validation, exhaustiveness, linear transfer, target admission, carry alias
deduplication, inactive-owner cleanup, fresh-name accounting and complete Core
CFG generation. The selected ordinary elaborator copies the complete result;
it does not invoke the retained match implementation on a refusal.

Composite v1 still lowers to primitive v6, v2/v3 to v7 and v4 to v8. Type
resolution, other nominal operations, function aggregation, the general
backend and installation remain separate owners. Correctly checking generated
Core is necessary but insufficient: the tests also compare exact normalization,
independent results, resource effects and refusal/counter behavior.

### Native release selection and rollback

[The native release-selection application](HIA_RELEASE_SELECTION_NATIVE.md)
adds explicit status, activation and previous-version rollback to the existing
immutable installer. A mutation requires the exact observed sequence and
current release, fully verifies the target with the actual installer policy,
serializes cooperating writers with a kernel-owned lock, publishes a bounded
checksummed record atomically, synchronizes it and reads it back.

Status can resolve the current selection after a lost receipt or restart. It
does not invent an original request identity or prove that a previous caller
received acknowledgement. Existing immutable releases are not overwritten.
The program uses HIA policy and packing with an explicit fixed Linux syscall
adapter; authoring and initial build custody remain hosted. It does not migrate
the ordinary Agent journal or change the default CLI or live service.

An independent review found that the first development image accepted surplus
empty arguments on `status`; the actual-argc check and regression fix retain
that original observation. Cloud ptrace refusal is recorded as an environment
failure, with actual syscall fault controls required on a capable host.

## Remaining production owners

| Owner | Current responsibility | Requirement before retirement |
| --- | --- | --- |
| Nominal elaborator | Record/partial-record and ordinary operation lowering, nominal SSA, calls/edges/returns, final origin binding and exports | Complete HIA producer with retained four-schema meaning, result, refusal, resource and state controls |
| General compiler/backend | Retained profiles beyond the selfhost compiler's bounded arguments/results/functions/blocks, target and object/linking support | Native producers for every retained profile and independent target execution |
| `HIAAgentService` | Eleven-tool authority, contexts, verification, emission/evaluation, adoption and rollback | Complete ordinary native request/report/service behavior and installed identity |
| `AgentStore` | SQLite/WAL, namespaces/refs, intent/completion, costs, slots, versions, leases and uncertain operations | Native transaction/state owner with same-key conflict, crash/restart and original-operation continuity |
| Worker and object bridge | Installation admission, foreign object custody, service dispatch and report serialization | Native complete worker protocol with actual code/profile pins |
| Default CLI/project build | Fifteen installed CLI actions, module/library orchestration and Python package hooks | Equivalent ordinary native entry and clean-machine build/install/recovery |
| Bootstrap/authoring | Hosted seed generation, application builders and source generators | Explicit bootstrap trust root and reproducible native successor build ownership |
| Release lifecycle | Service activation, active process/version references, administrative stage recovery and reference-aware retirement | Observe original effects and migrate/recover supported consumers before removing old files |
| Runtime/library/proof | Retained execution/library owners and scoped proof computation | Native replacements preserving proved/refuted/unknown/timeout and target semantics |
| Deployed HeptaRuntime | Separate Rust MCP/process owner and separately pinned worker | Real native worker ABI parity, installation, old-operation continuity and observed cutover |

The complete primitive checker and the native compiler have different admitted
profiles. The current selfhost compiler's 16 parameters, three results, 128
functions and 256 blocks per function are not a qualification for every legal
normalized program. Original/modified compiler fixed points are finite-profile
evidence, not whole-language soundness or a full native product certificate.

## Observed deployment blocker

A live manifest request returned `HIA_OBSERVATION_UNAVAILABLE`. The exact
original operation was then read through process status and bounded output;
it is terminal with exit code 127 and a missing operator-pinned Python
interpreter (`ENOENT`). Its stdout/stderr are empty. This is an actual failed
launch of the retained deployment, not successful native first use and not
evidence that changing a source repository automatically updates the worker.

The full private operation record remains in the runtime's original custody.
No new request key, substituted installation pin, cleared store or restarted
service was used to turn that failure into a successful observation.

## Qualification and retirement rule

The common profile for these changes is
`selfhost-core-linux-x86_64-v64-native-match-selection-build-custody`.
Its generated source closure must be frozen before cold replay, language and
native applications run. A previous compiler hash, green older workflow or
development image does not qualify this combined source.

For each production owner, retirement requires the complete replacement,
ordinary installed caller use, matching source qualification and relevant
recovery/compatibility controls. Independent reference implementations remain
test or research evidence until their own scope is deliberately resolved;
their existence is not an automatically selected production fallback. Git
history is retained. The final product flags remain false until the complete
ordinary chain passes, including actual deployed first use.
