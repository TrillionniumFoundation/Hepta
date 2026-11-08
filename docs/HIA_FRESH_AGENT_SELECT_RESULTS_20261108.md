# HIA fresh-agent `select` maintenance: factual record

**Record date: 2026-11-08. Status: frozen functional study; lifecycle and complete-cost acceptance remain open.**

A separately registered agent implemented scalar `select` in the actual HIA self-host compiler, retained a repository patch, ran native language and cold self-host checks, and supplied a C consumer that compiled and executed a new program on six varying inputs. Lifecycle adoption and complete interaction/cost accounting remain incomplete. This record derives those findings from the frozen study documents and a separately retained post-freeze verification receipt. It does not claim a complete provider transcript or a universal compiler theorem.[^registration][^report][^summary][^postfreeze]

The machine-readable companion is [fresh-select-summary.json](../review-evidence/hia-sixgap-20261108-c184/fresh-select-summary.json). The [original prompt](../review-evidence/hia-sixgap-20261108-c184/fresh-learner-public/PROMPT.txt) is copied byte for byte. The companion identifies every source document by SHA-256 and byte count. Retained raw evidence is named below; this public factual record does not itself distribute the entire native-evidence archive.

## 1. Registration, public starting point and isolation limits

The registration specifies `fork_turns = "none"`, no inherited parent transcript, no CLI credential use, and a functional repository-maintenance task. The agent was instructed to start with public release/discovery documentation, identify the pinned language/ABI/assumptions, and work only in its assigned directories. The preparation record reports that no previous solution or trial result was included in the learner tree. These facts establish the registered context and supplied inputs. They do not establish that the agent had no prior general knowledge of the project.[^registration][^preparation][^prompt]

| Public identity | Value |
|---|---|
| Repository | [TrillionniumFoundation/Hepta](https://github.com/TrillionniumFoundation/Hepta) |
| Task source commit | [`d1c97d22d503b395ba9b0dfaa87e5a1c1b208fe6`](https://github.com/TrillionniumFoundation/Hepta/tree/d1c97d22d503b395ba9b0dfaa87e5a1c1b208fe6) |
| Task source tree | `5e16f76e52f2b44d84b926161333bdfa94671e5f` |
| Release entry assigned in the original prompt | [Entry at `93ef29d57090f62ffe71d7d05c5f40d0721f046f`](https://github.com/TrillionniumFoundation/Hepta/blob/93ef29d57090f62ffe71d7d05c5f40d0721f046f/docs/HIA_RELEASE_ENTRY.md) |
| Corresponding merged public entry | [Entry at `df70e807be715819570ddef4e9caa9cf4d5ba0f1`](https://github.com/TrillionniumFoundation/Hepta/blob/df70e807be715819570ddef4e9caa9cf4d5ba0f1/docs/HIA_RELEASE_ENTRY.md) |
| Source-language documentation | [Self-hosting Core](https://github.com/TrillionniumFoundation/Hepta/blob/d1c97d22d503b395ba9b0dfaa87e5a1c1b208fe6/docs/HIA_SELF_HOSTING_CORE.md) and [support contract](https://github.com/TrillionniumFoundation/Hepta/blob/d1c97d22d503b395ba9b0dfaa87e5a1c1b208fe6/docs/HIA_SELFHOST_CORE_SUPPORT.json) |

The original prompt used the `93ef29…` entry. The coordinator separately verified that this entry and the merged `df70e807…` entry have the same tree, `6313534639fecb3041347bb38d04127b35c0835a`, and the same entry content. That observation is recorded as coordinator provenance; it does not rewrite the original prompt.[^coordinator]

The supplied working tree contained **228 public source files**, materialized using the original public CI closure and independently fetched public GitHub Git data. The preparation record reports verified commit, tree and blob objects and a clean initial Git status. This was an exact Git-object materialization of a sparse source closure. **A full public cold clone was not performed.** The directory restrictions were instructions to the agent; they were not an operating-system sandbox.[^preparation][^prompt]

The later cold self-host replay used a fresh source export, HOME and Python processes without inherited seed images or bytecode caches. It still shared the host CPython executable/standard library, GNU ld, libc, Linux and hardware. Its isolation claims concern source, processes and caches.[^report]

## 2. Requested change and frozen independent implementation

The task required `select(bool, T, T) -> T` for the existing scalar types `u8`, `u32`, `u64`, `usize` and `bool`. True selects the second argument; false selects the third. Bad arity, non-boolean conditions, mismatched scalar types and resource selections must be rejected. The existing grammar, ABI, resource rules, capacities and other operations were to be preserved.[^prompt]

The frozen implementation appends the select token without changing earlier token numbers and adds an HIA helper for admission and machine emission. It checks the three operands and matching scalar result, loads the condition and alternatives, and emits a conditional move. The first inline implementation exceeded the existing per-function SSA limit. Moving the logic to the appended helper resolved that failure without increasing the limit.[^report]

| Frozen independent artifact | Identity |
|---|---|
| Profile recorded by the study | `selfhost-core-linux-x86_64-v6` |
| Patch | `select.patch`, 129,164 bytes |
| Patch SHA-256 | `e74f3c27d6ea7e7ccfc1c9e2a4e7674fecabef08ee0e05236e5a6e2b5bd75cb4` |
| Generated HIA compiler | 293,775 bytes; 45 functions; 1,152 blocks; 3,177 operations |
| Compiler source SHA-256 | `2dd847d9df46392e4ef4b99c781b45f56c9841ae61127a260be6e8523f042845` |

The eight changed files are the generator, generated HIA assembly, support-contract generator, two self-host test files, the generated support and coverage JSON files, and the self-hosting documentation. The companion carries the exact before/after identities from `change-manifest.json`. The independent study made no commit, push, deployment, production change or service adoption. Its original profile label remains **v6** in this record. The profile string alone does not identify the changed compiler; the source and patch digests bind this result.[^manifest][^summary][^report]

## 3. Original validation results

| Validation | Recorded outcome | Retained evidence name |
|---|---|---|
| Native language qualification | **298/298** checks; B3 and M3 exercised | `select-language-native.json` and its evidence directory |
| Cold self-host replay | **10/10** outer gates | `cold-replay-final.json` |
| Nested cold qualification | **189/189** checks | `cold-replay-final.cold/qualification.json` |
| Separate native C consumer | **6/6** varying inputs returned the expected full-width results | `042-run-native-consumer.stdout` |
| Original broad regression attempt | 34 tests: 33 passed and one stale witness-count assertion failed | `043-full-regression-suite.stderr` |
| Final focused language/contract suite | **12/12** passed | `051-final-focused-tests-and-contract.stderr` |
| Additional source assertions | 15 assertions passed before an included cold test hit the outer timeout; the overall command failed | `048-final-source-regressions.stderr` |

These results are recorded in the frozen report and summary.[^report][^summary] The broad-suite success recorded after freezing is reported separately in section 5.

The language qualification contains **608 scalar witnesses**, including 40 new select witnesses. Each of B3 and M3 receives 41 positive program/input fixtures, 89 rejection cases and 16 checked-shift trap cases. The positives include 28 dynamic select observations: five vectors for each of the four integer types and all eight boolean combinations. Outputs retain all eight result bytes, so high `u64`/`usize` bits cannot disappear behind the function's `u32` return. Thirteen select-specific refusals cover invalid forms. The general Core VM supplies independent reference observations.[^report]

The earlier count of 568 witnesses was changed to 608 because 40 cases were added. The final assertions also require eight select cases per scalar type, both condition values, the complete boolean truth table, and changing input/output observations from unchanged source text. The stale-count failure remains in the record.[^report]

### Cold generations

| Artifact | SHA-256 |
|---|---|
| B0 seed | `1e4b539bc07cfca7901db7f105061f7fc595edbb2b80967cf0fef003b152337e` |
| B1 = B2 = B3 | `f7dcf41864bb22793a60d12daace55ea35143733c536db7bf13f35b15efd4110` |
| M1 | `3b0b13effc06835c4d366efd89218b01240439f818cafb1cc684c430dd665325` |
| M2 = M3 | `d130d01d518cc80f7de2e18a1a08119f03658a3490d0664ae087c27b7cf1fd5a` |

The frozen records report the equal successor fixed point and a distinct mutation fixed point: `M1 != M2 == M3`, with `M3 != B3`. The final cold export contains 227 declared source files plus the support contract, and reports matching origin/export hashes. These are finite observations for the identified compiler and environment.[^summary][^report]

## 4. Separate native consumer

The C consumer was built with GCC using `-std=c11 -O2 -Wall -Wextra -Werror`. It mapped the exact B3 image, invoked the compiler with new HIA source and separate output/workspace allocations, retained the resulting 1,597-byte image, then executed that image on six inputs. No Python compiler callback was involved in those consumer executions.[^report]

| Input bytes | Observed selected `u64` | Observed `u32` return |
|---|---|---:|
| `0, 1, 2` | `ffffffffffffff02` | 4294967042 |
| `1, 3, 4` | `8000000000000003` | 3 |
| `255, 255, 128` | `80000000000000ff` | 255 |
| `0, 0, 255` | `ffffffffffffffff` | 4294967295 |
| `1, 0, 255` | `8000000000000000` | 0 |
| `0, 254, 0` | `ffffffffffffff00` | 4294967040 |

The recorded compiler call took 9,294,810 ns; the outer consumer command took approximately 0.0133 seconds. These are individual timing observations. They do not establish a performance advantage or a controlled comparison. Consumer source, executable, input-program and emitted-image SHA-256 identities are retained in the machine-readable companion.[^report][^summary]

## 5. Post-freeze broad-suite verification

A separately retained follow-up reran the previously selected broad unittest suite. Its recorded stdin is identical to the original selected suite's stdin, with SHA-256 `70df5de60d3176ac9b829e3de6934d3608187092f410f54f64ff2db8aa86db83`. It ran **35 tests successfully**, returned zero and did not time out. The outer suite wall time was **118.52228342600574 seconds**; unittest reported 118.349 seconds. The follow-up reports that the patch, protected original files, and repository HEAD/tree/status remained unchanged.[^postfreeze]

This is an extension of the original study. It is **not counted as completion within the original prompt's 20-minute goal**. No additional standalone cold-chain invocation was made in this follow-up. The rerun resolves the final broad-suite coverage gap; it does not recover missing historical timing, stdin or deleted temporary evidence, and does not complete lifecycle adoption.[^postfreeze]

The follow-up also retains a separate orchestration failure: `functions.exec` rejected JavaScript with `SyntaxError: Unexpected number` before any shell subprocess or filesystem action. The recorded cause was unescaped Markdown backticks in a JavaScript template literal. The tool-reported 0.0 seconds is a tool observation, not a fee or complete cost measurement. This parser failure remains separate from the successful 35-test suite and from the original compiler/test failures.[^setupfailure]

## 6. Failed attempts, recording gaps and costs

The frozen report preserves five nonzero outer command results:[^report]

| Original command | Failure retained in the report |
|---|---|
| 25 | Initial source/native regressions: inline SSA capacity exceeded and new fixture/count issues |
| 28 | Explicit first cold replay failed from the same SSA-capacity cause |
| 39 | C compilation rejected misleading indentation under `-Werror`; formatting was subsequently corrected |
| 43 | Stale assertion expected 568 witnesses after the implementation added 40 |
| 48 | The 60-second outer timeout expired after the source assertions passed and a cold replay started |

Original outer stdout/stderr and failure status remain recorded. The report also identifies evidence that was not captured completely: recorder-bootstrap elapsed time and exact argv, exact timing for the first prompt read, heredoc stdin before command 37, and some nested temporary evidence removed by stock temporary-directory cleanup during the initial failure and interrupted replay. The later successful follow-up does not fill those historical gaps.[^report][^postfreeze]

The known sum of recorded outer command wall times through original command 52 is **364.1093976650591 seconds**. The post-freeze receipt separately reports **118.60313848900842 seconds** for its recorded commands, including the broad suite above. These measures have different scopes and are not reported as complete task latency, total labor, provider usage or a bill.[^summary][^postfreeze]

| Accounting field | Recorded value |
|---|---|
| Model tokens | `null` — unavailable |
| Model cost / provider fees | `null` — unavailable |
| Provider internal HTTP-call count | `null` — unavailable |
| Complete provider interaction transcript | Unavailable |
| Complete task wall time | Unknown |
| `full_cost` | `false` |
| `full_cost_complete` | `false` |

The command journal is self-maintained. It is not an independently complete interaction or provider transcript. This registered functional task is separate from the external CLI cost experiment. The two `model_not_found` CLI attempts belong to that other experiment; they are not included in this study's results, failure counts or cost totals.[^registration][^prompt][^coordinator]

## 7. Scope of the evidence and lifecycle refusal

| Scope field | Meaning in this study |
|---|---|
| Subject | The frozen `select.patch`, exact checked HIA compiler source and identified native generations/consumer artifacts |
| Property | Core syntax/type/resource admission, finite observed select behavior and rejection cases, repeated successor and mutation fixed points, and observed separate-consumer execution |
| Profile | The independently recorded `selfhost-core-linux-x86_64-v6`, Linux x86-64, SysV AMD64; compiler entry `f0(readbuf, mutbuf, mutbuf) -> u32`, represented by six machine ABI words |
| Assumptions | Published source/output/workspace and execution limits; live, private, disjoint caller allocations; no concurrent source mutation or escaping buffers; the recorded loader, CPython seed, GNU ld, libc, Linux and hardware |
| Checker identity | The frozen lifecycle assessment binds assembly, Core checker, opcode catalog, runtime, service and independent native checker source hashes; the companion reproduces those identities |
| Unproved obligations | Universal compiler correctness, arbitrary-input termination, whole-language support, complete Core-to-machine semantic refinement, and compatible lifecycle adoption |

`assemble_program` produced a `VerifiedProgram` for source admission. The native results are empirical observations under the listed assumptions. No solver result or theorem of universal compiler correctness is claimed.[^report][^lifecycle]

**Acceptance item 5 remains incomplete.** The actual independent compiler has 45 functions and a three-buffer entry ABI. The public lifecycle scalar-entry filter excludes `f0`; its only returned scalar entry is the unrelated helper `f32`. The independent refinement profile's actual refusal was:[^lifecycle]

```text
SafeCoreRejected: E_HIA_SAFE_CORE: Safe Core admits exactly one primitive function
```

The service's documented refinement path requires a retained shared artifact with scalar entries and excludes foreign-buffer exports for that path. The independent checker's lower-level borrowed-range provisions also do not admit this 45-function, three-buffer compiler. The compiler successor is a flat image with a buffer ABI. No compatible service endpoint or dedicated nonproduction slot was exposed; the adoption receipt is `null`. The local refusal and local consumer success are recorded as those observations, without a service-adopted claim.[^lifecycle][^report]

| Acceptance item | Status after the supplied follow-up |
|---|---|
| 1. Real patch and exact identity | Complete |
| 2. Native behavior and boundary evidence | Complete |
| 3. Cold self-host replay and closure | Complete for the explicitly supplied sparse source closure |
| 4. Separate native consumer | Complete |
| 5. Compatible HIA lifecycle verification/measurement/adoption | Incomplete |
| 6. Command/test evidence and explicit accounting/proof limits | Partial; historical recording gaps and unavailable provider data remain |

These statuses preserve the original acceptance limits and the follow-up's remaining-unmet list.[^summary][^postfreeze]

## 8. Later coordinator integration is a separate result

After the independent patch froze, the coordinator combined it with separately reviewed integer operations, proof-scope and packaging work. That combined candidate uses **v8**, declares **28/50 operations**, and reports **456/456** local language checks. Those figures belong to new combined-source qualification. They are not inherited from, or substituted for, this independent study's **v6 / 298 language checks / 189 nested cold checks / six consumer inputs**.[^coordinator]

At the drafting cutoff, final same-head CI, a public entry for that combined candidate, and production adoption had not been established. The earlier merged `df70e807…` entry remains the public d1 starting point described above. This record does not use a later integration to retroactively complete the independent lifecycle or cost acceptance items.[^coordinator]

## Preserved archive and integration failure

The [original repository patch](../review-evidence/hia-sixgap-20261108-c184/fresh-select.patch) is retained byte for byte. A separate private evidence archive preserves the original functional outputs and inputs: 97,932,338 bytes, SHA-256 `22046fb974628e2ac57f1f4fc6807033fb6231e55625ef9966fe8e6b1229831d`. Its 14,802 ZIP entries passed CRC verification, and 14,698 extracted regular entries passed SHA-256 and disk-readback checks. The six known test-fixture symlinks were preserved only as metadata; their targets were never followed. Archive creation and verification are separate preservation work, outside the original task budget. Retaining this archive does not recover the historical recording gaps listed above.

The later combined candidate `0b82ad16db4df026a995ddc12a29f5d2a98cffb9` had an [actual source CI failure](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42493458747): one of 83 Agent-native tests still expected the old v6 discovery profile. The other 82 tests and 173 direct-native checks passed; the remaining source stages were skipped. The [failure record](../review-evidence/hia-sixgap-20261108-c184/source-0b82-failure.json) and original CI artifact preserve that result. A successor qualification cannot change this failed attempt or the independent study results.

## Source-document fingerprints

The original files below were read as frozen evidence. Full SHA-256 identities and byte counts are also present in `fresh-select-summary.json`. Original local absolute paths and private storage identifiers are not reproduced in this Markdown or the summary. The accompanying prompt remains an unmodified historical input and therefore retains its original execution-directory wording.

[^registration]: `fresh-learner-preparation/REGISTRATION.json`, SHA-256 `39fe61e65b4d55fe0e166df8aaaebfb6af3f88694a15df096c797fda72b8a69f`.
[^preparation]: `fresh-learner-preparation/SOURCE_PREPARATION.json`, SHA-256 `9796879986f65e30811cd1e3eb8a0996cdf4a5ff3156d8ea8f4510075b30e5ab`.
[^prompt]: `fresh-learner-public/PROMPT.txt`, SHA-256 `b405cd565c20d4acfd1f84eb8de94ef2eddd54fc3c876fd433393dc1a3347af1`.
[^report]: `fresh-learner-output/REPORT.md`, SHA-256 `712a85a9a73bd7692ecab79cf198416fab825679ad6304d6fe10be3eb156fcda`.
[^summary]: `fresh-learner-output/final-evidence-summary.json`, SHA-256 `6c2f504c09cdcafda65d7f2da6b570c5bb18d4fb6753988a22e7cb35145e4d01`.
[^manifest]: `fresh-learner-output/change-manifest.json`, SHA-256 `50ddd41e9815f5f0fdc54fbb50f5189c28762a41e399a6d03e22d13c8244ac77`.
[^lifecycle]: `fresh-learner-output/lifecycle-assessment.json`, SHA-256 `fffac53cc0c5c419cafcf7cf7861d5087fb9edcc02e4afc6500a2974acc303e7`.
[^postfreeze]: `fresh-learner-output/post-freeze-verification/HANDOFF.json`, SHA-256 `c9dcc9814750fecaa4aa99dd7dc1e979cb42c23ba27af70be327e72635475565`.
[^setupfailure]: `fresh-learner-output/post-freeze-verification/setup-tool-failure.json`, SHA-256 `5eb8138ad8df1a1480381c69728ca2c0facee8a905f4d2ef984d69bda7a515cf`.
[^coordinator]: Coordinator observations supplied at this draft's cutoff: the public entry commit/tree equality, separation from the two external CLI failures, and the later v8 integration/status. These observations are explicitly separated from the frozen independent-study inputs in the machine-readable summary.
