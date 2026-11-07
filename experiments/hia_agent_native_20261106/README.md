# HIA Agent-native qualification — 6–7 November 2026

This record qualifies the implemented Agent → HIA tools → direct x86-64 machine
code → native evaluation → conditional adoption/rollback path. Its public native
entry profile is Linux x86-64 SysV with scalar integer/Boolean arguments and at
most one scalar or unit result. Internal Core resource operations retain their
existing verifier and native-backend coverage.

The application contract, worker implementation and runtime adapter are separate
from this evidence. The Agent chooses a transformation or an explicit block
layout. The backend checks and realizes that choice; it does not select a
profitability optimization. GNU `ld` may link an already emitted object into a
shared image. LLVM, a C/Rust compiler and an external assembler are not fallback
instruction generators on this path.

## Source identities

The Hepta implementation was published as commit
`124ed9275d1f977b697aac22028341865d9ca940` in
[PR #787](https://github.com/TrillionniumFoundation/Hepta/pull/787), stacked on the
direct native backend [PR #773](https://github.com/TrillionniumFoundation/Hepta/pull/773).
The runtime implementation was published as
`d95866c9e244e03a182740d420f94294ee43cdcd` in
[runtime PR #109](https://github.com/TrillionniumFoundation/hepta-runtime/pull/109),
stacked on runtime PR #84. Hepta qualification-inventory fixes were published as
`2687e9c1dbe62b70d5eabc2d3381abf4aefe524e`. The bounded proof-evidence allocation
fix is `574a6f10ea1de984bb21564231cb3df17fa44236`; the final all-host Clang smoke
budget correction is `4c1757bcd4db1f6deeadd190213dc26264ec46f0`. Runtime commit
`9f60a30530f47925f4f6ae495660a1d68bb6947d` refreshes only the frozen REA ledger
source projection; all 229 upstream tool qualification records remain unchanged.
These qualification fixes do not alter the pinned worker source bundle or the
16-file runtime implementation qualified below.

| Identity | SHA-256 |
| --- | --- |
| Actual worker installation | `15b1bde41801117626509595d2d7908f44340fe1a2bf88227f3626e42d29a937` |
| Direct backend | `2da6aaaaec1129a0129f0fdb7c3f91a4158103e0bcd0cb0f85baa77760a18c28` |
| Shared eleven-tool catalog | `8b880cc02efc93e10d920bf812bccbb33197aa00f6b92282536a000238ba5e9e` |

[`source-identity.json`](source-identity.json) retains all 201 worker source and
documentation file hashes. These are hashes of actual installed bytes, not an
inferred clean Git revision. Runtime binary and configuration identities belong
to each transport run, so results from different binary revisions remain
distinguishable.

## Direct backend and domain regression

[`direct-native.json`](direct-native.json) records 173 executed test methods,
zero failures, zero errors, zero skips, a complete test inventory and
`source_unchanged: true`. This final local run uses the published implementation
commit and the final worker source bytes. [`agent-tools-tests.log`](agent-tools-tests.log)
records 28 passing Agent tool tests, including admission/proof separation,
native execution, explicit layouts, wrong native outputs, deadlines, request
ownership, leases and rollback.

The dedicated exact-source GitHub Actions run
[42314773193](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42314773193)
passed both the 28-tool-test suite and the 173-method native qualification.
The separate direct-backend workflow
[42314773284](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42314773284)
also passed on that implementation commit.

The schema generator's 66 checks validate 22 wire schemas. Its deliberate
`runtime_tools_registered: false` and execution-claim fields describe the scope
of that schema-only checker. Actual registration and execution are established
by the separate MCP traces below.

## Broader native/NDU integration regression

[`ci-hepta-ndu-4c1757.json`](ci-hepta-ndu-4c1757.json) and its complete compressed
job log retain the final-head NDU workflow's **37/37 successful steps**. Its full
native regression executed all **1,785 planned tests**, with zero failures,
errors, skips or expected failures; planned, started and finished test-inventory
hashes agree, and source/worktree were unchanged. Separate native-planning
checks passed all twenty tests. Six archived validators executed 74 tests.
These are separate inventories and are not summed as disjoint test coverage.

Passing this workflow preserves nonwinning outcomes. The finite NDU loop's
actual outputs were all correct, but its observed median net cost was
298.021041 ms, compared with 234.6765345 ms for fixed-selected and 235.0272715 ms
for light; both lower-cost flags remained false. The guarded opportunity result
was `no-economic-opportunity`. This workflow's final agent-assembly qualifier
made zero model requests and did not qualify Agent advantage. That scripted
qualification is distinct from the separate fresh-context Agent experiment below.
The native regression and emitted-code correctness observations do not establish
universal performance or economic superiority.

## Actual MCP transport, revision r3

The first complete transport run used the actual Rust stdio MCP server on ai395,
the existing configured SSH route to x230, and the final pinned worker. It made
39 scripted HIA calls covering every one of the eleven tools. The actual
`tools/list` schemas, descriptions and operation annotations matched the frozen
family catalog.

[`mcp-qualification-summary-r3.json`](mcp-qualification-summary-r3.json) is the
readable summary. The complete report and original request/response log are
retained as `mcp-qualification-r3.json.gz` and
`mcp-qualification-calls-r3.jsonl.gz`; their compressed and uncompressed hashes
are in [`mcp-evidence-index-r3.json`](mcp-evidence-index-r3.json).

For this explicit synthetic `u8` wrapping `x + 7` fixture, the client removed
128 redundant zero additions. Both native images completed all 256 independent
expected inputs. Whole shared-file size changed from **17,816 to 13,720 bytes**:
**4,096 bytes**, or **22.99057%**, saved. This is a code-size result for a
declared synthetic fixture. It is not application speed or net optimization
benefit. The same run established finite-domain equivalence, actual encoding
identity, adoption, stale-generation refusal and rollback.

[`mcp-lifecycle-r3b.json`](mcp-lifecycle-r3b.json) records six additional actual
transport checks:

1. An issued resource URI reads the exact hashed manifest.
2. An identical mutation returns its original response after server restart.
3. A changed payload under the same request key is refused; the original result
   remains available. The refusal is an MCP JSON-RPC error with the original
   ownership/recovery guidance, not a newly successful domain operation.
4. An outdated catalog is rejected before worker admission.
5. An owned in-flight verifier is cancelled. After confirmed termination, its
   missing domain result remains `unknown` with the same original operation,
   including across another server restart.
6. An incorrect worker source pin fails closed. An exact retry observes the same
   failed native job and does not allocate a replacement execution.

The r3 binary predates the final escaped-input bound and system-program
portability corrections. Final-binary qualification is recorded separately.

## Final runtime regression

[`runtime-final-gates.json`](runtime-final-gates.json) binds the exact published
runtime source commit `d95866c9e244e03a182740d420f94294ee43cdcd`, all 16 integration
file hashes, the staged source manifest, toolchain, commands and complete logs.
Before and after each step, the source remained unchanged and clean.

| Final development-host gate | Observed outcome |
| --- | --- |
| Format and both feature-mode Clippy checks | Passed |
| Targeted HIA/owner-fence/provider regression | 73 passed |
| Actual system-program SSH observation module | 56 passed |
| All-target/all-feature complete nextest suite | 2,351 passed, zero failures; 40 existing default skips |
| All-target/no-default-feature complete nextest suite | 2,322 passed, zero failures; 28 existing default skips |
| Locked all-feature runtime build | Passed |

The repository's existing default skip counts are reported as skips, not
executed passes. Final qualification binary r4 is 47,188,920 bytes, SHA-256
`6dcadf26053b35b9edb1270576bbbdc5f1ec8f37f958e9e5ca9b9350d2d5e13f`.
The original r3 binary and its observations remain separately identified.

The generated REA ledger correction was independently recomputed on the development
host. Exactly ten source records changed only their byte lengths and SHA-256
values. Upstream snapshots, capability mappings, all qualification records and
claims remained equal. Existing ledger unit checks and `check_mapping` passed.
[`runtime-rea-source-projection.json`](runtime-rea-source-projection.json) records
the precise old/new projection; it is not a new upstream-behavior qualification.

[`runtime-ci-9f60.json`](runtime-ci-9f60.json) records complete GitHub CI at the
published runtime head `9f60a30530f47925f4f6ae495660a1d68bb6947d`:
push and PR exact-source jobs passed all 26 steps each; the prospective merge
`0517aaac6b13494b3f1201590d1e1d8703032d63` passed all 23 steps. Both workflows
completed successfully on their first attempt. Each of the three executing jobs
ran all 2,351 all-feature tests and all 2,322 no-default tests, with the existing
40/28 configured skips. Format, both Clippy modes, descriptor-relative file
safety, REA mapping/evidence, control-plane, X230, release builds and shipped
release MCP/parser/ZIP checks all passed. The push event's merge-only job was
correctly skipped; the PR's actual merge job executed and passed. All three
complete logs are retained with their compressed and raw hashes.

## Final-binary actual MCP transport

[`mcp-qualification-summary-r4b.json`](mcp-qualification-summary-r4b.json) records
the final actual ai395 Rust MCP → configured SSH → x230 worker run. All eleven
tool schemas, descriptions, annotations and published title mappings matched the
frozen catalog. The required **39 main-flow actions, two maximum-escaping round
trips and six lifecycle checks passed**. The main actions returned 38 completed
results and one expected stale-generation rejection.

The runtime binary hash was identical before/after. Command, configuration,
staged runtime source manifest and all three installation pins are retained in
the binding records. Both outer jobs authoritatively completed with exit zero,
complete durable output, no truncation and no stderr. The private endpoints were
closed; a read-only check of the six exact configuration argv values found no
matching active MCP processes at `2026-11-07T00:55:33Z`.

The scripted whole-image result reproduced **17,816 → 13,720 bytes**, saving
**4,096 bytes (22.99057%)**. Baseline and candidate each executed every one of
256 frozen expected inputs. This remains a declared synthetic fixture and a
code-size observation, separate from the independent Agent result below.

| Exact maximum input | Characters / UTF-8 bytes | Read pages | Largest actual request line | Largest actual response line |
| --- | ---: | ---: | ---: | ---: |
| NUL | 65,536 / 65,536 | 5 | 393,599 bytes | 214,077 bytes |
| Mixed quote, backslash and control characters | 65,536 / 65,536 | 2 | 117,456 bytes | 197,694 bytes |

Both artifacts round-tripped byte-for-byte and matched their issued hashes. The
actual response lines, including their newline, remained below 262,144 bytes.
The two cases used eleven actual tool calls, including discovery and all pages.

All six lifecycle checks listed for r3 were repeated on r4. Cancellation retained
`unknown` with the original operation after confirmed native cancellation
(exit −15), including across restart. A wrong worker pin retained `unknown`
with the same failed native job (exit 2). These are successful failure-handling
checks; neither domain operation is relabeled completed.

[`mcp-evidence-index-r4b.json`](mcp-evidence-index-r4b.json) retains 30 indexed
artifacts, including all complete traces, compressed/raw digests, binding records,
terminal receipts, historical r3 outcomes and the unsuccessful initial r4 title-
binding harness attempt. Every indexed file and compressed original was verified
locally before publication.

## Independent fresh-context Agent acceptance

[`fresh-agent-report.md`](fresh-agent-report.md) and
[`fresh-agent-report.json`](fresh-agent-report.json) retain the independent
Agent's findings. The Agent began without task-context HIA grammar/examples and
used actual MCP discovery/read tools to learn and author its programs. It did not
read implementation, tests, or the scripted qualification during the experiment.
The experiment ran on explicitly identified **r3**, not r4. Model pretraining
exposure is unknown.

The Agent independently authored `((x ^ 0x5A) + 13) & 255`, its redundant baseline,
and a complete 256-input oracle. It repaired an invalid `u8` constant from the
structured diagnostic. Its first large baseline exhausted the finite proof
budget at 237/256 inputs; the result remained `unknown`, and evaluation rejected
its missing required claim. A smaller baseline completed all 256 proof cases
without relaxing the required claims, and both actual native images matched every
independent expected result.

The qualified comparison saved **zero whole-file bytes: 13,720 → 13,720**.
Aggregate measured ctypes-call time was 984,982 ns for the baseline and 1,282,871 ns
for the candidate across 768 calls each; the candidate was slower in this
observation. The explicitly frozen objective allowed unchanged artifact size,
so the Agent exercised conditional adoption, stale-CAS refusal and rollback
without claiming a speed, size or net-benefit win.

A separate Agent-authored branch program and explicit block-order permutation
changed **16 actual byte positions** in a 406-byte ELF executable section.
Both variants matched all 256 independent expected outputs; whole files remained
13,712 bytes each. The plan's preservation claim is conditional on the published
canonical-lowering and encoder assumptions.

The archive [`fresh-agent-evidence.tar.gz`](fresh-agent-evidence.tar.gz) preserves
190 files, including the index, all source attempts, discovery artifacts,
request/response traces, emitted binaries, observations, failures and lifecycle
receipts. [`fresh-agent-retrieval-verification.json`](fresh-agent-retrieval-verification.json)
records independent local verification of all 189 indexed files, both their
packaged and original digests, and the archive SHA-256. All 121 observed HIA
operations are terminal; the final endpoint exited successfully at
`2026-11-07T00:16:02.287309Z`.

The trace has one precise recording limitation: the supplied initial CLI session
omitted its one-way `notifications/initialized` record. Its initialization and
`tools/list` calls are retained; every actual HIA tool RPC request/response and all
subsequent notifications are recorded. The original r3 binary hash is explicitly
parent-observed, not independently hashed by the fresh Agent. These limitations
remain in the report.

## Whole-repository qualification repairs

The newly introduced native/Agent modules exposed stale repository qualification
inventories. The source closure now explicitly adds the nine reviewed modules,
preserves every historical projection and commitment, and rejects unreviewed
extras. The safety registry updates its actual instruction-catalog identity,
retains the original capability claims, and adds separately scoped direct-native
boundary checks. The targeted source/safety/native check records 37 passes in
[`ci-inventory-qualification.json`](ci-inventory-qualification.json).

The original Core kernel CI failed before any Lean invocation and retained only
a failure result. The inherited 144,713-byte identity allocation described 239
source paths, while the reviewed current closure has 323. Its exact maximum
canonical identity is 156,044 bytes. The fix transfers 11,331 bytes from the raw
log allowance to identity metadata: metadata 235,920, raw logs 808,560 and display
4,096 still sum to the unchanged **1,048,576-byte** evidence/display limit.
Source/module/time budgets and all proof gates remain unchanged. The historical
protocol retains its original limits. Existing focused tests check the exact
maximum, historical projection, full aggregate boundary and one-byte overflows;
all ten passed. The actual head-574a Lean run then completed all **eleven fresh
modules, 66 positive targets and ten exact negations**, and independently replayed
the same evidence successfully. Those checks were repeated successfully at the
final source head **4c1757**. Both final console summaries bind RESULT SHA-256
`70ad0b07293a7258c0eebc9c87d6906e120fdfe4c7e30d2fa948e5ee0686cf94`.

The complete original final ZIP,
[`ci-hepta-shared-kernel-4c1757.zip`](ci-hepta-shared-kernel-4c1757.zip), exact
IDENTITY/PLAN/RESULT, member index, complete job log and both original console
summaries are retained. The earlier successful 574a archive remains separately
identified. Final source-control qualification also completed all fifty expected,
collected, started and finished tests with zero failures/errors/skips and unchanged
source identity; that source-control suite correctly records zero Lean invocations
and is distinct from the actual kernel run.

The actual canonical IDENTITY was **145,156 bytes**, exceeding the old allocation
by **443 bytes**, directly corroborating the capacity diagnosis. Actual raw logs
used 543,513 bytes, below the reallocated limit. These narrow syntax results retain
`DENY_ALL` authority and all twelve wider unproved obligations; they do not prove
universal Core-to-native refinement.

The actual Windows Clang and MSVC CI jobs passed after correcting the bounded
Clang preprocessor smoke deadline. A later Linux GCC job exposed the same
artificial ten-second smoke limit; its failure logs and artifact are retained.
The final test now uses the existing thirty-second capture default on every
host. Real x230 Clang then passed all sixteen capture tests, with no skips,
including the unchanged short-timeout and descendant-termination cases.
Production capture code and limits were not changed. All eight final published-head
host ABI jobs then passed, including Linux x86-64 GCC/Clang, Windows Clang/MSVC,
macOS and the existing ARM hosts. The final Linux GCC log retains the successful
real Clang smoke and unchanged 0.15-second wall-timeout/descendant controls;
its capture suite completed all sixteen tests successfully.

## Retained unsuccessful attempts

Earlier source-changing regression, an output-file collision, initial MCP
controller-state/configuration admission failures and a supplemental harness
expectation error remain in the attempt records. They are not counted as
successful qualification runs. The output-file collision did not execute the
native suite; `direct-native.json` is the later successful run against a new
output path. The initial lifecycle harness expected a tool-error envelope for
an ownership conflict; the corrected harness asserts the actual JSON-RPC
refusal without changing runtime behavior. The initial r4 catalog-binding harness
assumed a catalog title field that is intentionally absent; the corrected check
uses the runtime's published generated-title rule. Its original failed run, driver
and complete traces are retained, distinct from the passing r4b run.

## Final published-head CI

All fifteen tracked Agent-native integration blockers are closed in
[`blocker-closure.json`](blocker-closure.json). This closure is scoped to the
implemented direct-machine-code and Agent/MCP contract described above.

The final Hepta source `4c1757bcd4db1f6deeadd190213dc26264ec46f0`
passed **all sixteen workflows**: fifteen pull-request events and the separate
Agent push event. The last frontier workflow,
[42321800225](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42321800225),
completed successfully with **all 79 jobs executed and successful**, with no
failures, cancellations or skips. The final receipt
[`ci-hepta-head-4c1757-final.json`](ci-hepta-head-4c1757-final.json) retains the
complete source-bound inventory and hashes of original API responses.

The final runtime source `9f60a30530f47925f4f6ae495660a1d68bb6947d`
passed both workflows and all three applicable executing jobs: push source,
PR source and prospective merge. The merge identity and complete logs remain
in [`runtime-ci-9f60.json`](runtime-ci-9f60.json).

[`ci-published-heads-final-verification.json`](ci-published-heads-final-verification.json)
records a separate root-agent reread of the complete GitHub inventories, terminal
parent state and exact PR head/base identities after the last gate completed.
Earlier pending observations and unsuccessful attempts remain historical records;
they are not used as the final gate result. The implementation branches retain
their tested source heads; this evidence is published on a separate evidence
branch. No production deployment or broader self-hosting/proof claim follows
from this CI completion.

## Claim boundaries

Core admission, behavioral equivalence, conditional block-layout preservation,
native encoding identity and observed workload results are different claims.
Unsupported or incomplete proofs cannot satisfy a required adoption claim.
The finite equivalence profile covers supported pure acyclic scalar programs
with at most 12 total input bits; it does not establish universal equivalence
or universal Core-to-x86 refinement.

The independent Agent experiment tests learning and using the current tool
contract from a fresh conversation context. It cannot establish what was absent
from model pretraining. External model/discovery costs are unknown unless
explicitly supplied; unknown cost is not zero and no net-benefit claim follows.

This implementation retains the Python bootstrap implementation and Rust
runtime. It is not a compiler self-hosting bootstrap or a rewrite of the whole
runtime in HIA. The private qualification endpoint is not a redeployment of the
existing production connector or public gateway.
