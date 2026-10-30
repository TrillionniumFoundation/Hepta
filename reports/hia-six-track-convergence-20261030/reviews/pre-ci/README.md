# Six-track execution results — 2026-10-30

This delivery converges the two actual implementation branches, repairs a
native-input validation race, and executes the migration, NDU and Agent
qualification work against a committed common source. **It does not establish
all six requested acceptance criteria.** In particular, general complex-C++
migration, an additional net NDU benefit and an Agent development-cost advantage
remain unestablished. The Agent provider rejected all registered calls before
an answer because of its usage limit.

## Source and review identity

| Identity | Commit |
| --- | --- |
| Catalog parent | `192d2cbba7e49bde3b03af73685ecf96f6fb1b05` |
| P0–P7 parent | `953fa62dee5aa563551d57b1374ab95b6d548b45` |
| Actual published two-parent merge | `f259dacd6bc3d9155dcdd691acd00fc5cc44061c` |
| Code and CI follow-up | `5e214cd107b3d84395fab7f8ee6b07828800bb37` |
| Frozen experimental code and Agent registration | `14fe263fd8b65cb9bab019212e03a18550436cf0` |
| CI profile fix and final canonical qualification | `8a45d2f153cbe5200ee8567d67f2176ce63ba8a6` |

The registration commit adds the exact Agent `FREEZE.json` before model
requests. The later CI fix changes only the workflow: it explicitly binds
Rust 1.95 `rustdoc` and isolates that crate target from the production Rust
1.90 target. All production, test and experiment code is byte-identical
between these commits. The canonical rerun uses the CI-fix commit. Later evidence commits add results; they do not retroactively change
the source identity in a receipt. Earlier developmental results retain their
original local source identity and are not relabeled as final runs.

The review is [PR #418](https://github.com/TrillionniumFoundation/Hepta/pull/418),
targeting the existing P0–P7 branch. The published merge preserves both parents.
See the [merge decisions](../../docs/HIA_SIX_TRACK_CONVERGENCE_20261030.md) and
[Rust overlap review](../../docs/HIA_RUST_INTEGRATION_REVIEW_20261030.md).

## Acceptance state

| Priority | Work and observed result | Remaining boundary |
| --- | --- | --- |
| 1. Common semantics | Actual two-parent convergence, one opcode/schema contract, retained interpreter/backend/routes and independent Rust admission. Final exact-lock Rust run: 121 passed, 0 failed, 0 ignored. | The complete 552-selector gate and 33-method catalog/route check pass on the same `8a45d2f` commit. A regression pass is not a complete compiler-refinement theorem. |
| 2. Safety and preservation | The merged contract retains both parents' loop, owner/loan, failure, cleanup and resource analyses, and adds bounded immutable native-input capture. 53 capabilities, 552 unique selectors. | Only the declared finite solver/resource profiles have their stated authority; unknown bounds and unsupported effects refuse. |
| 3. C++ migration | Real Microsoft GSL 3.1.0/4.0.0 implementation and instantiated factory are captured by Clang AST; original C++ and generated Hepta execute separately. Version and callback-body changes are exercised. | Small RAII/callback specialization; no arbitrary exception ABI, callable, pointer lifetime or whole-library migration. Human cost is unknown. |
| 4. NDU value | 13 original native evaluations agree with independent finite oracle/DP, including a real SMT refusal followed by replanning. | No extra net benefit demonstrated; no learned FBSDE evaluation, unrestricted optimum or native application speedup. |
| 5. Dynamic execution | Active-call/retirement and owned-state controls are retained; a caller-mutation race and oversized-queue admission are repaired. Actual native functions and allocator observations are used. | No general OSR, arbitrary shared-memory guest execution, external-I/O rollback or crash recovery. |
| 6. Agent maintenance | New frozen 3-task × 2-requested-model × 2-language matrix, public/hidden checks, real resource witnesses and complete/unknown cost handling. | All 12 requests hit the provider usage limit before an answer. Coding correctness and productivity are not evaluated. |

## Final source-bound verification

**The complete reviewed matrix passes on clean `8a45d2f`: 552/552 passed,
0 failures, 0 errors and 0 skips**, covering all 53 declared capabilities.
All 1,159 qualified source inputs and HEAD remain unchanged; final Git status
is clean. Qualifier wall time is **606.044280227 s**. The original report SHA-256
is `a25e07026ab31edfa40e8863fb5c20ea62d312d2c08d76076ed293d1e82cc776`.

The generated catalog check also exits 0 on the same clean commit. Full opcode,
schema and route modules pass **33/33**, 0 skips, in **1.287406670 s**. These
33 methods overlap the 552-selector matrix and must not be summed as independent
coverage. See `safety-gate/FINAL_SUMMARY.json` and
`safety-gate/CATALOG_ROUTES_SUMMARY.json`.

The first complete attempt is retained: **543 passed, 9 errors, 0 skips**,
596.948368286 s, on `14fe263`. All nine errors arose from a missing tracked
historical template in the local sparse materialization. Seven original
provenance files were restored by exact Git blob and protocol SHA-256; the
19-file inherited closure then validated and the nine affected tests passed.
The successful 552 result is a new complete run, not a concatenation of results.

The independent Rust crate was rerun from the clean registered source `14fe263` with its
unchanged `Cargo.lock`: **121 passed, 0 failed, 0 ignored**, 21 suites, outer
wall time **11.567175942 s**. It used real Rust 1.95.0. The older production
backend retains its real Rust 1.90.0 pin; its identity was not replaced or
spoofed to make a test pass.

The three new modules were also rerun on the clean registered source `14fe263`: **31 passed,
0 skipped** (GSL 11, NDU 12, Agent tooling 8), outer wall time **3.201704149 s**.
These are tool/implementation regressions, not successful model generations.

The original-vs-fixed dynamic evidence in `safety-dynamic/` retains the real
pre-fix failures. There are eight dispatcher-spy methods and six native
integration methods; the former are not described as machine-code evidence.
The existing adaptive qualification executes 131 differential pairs and
262,144 concurrent host dispatches. The owned qualification records 17
allocations, 17 frees and zero live owners after its admitted scenarios.
These developmental runs have their own original provenance; the final
canonical gate independently reruns the registered snapshot regressions.

## C++: a real, bounded implementation migration

The upstream source pins are GSL 3.1.0 at
`0f6dbc9e2915ef5c16830f3fa3565738de2a9230` and GSL 4.0.0 at
`a3534567187d2edc428efd3f13466ff75fe5805c`. Source, dependency closure and
license bytes are retained. The importer reads the real value constructor,
move constructor and destructor, the instantiated `finally` factory, and one
closed scalar callback body. Unexpected AST shapes fail closed.

Each original C++ version and its Hepta counterpart is checked on 416 cases,
with a separate oracle. The actual 3.1.0 lvalue factory fails to instantiate;
4.0.0's changed reference/cv handling instantiates and executes. The supported
4.0.0 lvalue path and a changed callback multiplier are each checked on 416
cases. A resource-safe but semantically wrong multiplier produces 325
value/trace mismatches; duplicated or lost owners are rejected structurally.

The original is compiled as separate C++ translation units. The migrated
executable links generated Hepta code and a C harness, without a C++ bridge
object. The authored Hepta clients make exception-related paths explicit as
status values: this does not translate general C++ stack unwinding.

The final qualifier succeeds on the frozen source. Outer wall time is
**3.782893692 s**. Generated component size is 1,074 bytes; authored clients
total 1,604 bytes. The zero-byte owner is a linear lifetime token; it is not an arbitrary C++
allocator or native-memory proof. These byte counts and measured qualification time are not
the engineering cost of migration. Human implementation/review time remains
unknown, and no migration speedup or full semantic-equivalence theorem is
claimed.

## NDU: independent agreement, no demonstrated extra net benefit

The actual upstream evaluator is built from private-ci commit
`c4a1bbed3a39beba43a6abf1a18b6f75c5725c21` and its unchanged lockfile.
Its binary SHA-256 is
`2b82bf0345c917c65b058faaadd79d8a0379284103b39e712ad89a765052a40a`.
Its existing `DENY_ALL` authority is retained.

The new model includes pay-once preparation, resident holding cost, memory
quota, sunk work and a changed generation/snapshot after an actual refusal.
The same state and information are supplied to the independent exhaustive
oracle, resource DP, fixed combinations and lightweight greedy controls.

| Observed cost | Measurement |
| --- | ---: |
| Native enumeration, 6 actual requests | 33.101680 ms |
| Native exact compact search, 7 actual requests | 24.491149 ms |
| Independent resource DP, 7 finite models combined | 1.104763 ms |
| Actual failed translation proof and replay | 36.929322 ms |
| Full final qualification subprocess | 505.352832 ms |
| Separate native-bridge build, outer clock | 27.855271935 s |

These scopes differ and are not an application speedup ratio. The build
measurement excludes source acquisition and does not claim a fully cold host.
All retained failed preflights are included in the evidence and selected-cost
ledger. Unknown or unmeasured project costs are not filled with zero.

The larger three-variant model exceeds the original complete-enumeration
127-path cap; that arm refuses the entire case. Exact compact search handles
it. No partially searched set is reported as a global optimum.

The actual `add.wrap` to `sub.wrap` proposal passes structural admission on
both sides, but Z3 finds a counterexample and the canonical interpreter
replays different outputs. Its measured failure cost is charged before every
control and native arm replans the same successor. Declared preparation,
holding and execution numbers remain **model costs**, not measured native
application performance. The results establish the bounded consistency and
cost-accounting behavior, not an additional NDU performance benefit.

## Agent: frozen experiment, provider-side block

The new tasks change a quota API, revise a bitfield protocol, and resize and
rewrite an owned buffer with real allocation/load/store/drop obligations.
HIA and Rust use the same public contracts and hidden oracles. Requested
models are `gpt-6.1-sol` and `gpt-6-luna`; results are not pooled across them.
The protocol fixes ordering, six-request and three-public-check caps, terminal
hidden evaluation and failed-work accounting before generation.

Two author-control runs and an independent exact-freeze review pass. They
make **zero model requests** and are not model success evidence. The formal
12-cell attempt then takes **27.189146972 s** and receives 12 usage-limit
rejections. It observes 12 `turn.started` events, but **zero answers, zero
complete usage events, zero public candidate checks and zero hidden
evaluations**. All children are cleaned up and no cell is retried.

The raw runner's `actual_generation_observed` means only that `turn.started`
was observed. The derived summary makes this distinction explicit. Reported
tokens are a lower bound of zero; actual token consumption and billing are
unknown (`null`). The coding outcome is **not evaluated**, not 0/12 coding
correctness and not a language/model failure. Human review time and full
development cost remain unknown. No Agent productivity advantage is claimed.

## Evidence layout and limits

- `RESULTS.json`: source identities, acceptance state and exact evidence links.
- `safety-dynamic/`: retained pre-fix failures and bounded dynamic repairs.
- `safety-gate/`: final canonical selector report, logs and execution envelope.
- `rust-final/`: final exact-lock Rust log and envelope.
- `additional-tests/`: final 31-test log and envelope.
- `gsl/`: source-bound migration summary, manifest and complete archive.
- `ndu-agent/`: native NDU and frozen Agent summary, manifest and complete archive.

Archive manifests bind individual original bytes; the external validation
checks member paths and decompressed bytes. Derived summaries are labeled as
derived and do not overwrite the original receipts. The first safety archive
retains a serialization defect in `finite-source-commands.json` and
`recursive-source-commands.json`: each complete array is followed by literal
backslash-plus-`n` bytes. Those files remain raw command evidence rather than
strictly parseable JSON; they are not admission receipts or inputs used to
compute the reported selector outcomes. Source hashes, native
artifact identities and finite negative controls support the stated scoped
findings. They do not prove whole-language soundness, source/Core/native
refinement, native RSS/stack bounds, unrestricted global optimality, absolute
resource safety or Rust performance superiority.

## Cloud CI observation

The first [cloud run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41091348852)
passes the original native-NDU job. Its semantic job reaches the Rust doctest
stage and fails because `rustdoc` resolves to 1.90 while the independent crate
was compiled with 1.95. Both the original failure and a local reproduction are
retained in `ci/`. The exact workflow fix in `8a45d2f` explicitly selects the
matching 1.95 `rustdoc` and separates the crate target. The real reproduction
fails before that change and passes with the matching tool.

The [corrected cloud run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41093887756)
has passed its native-NDU job; its semantic job is still queued at the last
observation recorded in `RESULTS.json`. The entire cloud run is not reported
as passed. The complete local 552-selector and 33-method results
above are separate, actual executions on that corrected source. An evidence-only
follow-up commit can trigger another cloud run; it does not change the source
identity of these retained qualifications.
