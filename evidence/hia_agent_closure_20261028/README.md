# HIA agent-oriented language: final-source qualification, 2026-10-28

This evidence increment belongs to source commit
`fc5c155c47a7920519ed79a9953f8e415b0a7863`, tree
`a805d4609860e88e1d26f4e2ea45ce809e9692ee`.
It extends the previously qualified source `efb210e` and keeps Draft PR 329
as the review entry point. This evidence commit has the final source as its
sole parent and changes only `evidence/hia_agent_closure_20261028/`. Qualification
targets the source parent; serialized evidence grants no native compilation,
execution or publication authority.

## Reading and restoring the evidence

`SOURCE.json` identifies the exact source and its three-commit publication
chain. `SUMMARY.json` keeps the different test, observation and host denominators
separate. `audits/` exposes the independent read-only conclusions. Full original
records and retained program bytes are in the numbered `raw-evidence.tar.xz`
parts; `ARCHIVE.json` binds every part and `RAW-INDEX.json` binds every payload.

From this directory, verify every retained payload without restoring it:

```sh
python3 RESTORE.py --verify-only
```

To restore all raw files and reconstruct each original CI extraction tree into
a new directory:

```sh
python3 RESTORE.py --output /absolute/new/hia-evidence --expand-ci
```

The reader refuses an existing destination, path traversal, symlinks, duplicate
members, unexpected members and hash/length/source/count mismatches. It does
not compile or execute archived programs. The complete original CI ZIPs are
retained; their duplicate extracted trees are represented by explicit ZIP-member
hashes and reconstructed by `--expand-ci`. An original collection manifest can
therefore list extracted files absent from the compressed outer archive until
this expansion is performed.

Original absolute process paths remain provenance and are not rewritten.
`PACKAGER-SOURCE.py` records the packaging implementation used in the original
workspace; `RESTORE.py` is the portable retrieval entry point. Local toolchain
SDK payloads, unreferenced local compiler caches and temporary signed download
URLs are excluded. Original CI ZIPs remain byte-for-byte intact, including
build-cache members uploaded by the full CI workflow. Original native
application artifacts and retained Rust harnesses are preserved. CI toolchain
binaries themselves were not uploaded by their workflows; their original
identity/process/hash receipts remain available. The XZ archive uses a 512 MiB
dictionary; allow more than that amount of memory for verification/restoration.

## What changed

The canonical v8 source frontend can return a read or mutable loan of one
stable nested record field. It resolves the actual flattened field origin,
including non-first fields, and preserves mutable scalar writeback. All return
paths must identify the same declared origin. Path-dependent fields, scalar
origins and premature owner/loan consumption remain refusals. The Python and
independent Rust machines, canonical verifier and direct LLVM backend retain
their existing semantic authority.

Native runtime snapshots now retain the original per-image admission mapping.
The adaptive and owned-state qualifiers bind retained native bytes to that
mapping's artifact, device, inode, length and loaded entry. Background
qualification additionally records the separate measurement candidate's actual
post-close state. These are admission-time and owned-release observations;
they are not a proof of every process-wide loader reference or permanent path
absence.

Exact-request NDU response reuse is explicitly bounded and defaults off. It
binds the full request, generation, objective, snapshot, budget, proof/support
identities and original native executable/build to a detached advisory response.
Hits recheck those identities and admissibility. Resource legality, behavioral
proof, native preparation and publication remain separate checks. Neither an
NDU recommendation nor serialized evidence grants authority.

The upstream C++ host profile compiles a real `.hepta` consumer to a Rust object,
links generated C ABI wrappers and calls unchanged pinned nlohmann/json
3.11.3 and 3.12.0. Both complete headers and licenses remain byte-for-byte
pinned. GCC, Clang and MSVC have explicit command-line and target contracts.
Wrong-signature evidence requires the actual failed compile, exact mutated
contract/generated source, method-specific static assertion and original bounded
diagnostic bytes. Compiler-family claims bind to original probe/version/target
processes, including the underlying executable identity.

## Exact-source results

The final summary and CI collection records give completed gate results and
original run IDs. An unfinished or skipped invocation is never counted as a
passing complete gate. Test methods, input vectors, repeated budgets, native
calls, host jobs and read-only audit checks are different denominators.

The exact final-source local integration passes all seven gates: 3,014 distinct
Python methods and 63 Rust tests, with zero failures or skips. The 19 critical
coverage groups and 57 modules are a subset of that same Python invocation.
All 4,021 tracked source files and 341 external inputs remain unchanged.
Independent byte/log/Git checks confirm these records. The Rust output has
11 executed test-harness binaries and one empty doctest result block; all 11
harness binaries and the existing VM are retained without rebuilding.

The final verified-optimization CI separately passes 353 methods in 37 modules,
with zero failures, errors or skips. Its 297 declared implementation hashes
match the final Git source. This checkout also contains three untracked output
and upstream directories, so only its unchanged tracked implementation is
claimed, not an entirely clean CI workspace. These 353 methods overlap the
full local run and are not added to its count.

The final full CI, run `40732196849`, succeeds in all three phases:

| Phase | Passed/planned gates | Full or focused test invocation |
|---|---:|---|
| Release | 50/50 | 3,014 Python tests, zero failures/errors/skips |
| Unified execution | 35/35 | A separate 3,014-test invocation, zero failures/errors/skips; 63 Rust tests |
| NDU pipeline | 9/9 | 200 focused Python methods and 63 Rust tests, zero failures/skips |

The unified phase also executes 45 shadow-parity and 53 agent-query methods.
These gate invocations and overlapping suites are not added into a larger
unique-test count. The release/unified source inventories each bind 1,747
declared files, and the pipeline binds 652; every recorded implementation
remains unchanged. The independent full-CI reader checks the original ZIP's
6,117 members, exact source bindings, all gate/process logs and the three
actual native bridges. The source includes no AI-model productivity trial,
universal Rust-performance result or physical-device qualification.

### Returned loans and resources

The final standalone run executed 13 methods with zero failures, errors or
skips. It recorded 439 Python/Rust state-and-ledger pairs: 93 normal returns,
16 traps and 330 budget stops. Forty-eight illegal programs were refused by
the actual Rust executable under two budgets, giving 96 refusal processes.
Six native fixtures made 21,504 successful calls. Eighteen native failure-policy
observations, two deliberately wrong native artifacts and four real CLI
commands were retained separately. These returned-loan native executions are
Linux x86-64 observations, separate from the C/C++ host matrices. VM budget
stops do not imply automatic cleanup and are not a budget mechanism implemented
by these native fixtures.

The actual executed Rust VM is retained, not rebuilt for archiving:
16,782,376 bytes, SHA256
`d66b8df27eb64001a0519a27e6317da47dc7bf3f6f04d332d7e20ce1c98c4fac`.
Fatal traps can leave live allocations at the recorded stop. Those states are
not successful cleanup. Native allocation/free observations are not a proof
of all native borrow lifetimes. This profile does not establish general
borrowed-record storage, panic unwinding or universal asynchronous cancellation.

### Actual native C and C++ hosts

C/ABI and C++ library reuse are separate seven-job matrices. Each uses actual
Linux x86-64 GCC/Clang, Linux AArch64 GCC/Clang, macOS AArch64 Clang and Windows
x86-64 Clang/MSVC jobs. Matrix declarations and cross-compilation alone are
not execution evidence. The final host collections retain original workflow
ZIPs, job logs and source bindings. The C++ reuse and stb_divide migration
profiles additionally retain their original native artifacts. The separate
C ABI matrix retains command, stdout/stderr and executable-hash receipts;
its temporary matrix object, O0/O2 executables, wrong-code binary and generated
matrix header/caller sources are absent from the uploaded artifacts.

The stb_divide host profile compares original C callers with the source
translation bundle's generated Rust shared libraries, across two declared
macro variants. It also retains HIA programs and interpreter observations.
Direct HIA-native execution was neither requested nor executed in these seven
host jobs, and UBSan was not enabled.

Across those seven C host jobs, 21,453 unique inputs are reused in 300,342
host/configuration/input comparison groups. Their original C and generated
target function observations total 3,604,104. The HIA interpreter function
observations total 4,872 across the seven host jobs and two variants. There
are 168 target-only native trap processes,
7 compiled wrong-implementation refusals, 21 whole-bundle source refusals
and 7 C++ profile refusals. The independent C ABI matrix records 14 profile
executions, 2,534 observed foreign calls, 21 type compile refusals and 7
wrong-echo refusals. The adapter tests execute 11 methods on each host
(77 method-executions, zero skips). These are separate denominators, not
millions of independently proved programs.

The retained C component images are 14 original C callers, 14 generated Rust
shared libraries and 7 deliberately wrong libraries. Their ELF, Mach-O or PE
headers and required exports match the respective hosts. This component is
scalar arithmetic without owning resources or loans; its zero allocation
counts do not establish migration safety for general resource-bearing libraries.

For each C++ library version on each host, 98 distinct inputs run through direct C++ and
compiled Hepta routes. Thirty-two persistent lifetimes cover copied input,
mutation refusal, stale reads and duplicate destruction; four threads make
1,024 serialized foreign calls. The cancellation case stops between completed
foreign calls after 3 of 7 requested mutations, retaining value 107 with no
replay. Eight metadata substitution controls are reader refusals, not eight
additional native compilation failures.

Each final C++ host report binds 148 source inputs. Linux and macOS match all
148 Git blob byte hashes directly. Windows matches 6 unchanged blobs and 142
CRLF checkout byte hashes; pinned upstream headers and licenses remain
byte-for-byte unchanged. The original byte representations are retained and
checked separately, not silently normalized in the receipts.

Completed-operation ordinary allocation deltas are zero on every host.
The process-lifetime registry retains 2 ordinary allocations on Linux/macOS
and 3 on Windows; these allocations are reported separately and are not
counted as released. The C++ results establish finite
qualification of real library reuse. Source migration evidence comes from the
separately reported C profile. These results do not establish arbitrary C++
translation, foreign-library memory safety, cancellation of an active foreign
function or a measured low migration-development cost.

### Native version and lifecycle mechanisms

Three final-source standalone qualifiers retain 8 admitted ELF instances and
6 distinct byte hashes. Adaptive retains 2 scalar images; owned-state retains
2 scalar images and its 14-export native driver; background retains 3 instances,
including its separately measured candidate. An independent reader checked
51 frozen files, 21 loaded-symbol offsets, build bindings and 14 retained SMT
obligations without re-executing a compiler, solver or native library.

Adaptive makes 262,407 application native calls and 278 shadow calls, but its
measured net is -296,808,249 ns and automatic selection remains refused.
Owned-state ends at 17 allocations, 17 frees and zero live owners; a real
partial queue commits 1,078,376 of 1,000,000,000 steps without replay. Its
measured deployment net is -855,408,336 ns. Measurement is already included
in calibration cost and is not charged twice. The optional performance campaign
was not requested or run.

Background executes the original ranking NDU three times and makes 14,592
native measurement calls. Measured costs abstain, explicit synthetic costs
exercise a proved publication, and a behavior-changing candidate is refused.
Its three admitted instances have distinct sealed identities but identical
machine-code bytes. They demonstrate admission and lifecycle behavior, not
different optimized instructions or a speedup. Both the main runtime and the
separate measurement runtime retain successful post-close observations with
no generations, pending resources or owned path identities.

## Registered NDU reuse experiment: negative result retained

This study keeps its original source `b66314a9e1101c30bc39af8f8545fff31fb01ec3`
and protocol SHA256
`bf5399cf0d32c6620050b69154e300ed608286f7f73da7e1c73ff14b82141b57`.
It is not relabelled as an experiment on the final merged source.

The single registered execution contains 30 episodes, 1,920 queries, 600
native evaluations and 12 identity probes. Fixed-plan, complete-DP and
enumeration controls receive the same future graph/model and reuse capacity.
Each reuse arm has 168 hits and 216 misses across its 384 queries. A separate
standard-library reader reconstructed the registered traces, requests, finite
graph values, frontier decisions, reuse receipts, actual command streams and
all 2,528 frozen files / 60,992,460 bytes.

| Strategy | Standalone warm seconds | Standalone cold seconds |
|---|---:|---:|
| Fixed-plan reuse | 0.574435465 | 0.574435465 |
| Complete-DP reuse | 0.586218882 | 0.586218882 |
| Enumeration reuse | 0.746066070 | 0.746066070 |
| Native NDU without reuse | 2.494697139 | 29.217710826 |
| Native NDU with exact reuse | 3.273724786 | 29.996738473 |

Native cold totals charge the original empty-target build of 26.723013687 s
once to each standalone native strategy. The warm common preparation cost is
also charged once per strategy. Aggregate reuse saving is **-0.779027647 s**,
meaning slower execution. The retry-only descriptive saving of 0.003561217 s
does not establish statistical superiority. Changed-generation inputs cost
0.782588864 s more with reuse.

The frozen historical cost bank is an advisory model input, not a fresh
application measurement. No general NDU advantage, current application-runtime
improvement, global optimum or statistical superiority is claimed. Default
activation remains false.

The CI's separate 30-episode native-loop qualification is not this registered
30-episode reuse study, and neither is the earlier 48-episode experiment.
Their source identities, protocols and denominators remain separate. The
registered new-30 and prior-48 experiments were not rerun to select a result.

## Failures and version history

- `c9f1915`: C/ABI hosts passed 7/7; C++ hosts passed 5/7, with two Windows
  tests failing before native qualification because a shared subprocess mock
  intercepted Python's platform discovery.
- `801cf02`: the narrowly isolated host-refusal mock passed all 7 actual C++
  hosts. It changes only the test boundary, not production semantics.
- `c9f1915` verified CI ran 353 methods with zero failures/errors and one skip.
  The zero-skip gate correctly failed because the new native-reuse test expected
  HEPTA_CLANG while the workflow supplied CLANG.
- The old full CI `40730763364` likewise retains release 49/50 and unified
  34/35 as failures, with pipeline 9/9. Both full regressions report 3,014
  tests and one skip: the native advisory-reuse compiler integration method.
  Process exit zero does not override the zero-skip gate. Its original ZIP
  and independent consistency audit remain separate from the final-source pass.
- `fc5c155`: compiler selection now uses the actual configured CLANG with the
  existing fallback. The same native integration test executed successfully in
  the CLANG-only environment; final verified CI passed 353/353 with zero skips.
- The original local `c9f1915` full regression did not produce a final report
  after its supervisor disappeared. Its five completed preliminary gates and
  incomplete-run receipt remain retained; no complete pass or test count is
  inferred. The final source receives a separate full invocation.
- Earlier setup, finite bridge build, focused test-fixture and checkout-state
  failures remain identifiable under their original logs and source identities.
- The first C++ development run records an `efb210e` dirty worktree, not a clean
  commit. Four pre-commit source files have only their recorded input hashes,
  not complete historical snapshots. Early `7db3f1c` and `41a698d` negative
  signature reports retain their original limits; the stronger compile-stage
  binding first appears at `2567eb5` and is not applied retroactively.
- The first independent integrated-log reader rejected eight success records
  that wrap over diagnostic/docstring lines. Its failed audit and original
  reader are preserved. The revised read-only reader requires each complete
  method record to end in its own `ok`; it confirms 3,014 successes without
  changing any original report or re-executing tests.
- The complete-CI collector's initial directory scan included unrelated
  transfer temporaries. Its first freeze is preserved as superseded metadata;
  the final outer archive follows the explicit `FREEZE-v2.json` whitelist.
  Both original GitHub ZIPs and their full member inventories are unchanged.

The previous immutable evidence at `febb7db` qualifies its parent `efb210e`.
It remains a separate milestone. This increment does not overwrite its
observations or count old executions as new final-source evidence.

## Remaining closure conditions

The concrete declared profiles now have stronger same-source resource,
behavioral, host and lifecycle evidence. Whole-language soundness, general
Rust-equivalent unwinding and cancellation, backend refinement, arbitrary
C/C++ conversion and general resource-state migration remain open. Real net
optimization benefit and an incremental NDU advantage over strong equal-budget
controls are still unestablished. All six workstreams are not fully closed.

No finite qualification justifies an absolute-safety claim or a guarantee of
the true global optimum for arbitrary programs, inputs and machines. Runtime
optimization remains bounded by the admitted grammar, current proof profile,
measured cost assumptions and independent publication checks.

## Frozen package verification

The outer archive contains **4,182 original files / 1,220,350,688 bytes**. It
retains **39 original CI ZIPs** whose inventories describe **15,637 members /
2,165,373,534 bytes**. The latter are reconstructed only when requested and
are not extra unique coverage or additional benchmark executions.

The archive is **315,103,156 bytes**, split into **51 parts**. Its SHA256 is:

```text
c1598116563c13783da2c07e8ac60f1dc84f4372cd5b1f820255309a92b3efa3
```

`RESTORE.py --verify-only` completed successfully, reading and hashing all
51 parts and all 4,182 archived payloads, checking the XZ checksum and the
source/count/index bindings. It executed no project program and did not
materialize another CI extraction tree. The collectors and packager separately
rehashed every original CI ZIP member against the existing extracted bytes.
Allow about 3.39 GB for the restored raw files plus optional CI expansions,
in addition to the compressed input and temporary verification file.

`SOURCE-ISOLATION.json` records a final read of all 4,021 source-parent files
(275,775,054 bytes), each matching its Git blob. The evidence prefix preserves
original file bytes on different host checkouts. `SHA256SUMS` covers the final
direct reports, readers, manifests and archive parts.
