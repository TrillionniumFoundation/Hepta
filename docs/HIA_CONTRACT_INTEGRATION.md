# One HIA admission contract with explicit optimization profiles

This integration combines the bounded pipeline from PR #328 with the independent
implementation in PR #325. Their original branches and recorded experiments are
preserved. The combined source requires its own frozen qualification; historical
test counts, timings and compiler identities are not results of this new tree.

## Agent-facing contract

`hepta hia routes` inventories source/IR/backend routes and the five explicit
optimization commands. Every supported input route ends in the same canonical
`hepta.hia_program.verify_program` authority. Route metadata is descriptive and
does not authorize a candidate or an executable. Unsupported source languages
and legacy routes do not silently select another backend.

| Command | Meaning and boundary |
| --- | --- |
| `verify-translation BEFORE AFTER --function NAME` | Fresh all-input proof of one public scalar function's complete acyclic values and first traps. Different acyclic CFGs can be compared. Calls, loops and resources return `unknown`. |
| `verify-optimization BEFORE --candidate AFTER` | Fresh compositional proof over the whole module while preserving the exact CFG, interfaces and ordered resource/call skeleton. Scalar segments and values observed at effect barriers are compared. This does not prove general loop or resource transformations. |
| `fold-constants BEFORE --output AFTER` | Generate the whole-module constant-folding candidate and require `verify-optimization` before writing checked Core. |
| `optimize BEFORE --function NAME ...` | Generate finite selected-function proposals, prove each with `verify-translation`, obtain an advisory native NDU ranking and charge actual recorded costs. Returns a decision/Core; does not publish native code. |
| `build-optimized BEFORE --candidate AFTER --output LIBRARY` | Fresh compositional validation followed by the existing artifact-bound native build. A saved proof receipt is not an input program. |

The ambiguous constant-folding use of `hia optimize` from the draft #325 is now
named `hia fold-constants`. There is no missing-argument fallback between folding
and NDU ranking. Both proof result schemas and their meanings remain explicit:
`proved/disproved/unknown` is not translated into
`verified/rejected/unknown/timeout`, or vice versa. Consumers revalidate actual
Core and recompute the applicable proof instead of trusting a success field.

Both dependency extras (`verification` and `optimization`) now install
`z3-solver==4.15.4.0`. The compositional checker retains its exact runtime version
check, loaded-library identity and bindings digest. Its prior 4.13.4 results are
historical. The integration regression exercises both engines concurrently with
fresh independent Z3 contexts and tests their deliberately different scopes.

The finite action set now also includes explicit scalar equality guards with
specialized and generic clones. The guard remains executable Core, and every
selected candidate still requires fresh all-input validation. A narrow
single-arrival parameter-encoding reduction preserves reachability and first
traps; independent tests compare it with the prior encoding. An already-paid
cost lower bound may skip dominated proof work but never grants admission.
See [HIA_GUARDED_SPECIALIZATION_20261028.md](HIA_GUARDED_SPECIALIZATION_20261028.md)
for the frozen real-NDU experiment, equal-information controls and separate
direct-baseline deployment accounting. Its results retain their tested SHA.

## Two native NDU transports, no implicit protocol fallback

The shared NDU evaluator is advisory in both transports. The candidate-cost bridge
retains its original builder bytes and pinned upstream
`d3c2d760eca5065fc966820379c35c6e8d56e855`; the recursive event-utility bridge uses
`2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b` and its separately named builder.

| Transport | Build command | Process environment |
| --- | --- | --- |
| Finite candidate cost ranking | `tools/build_hia_ndu_bridge.py --upstream SOURCE --output NEWDIR` | `HEPTA_NDU_BRIDGE`, `HEPTA_NDU_BUILD`, `HEPTA_NDU_UPSTREAM` |
| Recursive event utility | `tools/build_hia_recursive_ndu_bridge.py --ndu-source SOURCE --expected-source COMMIT --output NEWDIR ...` | `HEPTA_RECURSIVE_NDU_BRIDGE`, `HEPTA_RECURSIVE_NDU_IDENTITY` |

Their request schemas, build identities and receipts remain incompatible on
purpose. Same-process native tests exercise both normal protocols, missing
recursive environment, exchanged build receipts and exchanged protocol payloads.
See [HIA_NDU_BRIDGES.md](HIA_NDU_BRIDGES.md) for exact build and invocation shapes.

## Resource, wire and native increments retained

The merge retains the independent Rust byte-owner CFG/call execution increment,
call-scoped loans and failure ledgers. It also retains the C++ lexical scope,
conditional construction/move, early-return and reverse-cleanup increment from
#325. These are different declared subsets: neither implies general returned
loans, arbitrary C++ source translation or a source-to-HIA refinement theorem.

The shared bounded JSON boundary rejects lone Unicode surrogates and object keys
that would collide after wire conversion. Direct LLVM allocation declarations
retain nullable fresh `noalias` returns and `no-builtins`. Actual allocator-null,
simultaneous-live-address, allocation-failure and cleanup tests remain required.

The imported explicit empty-state `AdaptiveRuntime` and the bounded generation-
lease/background runtime retain separate lifecycle contracts. The first refuses
switching with calls in flight; the second keeps old generations alive until
their leases are released and checks generation/epoch, cancellation and actual
preparation cost before a conditional publication. Neither implements general
live owner/loan/state migration. The runtime's actual Linux sealing/readback
checks remain mandatory even when Python lacks named `fcntl` constants; test
readiness now reflects Linux/memfd capability instead of those Python names.

The subsequent resource increment extends the same Rust Machine with canonical
bulk operations and v7 chains, including stopped destructor ledgers. It retains
the v2 byte-only report and uses an explicit v3 execution profile for extended
modules; see [HIA_RUST_OWNED_MEMORY_VM_20261028.md](HIA_RUST_OWNED_MEMORY_VM_20261028.md).
Source returned projection borrows still use the existing checked inlining;
that remains the default v1 frontend contract. The explicit v8 frontend instead
retains returned byte-view helpers as actual calls/returns with parameter-origin
metadata. `hia lower --core-schema hepta.hia.program.v8` feeds the same canonical
authority, Python VM, independent Rust resource VM and Linux x86-64 emitter.
Old versions, nominal normalization, unsupported targets and arbitrary lifetime
relations retain their refusal boundaries. See
[HIA_RETURNED_LOANS_V8.md](HIA_RETURNED_LOANS_V8.md).

Captured C source spelling, semantic driver dependencies and decayed array/
function-attribute ABI refusals are now checked before translation, including
the record-view route. [C_MUSL_COMPARE.md](C_MUSL_COMPARE.md) describes migration
of two unchanged, complete musl 1.2.5 comparison components. Its finite native
oracle and authored platform/contract adapters do not imply a whole-libc build
or general C++ translation. The existing C++ reuse and ownership gates remain.
The next complete C component is unchanged upstream `stb_divide.h` v0.94:
six public functions, both declared preprocessor configurations, all active
declarations accounted for and independently compiled originals. Pure scalar
lazy conditionals and checked definite assignment are shared lowering additions.
[C_STB_DIVIDE.md](C_STB_DIVIDE.md) separates source migration, native ABI/oracle
checks, target-only undefined-input traps and actual-host qualification. An
authored seven-host CI step is not evidence that every host has executed it.

[HIA_SCALAR_STATE.md](HIA_SCALAR_STATE.md) adds one explicit scalar state value
on top of the existing generation-lease runtime. All-input equivalence includes
that state argument; revision checks prevent duplicate commits, cooperative
cancellation can discard an in-flight result, and rollback changes code without
rewinding data. Heap/loan/stack migration and profitability remain unestablished.

## Proved total native candidates and finite economic search

[HIA_PROVED_TOTAL_RUNTIME.md](HIA_PROVED_TOTAL_RUNTIME.md) adds an explicit
runtime profile for acyclic u8/u16 checked division and remainder. Every exported
function needs a fresh all-input normal-return proof before any native build;
candidate equivalence is an additional independent obligation. A self-equivalent
program that traps remains inadmissible. Unknown, timed-out, stale and malformed
proofs cannot authorize a candidate. The original syntactically total profile
remains the default.

[HIA_NATIVE_RETIREMENT.md](HIA_NATIVE_RETIREMENT.md) defines observable resource
retirement, finite pending-cleanup capacity, native operations attempted at most
once, and explicit ownership-bound file cleanup. A cleanup error does not undo
an already committed selection or become a fabricated successful release.
The actual post-close observation is made before an outer temporary-directory
helper can remove artifacts. This does not establish crash recovery or protect
against arbitrary mutation by the trusted host process.

[HIA_ECONOMIC_SEARCH_20261028.md](HIA_ECONOMIC_SEARCH_20261028.md) specifies a
separate frozen experiment using the actual recursive NDU bridge to choose
finite measure/stop actions. Exact arithmetic over the same supplied scalar
model, fixed actions, a calibration-selected fixed action and exhaustive search
remain controls. Costs include the dependencies each strategy actually uses;
same-information costs and full single-deployment charges are also retained.
The local native driver has its own explicit byte recurrence and independent
long-run checksum oracle. It is not a `ScalarStateSession` commit experiment.
Formal measurements belong only to their recorded source and protocol hashes;
the earlier all-abstain `01310b2` campaign is not replaced or relabeled.

## Fresh integrated qualification

`tools/qualify_hia_integrated.py` is the local single-run acceptance entrypoint.
It requires the exact committed `--expected-head`, a clean tree and all tracked
files materialized. It checks actual compiler/solver/emulator/tool identities,
real Linux sealing, both upstream Git inventories and native bridge replies,
the Rust crate, and exactly one full verbose Python discovery with zero skips.
Critical module coverage is a view of that same discovery, not another test
denominator. Source and external identity inventories must be unchanged after
the gates. Failures and raw outputs are retained in the new output directory.

The existing CI `release_check` already runs full Python discovery. CI prepares
both independent bridges before that required gate; it does not invoke a second
integrated full discovery in the same job. Existing finite/native qualifications
and the seven-host ABI matrix remain in place.

The prior bounded-source CI run `40551242912` passed all 50 release sub-gates,
including 2,640 Python tests without skips, but correctly failed its final source
snapshot check. The subsequent standalone gate's initial inventory shows 319
new files under `rust/hia-core-shadow/target/` and no modified or removed source
paths compared with the release gate's initial inventory. The old release report
did not retain its own final inventory, so that diagnosis uses the immediately
following gate as corroborating evidence. CI now exports an external Rust target
directory before full discovery. The source snapshot refusal remains unchanged;
new release reports also retain both exact inventories and explicit added,
removed and modified paths. The historical failed run remains a failed run.

The first frozen integrated source, `a4ab87889616925306b84f9699316d1a850c183d`,
completed 2,716 Python tests with ten failure entries in three JSON-key preflight
test methods, zero errors and zero skips. Its source and registered external
identities were unchanged. The preflight incorrectly called `json.dumps` for
primitive keys before refusing converted-name collisions or nonfinite keys.
The correction uses exact built-in key spellings without an encoder invocation,
retains the original refusal assertions, and checks actual wire-byte parity for
valid keys. The selected CI gate now includes both in-memory wire-boundary test
modules and the cross-profile proof tests; its earlier 207-test pass did not
cover those separate wire modules. The failed full run remains retained and is
not converted into a pass by the focused repair checks.

The collector does not rerun the standalone performance/Agent campaigns or
reassign their observations to this source tree. Reduced native timing controls
inside existing regression tests still execute and are identified as such.
No integration result establishes NDU incremental gain, universal Rust
performance superiority, whole-language soundness or global optimality.
