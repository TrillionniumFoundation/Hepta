# Core/Rust convergence: exact f654 and public e0 evidence

This package preserves the actual local and public executions of the bounded
Core/Rust convergence candidate, together with its source reconstruction,
original failed controls, independent review, and the original official CI
failure. It does not convert a later repair or a historical qualification into
an execution on a different commit.

## Source identities

| Role | Commit | Tree |
| --- | --- | --- |
| Existing PR405 parent | `192d2cbba7e49bde3b03af73685ecf96f6fb1b05` | `30c20454c3e08990a7995306f31ff21acad182f4` |
| Frozen local convergence | `f6540186aa34c991b2082d59cd998b857f78ced4` | `7adcc2a0333b48374b4add2d8132d1998c5cc48c` |
| Public PR410 convergence | `e0b9012a249167b5bc5b0f3bd243899344621080` | `7adcc2a0333b48374b4add2d8132d1998c5cc48c` |

The two convergence commits have the same tree and the same PR405 parent, but
their commit identities and actual executions remain separate. The source
export retains 32 exact UTF-8 files, Git modes and blob IDs, a full-index patch,
and an independently reconstructed tree. The export's original
`qualification_running` status is a historical snapshot and is not rewritten.
Later actual execution receipts carry their own outcomes.

## What changed

The integration preserves PR405's existing opcode catalog, schema registry,
Core checker, runtime, Machine, sealed-memfd differential custody, immutable
argument snapshot, nested returned-field origins, and bounded empty-record
walk. It adds the already qualified finite raw Rust Copy-record frontpass to
that newer implementation, restoring one route into the existing primitive
Core and Machine without a second evaluator or a production-authority switch.

The raw candidate accepts only explicit monomorphic acyclic Copy records,
including nested and empty records. Nominal types, zero-width bindings and
source-derived export eligibility are checked before erasure. Unsupported
forms anywhere in the module fail closed. This is not general raw composite
support. The direct raw CLI's executable hash checks are distinct from the
sealed custody of the production differential wrapper.

The composite v4 adapter accepts the historical string origin only when it
names the original primitive borrowed formal with sufficient permission; it
then uses the newer existing origin resolver. The newer field-origin grammar
is retained. ELF driver contexts restore real selected-executable/alias
identity and exception cleanup checks while preserving current dispatcher and
bound-IR behavior. The separate P3 patch reads and rechecks the admitted
canonical C source and refuses a direct leaf source symlink; it preserves the
stronger existing migration IR and captured-stdin publication behavior.

## Actual required execution scopes

| Gate | Actual local f654 | Actual public e0 | Retained scope |
| --- | --- | --- | --- |
| Rust crate | 96 tests / 19 harnesses, pass | 96 tests / 19 harnesses, pass | Full existing crate plus raw frontpass tests |
| Raw record collector | 9 methods, pass | 9 methods, pass | 13 exact normalizations, 43 executions, 47 refusals; 103 native processes per run |
| Bound-v4 API collector | 8 methods, pass | 8 methods, pass | 155 positive observations, 37 refusals, 72 legacy report comparisons per run |
| Historical composite-origin collector | 13 methods, pass | 13 methods, pass | 153 Rust observations, 4 raw refusals, 31 native calls per run |
| Current field-origin and mixed-origin selection | 16 methods, pass | 16 methods, pass | 239 Rust observations, 11 raw refusals, 4 source cases; 54 oracle native rows plus 6 negative controls per run |
| Shared guards | 70 methods, pass | 70 methods, pass | Actual protocol, linker, registry and workflow guards |
| Required migration selection | 177 methods / 27 modules, pass | 177 methods / 27 modules, pass | P3 owner retained both exact-head runs |
| Canonical safety selection | Not repeated on f654 | 340 actual methods, pass in this workspace | Every expected method has one ordinary passing event; source, tools and external inputs stable |

These scopes overlap. Their counts must not be added into a count of distinct
coverage. The safety contract retains all 277 PR405 selectors and all 126 prior
raw-record selectors, including the 46 old selectors absent from PR405, then
adds current field-origin, mixed-origin and P3 obligations for exactly 340
selectors and 36 capabilities. Discovery alone is not execution; this package
also retains the actual 340-method event multiset and full logs.

The public Rust binary has SHA256
`090ea31c9631aae744d8a72b3eb1f753bba1a36edf887d564145546865761362`
and size 4,204,464 bytes. Executed binaries, native artifacts and original
per-gate build/process records are included. The full source identity checks
cover the materialized tracked tree; that coverage is not full-project test
coverage.

## Original official CI failure remains a failure

On public e0, official source/application run `41055139018`, job
`124060656375`, completed the safety selection with **339 ordinary passes and
one failed subtest**. The original artifact ZIP, its content, and the job log
are retained. The failure was the `fork_and_stall` case of the native child
limit test: the existing 0.2-second observation ended as a timeout while the
assertion required actual SIGSYS. The original record alone does not determine
how startup, scheduling, loading and evaluation divided that elapsed time.

The local public e0 run passed all 340 methods in its recorded environment.
That success does not erase the official failure or qualify the skipped later
official steps. A separately preserved controlled-startup experiment and a
later two-file test-fixture repair have separate source identities and belong
to the guard-fix evidence package, not this e0 execution corpus.

The separate actual generic Rust LLD fixture red is also preserved. It is a
different test-fixture defect: a bound-IR fixture supplied a generic linker
spelling directly to a production guard requiring an ELF driver. It is not
the cause of the official native-child timeout.

## Provenance and restoration

The producer scripts, selected environments, source before/after inventories,
tool versions and hashes, exact outputs, source exports, publication receipts,
initial development failures, corrections, and final independent e0 review
are included unchanged. The independent reviewer audited original contents
without adding native executions. Reviewer-only harness/metadata failures and
their corrections remain in that review archive.

The NDU profiles use retained original executables from the official public147
artifact. Their original compiler versions, build costs, source pins and
denied authority remain unchanged; these are new runtime observations using
retained artifacts, not newly measured builds. The package includes their
restoration receipt, exact identity/handshake outputs and derived transport
manifests. The transport change is the local executable path only.

The original ZIP is recoverable from the immutable public evidence commit
`156dbba842999b1165e0964146decf58b3fc64a7` at
`evidence/hia_core_closure_20261029/hosted-147d39-evidence/full-release/`.
Its retained publication map and 89-part offset manifest specify all bytes;
the original size is 370,966,739 bytes and SHA256 is
`515b2166e3b47c0b51b46421f67531eb053ac21266a8202cba8ba0ba8dc95c6c`.
The package includes the root's actual remote full-stream reconstruction
receipt. Huge toolchain installations and this already published whole ZIP
are not duplicated here.

## Limits

Python remains the production admission/execution authority. No optimization
policy or production switch is changed. These finite qualification profiles
do not establish general memory/provenance, arbitrary recursive ADTs, complete
initialization/escaping/external lifetimes, callbacks/reentrancy/threads,
asynchronous cleanup, all historical migration configurations, independent
agent efficiency, representative throughput/tail latency, physical devices,
whole-language soundness or backend refinement. Logical resource ledgers and
address-space limits are not RSS measurements. The broad P0–P7 obligations
remain open.

The archive manifest and full-stream readback bind every included file's
path, mode, bytes, SHA256 and Git blob ID. Archive-part identities describe
transport only and do not add execution or qualification claims.
