# HIA native rewrite: current source, implementation and remaining owners

Baseline audited on 2026-11-10 America/New_York:
`c2d937e5eec734af5c1d5d0519afc7e3a91df58a`.
The repository is `TrillionniumFoundation/Hepta`; product development continues
on `main`. The separate archival source-recovery PR #887 is not an adopted
compiler or an alternative product line. This report does not restore the
retired high-level language. Git history and original failed observations remain.

**Whole HIA-native delivery is not yet qualified.** The checked-in HIA compiler,
complete primitive checker, native workspace filters and native applications
are real implementations. The installed `hia` entry, Agent request authority,
build/install ownership and other retained components still contain Python.
Removing those owners now would remove supported behavior, not finish its port.

## Audit coverage and evidence

The [machine-readable inventory](HIA_NATIVE_REWRITE_INVENTORY.json) records the
complete indexed-file ledger, current file bytes and SHA-256, every retained
Python module's parsed imports, direct repository callers, public definitions,
native-source literals and explicit native selection variables. The collector
is `tools/audit_hia_native_rewrite.py`; it executes no inspected code. Missing
dynamic or external callers are explicitly unproven. This is complete static
accounting, not a claim that every line received a semantic proof.

The baseline contains 2,388 Git blobs, 1,039 Python files (including tests and
research), 144 production Python modules, 46 HIA assembly files and 12 Core JSON
source files. The patch and raw Agent result adapters add hosted custody modules
while moving transformation and diagnostic construction into HIA. File-count ratios are not a useful measure
of semantic completion; the current exact counts are in the inventory.

Baseline Actions run `42891040706` was independently read, including original
job logs: 216 source tests, 392 native component tests, 1,242 language checks,
10 language assertions and the 11-check cold wrapper passed. Original compiler
generations agreed; the modified compiler reached a distinct fixed point.
Those results qualify that original source, not this changed source. The raw
artifact metadata was read, but its entire archive was not relabelled as a
new independently replayed result.

Development and final qualification evidence is retained under
`review-evidence/hia-native-rewrite-20261111`. Development receipts preserve
their original source identity and failures; the final qualification record
must name the exact common source manifest. A source contract or compiled
image hash is an identity, not a qualification pass.

## Implemented in this continuation

### Immediate visibility of returned capabilities

The native complete Core checker previously created all results of a `call`
before adding them to the live capability inventory. A later result could
therefore miss an earlier conflicting mutable/shared return from the same
call. The independent reference rejected those programs.

Each returned owner or loan is now published to the live capability inventory
immediately; the enclosing instruction does not publish it twice. Actual old
and fixed native images were compared on four conflicting return patterns and
three legitimate patterns. The four old false acceptances now return
`E_HIA_LOAN`; valid shared and independent-owner cases remain admitted.
A fixed-seed differential exercised 30 real fixtures and 12,000 mutations,
with no remaining acceptance or error-category differences in that panel.
The minimal trap-only callee witness establishes a static policy mismatch;
it is not evidence of a demonstrated dynamic memory-corruption exploit.

### Direct HIA assembly in the native application

The native stdio application supports `capabilities`, `verify`, `compile`,
`render-assembly` and `assemble`. Direct assembly preserves the explicit build
profile (`flat`, relocatable ELF or executable ELF), keeps a separate inclusive
1 MiB input ceiling and retains semantic/resource refusal. It does not infer a
different language or output profile from the payload. Original and modified
HIA compiler sources can use the executable self-compilation path.

### Snapshot-bound structural edits in HIA

The [native patch application](HIA_CORE_PATCH_CLI.md) consumes `[BASE, PATCH]`,
extracts and fully verifies the original primitive Core, verifies its canonical
SHA-256 identity, applies the requested edit and fully verifies the candidate.
Only then may candidate JSON reach stdout. The two immutable HIA images run
four stages in one Linux x86-64 executable; no payload parser, serializer,
checker or editing interpreter is delegated to Python at runtime.

It supports function replacement/addition, operation replacement and terminator
replacement; exact target types; 1–64 edits; overlap refusal; v1 interface
preservation and explicit v2 preserve/migrate behavior. Original component-byte
quotas remain independent of canonicalized output length. Primitive v1–v8
Core admission is mandatory for both sides; nominal/composite normalization is
not silently erased. The application does not grant filesystem publication,
request replay, ref issuance or deployment authority.

The existing public patch path can explicitly select these kernels. The
installed source is packaged and participates in actual worker identity;
missing/changed resources or invalid selected manifests refuse without fallback.
The host adapter still materializes its existing Python result object and owns
its surrounding transaction. This preserves the existing ordinary caller while
the complete native Agent is still being built.

### Raw ordinary Agent patch results

The explicitly selected ordinary `hia_candidate` patch branch now passes the
authorized base and patch bytes directly to HIA. It does not construct Python
Core/patch objects, call the hosted verifier/editor or compute signatures and
receipts in Python. HIA returns the canonical candidate and complete existing
diagnostic bytes; full native Core admission still precedes and follows editing.
The existing store receives two opaque payloads and retains ref/context authority.

The independent [patch-result executable](HIA_CORE_PATCH_RESULT_CLI.md) exposes
the same calculation as `hia-patch-result v1|v2`. It writes a bounded `HIAPAR01`
frame only after both admissions. Candidate execution is still false; an editor
running natively does not mean the edited program has been executed. Original
artifact hashes remain distinct from canonical snapshot hashes. Existing v1/v2
receipt fields, interface sorting and default returned-loan equivalence remain.

Independent development controls compared 540 native cases (198 accepted and
342 refused), 11 actual Agent/SQLite cases and 10 HIA-packed CLI controls, with
no remaining difference in their covered behavior. The focused nine-test Agent
suite passed, including a real isolated installed wheel and four real SIGKILL
cut points: committed intent, published candidate, published diagnostics and
committed terminal response. The first three remain unknown after restart;
the last replays the retained response. A completed replay precedes any new
image admission. This verifies compatibility with the existing hosted journal;
it does not replace that journal with a native implementation.

The original local ptrace failures, a corrected `return_loans` test-fixture typo
and an initially incorrect cache-invalidation test remain in the evidence.
Development tests are not substituted for matching-source cold qualification.

### Complete nominal type sessions in HIA

The explicitly selected [nominal type owner](HIA_COMPOSITE_TYPES_NATIVE.md)
now performs the complete declaration and layout responsibility of `_Types`
in HIA for composite v1 through v4. This includes unused declarations,
generic applications and lexical bindings, by-value cycles, record/enum/task
layouts, stored-loan constraints, partial records, exact cache/active state and
the existing work budgets. The ordinary elaborator consumes native descriptors;
it does not rerun the hosted type algorithm on the selected path.

Private nominal keys are exact interned type identities in a held session.
They do not expand a shared zero-width type graph into an exponentially large
display string and never enter public normalized Core bytes. Primitive keys
remain their original strings. The 128-definition/instantiation, depth-32,
64-field, 32-variant, 512-slot and 32,768-step language limits remain explicit.
The arena layout accounts for lexical alias calls that do not increase layout
depth; their frames share a proven bounded region with symbolic nodes.

Development controls include independent Core VM execution before native
compilation, exact layout/error/state/counter differentials, four-version
ordinary normalization with the old type owner disabled, and an actual installed
wheel with build-tool imports forbidden. Original development observations are
retained by source/image identity. The independent boundary review also found
an init-envelope overhead issue at the original 8 MiB input limit; its failed
observation and correction must remain separate from earlier development passes.
The corrected private command envelope permits 8 MiB plus 128 bytes, while
public Core retains its original 8 MiB input, 262,144-node and depth-64 limits.
The complete program-to-command bound is at most five extra bytes, including
malformed inputs that reach the type owner. Five actual native-entry cases at
the public boundary preserve the hosted `E_HIA_FORMAT` result; an extra public
byte still returns `E_HIA_LIMIT` before native entry. The final development
suite passed all 18 tests. Independent raw ABI controls admit the exact private
limit and refuse one extra byte with output/state boundary canaries intact.
This type owner does not replace the operation elaborator, task helper generation,
returned-loan origin lowering, default installer or durable Agent.

A further independent fixed-seed panel executes the same r3 native image for
96 seeds and 1,032 initialization/resolution state observations. It compares
record, enum, task, generic and partial combinations, unused invalid declarations,
and state/counters after refusals against the retained reference. No differences
were observed. The original source/image identities and all observations are in
`review-evidence/hia-native-rewrite-20261111/v60/continuation`; this is development
evidence, not a new cold result or proof of equivalence over all inputs.

### Shared native builder source binding

The audit found that the shared JSON/kernel builder accepted a completed cold
report based on compiler hashes without checking the current complete source
manifest. It also accepted JSON `false` as a zero return code through Python's
integer equality. The builder now requires the current profile, exact integer
zero, every cold check, the complete source/contract map and the selected source.
It rechecks source, compiler and report bytes before publishing a manifest.
Custody controls reject stale/missing/extra source identities and changed build
inputs before publication. Their recording compiler stub is explicitly not
native execution evidence; actual native suites retain their separate gates.

The same complete gate now runs in outer application builders before they create
their parent output directory. Eight builders share this admission and recheck
the complete source map before publication; the existing workspace pipeline
keeps its independent full gate and now also requires an exact integer return
code. Nine application paths were checked against ten malformed or stale cold
receipts for both absent and pre-existing output directories: 180 refusal-boundary
observations preserve prior bytes, modes, inode and directory contents. Valid
bindings reach the native-build stage. These controls deliberately stop at that
stage and do not create a synthetic native qualification pass.

### Preserve cold evidence while removing repeated host work

The assembly source boundary uses the same exact forbidden-control-character
set through a compiled regular expression. Input limits, UTF-8/BOM handling and
error order remain unchanged. Name-limit fixtures reuse pure source-string seed
constructors instead of reconstructing unrelated accepted programs merely to
select one string; each actual reference case still executes its own admission,
assembly, interpreter and refusal controls. No qualification result is cached.

The complete old/new name-reference result is byte-identical: 2,447,154 bytes,
106 positive cases, 40 refusals and 52 programs. One local development comparison
measured 24.038 seconds before and 20.145 seconds after; 5,213 source inputs
retain their full outcome/error observations. These timings do not establish
a GitHub cold pass. The unchanged 180-second cold deadline, all 38 phases and
the original/modified compiler generations remain mandatory.

### Qualification observations

The first published v58 tree was exactly
`243ca1d7d25ba485681488ea330ff81167e0fff1`, committed as
`f174f9b970e227a2c6d3b98ea115cedba7f4e316`. Its Actions run `42933658467`
passed all 11 cold checks; the downloaded archive's SHA-256 and all 548 cold
source-manifest entries were independently matched to that exact commit.
The workflow failed because the language inventory retained the old profile
and support digest. Commit `ecf6886f43e325c411be38fea172bba0d79d7230` regenerates
both the inventory and its source contract. The failed workflow and original
logs are retained, without turning skipped later stages into passes.
Its new run `42934701069` passed both jobs: 222 source tests, 424 native component
test invocations, 1,242 language checks and 10 assertions, plus the 11 cold
checks. That exact v58 qualification does not qualify later v59 source edits.

The v59 commit `95ba911c347f8ef19cead56d04219093705219cf` passed 229 source
tests. Its first native attempt hit the unchanged 180-second deadline after
34 completed phases; all 3,758 checks in those completed phases were true.
Its second attempt passed all 11 cold gates, 38 phases/5,049 nested checks,
1,242 language checks and 10 report assertions. The archive and all 555 declared
cold-source entries were checked against that exact Git commit. The native job
still failed: nine Agent tests stopped in setup because `jsonschema` was absent;
the other 16 tests in that last group passed. Those nine errors are not passes.

Commit `bfea47b6267e4a2b18acb45e114aafcd9f466b1a` pins the missing CI dependency
to `jsonschema==4.26.0` and rebinds the source contract. Its first source job
passed 229 tests; cold again reached 180 seconds after 32 phases/3,718 checks.
All retained completed-phase checks passed, and process cleanup was confirmed.
Its only retry again timed out at 180.139949 seconds. The phase index records
28 completed phases and 2,876 true checks. Two additional scalar-cast reports
were actually written and independently verified, adding 736 true checks,
but remained pending in the index. The retained evidence therefore contains
30 independently checked reports and 3,612 true checks, without a complete
cold pass or any language/application test execution. Cleanup completed in
47.535 milliseconds with the leader reaped, ECHILD observed and no remaining
processes or errors. The source log was reused unchanged, not run a second time.
Repeated elapsed-time increases across identical inputs/images are measurable;
the available records do not establish a specific CPU, I/O or scheduling cause.
Later attempts retain their own source-bound results rather than overwriting
either original failure.

Two local cold attempts reached the unchanged 180-second limit and confirmed
their owned process-tree cleanup. The h execution connector subsequently
returned internal errors even for controller-only and known-state reads; the
uncertain remote source operation was not replayed with a new key. After the
connection recovered, the original environment job was observed successful and
the exact original source request/key was reconciled and observed complete.
A separately identified replay of the frozen `95ba911` Git tree passed source
reproduction, source controls, cold, language and every native component group.
The full retained suite then ran 3,896 tests in 1,742.849 seconds, with four
error records across three methods, no assertion failures, skips, expected
failures or unexpected successes. One public CLI fixture refused a temporary
directory beneath a Git ancestor; three UNIX socket setup records exceeded
the socket path limit. The original final status is HOLD, with full source
identity preserved. A revised external preparation tool requires a fresh short
temporary directory outside Git ancestors, checks a real UNIX socket round
trip and separately checks its disk/inode reserve. The failed complete suite
is not reclassified as passed by this environment correction.

The completed-stage archive now performs one complete ZIP-member replay and
binds that replay to three complete compressed-byte hashes on held descriptors.
Published bytes must retain the same inode, extent, mode and owner, with only
the expected hard-link ctime/link-count transition permitted. Source files
remain until publication and identity checks finish. Twelve archive tests
include actual replacement and in-place-change controls; failed sealing
preserves originals. A local read-only timing panel over 38 earlier completed
archives measured 6.126 seconds for full replay and 0.066 seconds for compressed
SHA-256. This is a bounded removal of duplicate work, not a measured CI speedup,
deadline change or new cold pass.

## Remaining implementation owners

| Area | Native implementation present | Work required before retiring the remaining owner |
| --- | --- | --- |
| Assembly/compiler | Direct x86-64 generation, resource checks, original/modified self-compilation, native `assemble` | Full retained language/composite lowering, general linking and all claimed targets; retain the compiler's actual limits separately from the larger checker's limits |
| Primitive Core admission | Declarations, 50 opcodes, SSA/CFG, calls/effects, ownership and loans; standalone checker | Nominal/composite normalization, complete object/diagnostic custody and independently justified equivalence for retained semantics |
| Nominal types | Complete selected declaration/layout session for four composite versions, including unused and symbolic partial obligations | Complete operation/helper lowering, returned-loan origin lowering and default installed integration |
| Workspace/project build | Native module graph, naming/privacy, Core materialization and semantic compiler pipeline | Complete project build, library resolution, installation/upgrade/recovery and file/process ownership without hosted orchestration |
| Agent editing | Native slice/snapshot/data helpers, snapshot-bound patches, complete patch diagnostics and explicit ordinary raw-byte candidate route | Remaining query, batch/impact orchestration, composite/import paths, default installation and ordinary full worker protocol |
| Agent state | Native artifact hashing, no-replace file publication and content byte store | Metadata/ref encoding and issuance, namespace/kind authority, SQLite transactions/WAL, request intents, locks, costs, leases, slots, versions and uncertain-operation recovery |
| Runtime and proof | Native kernels and selected runtime/verification applications | Complete retained runtime/library ownership, independent VM/reference roles, proof computation/certificates, exact unknown/refuted/timeout semantics and other target qualification |
| Authoring and packaging | Checked-in HIA source, native compiler and application packers | Replace remaining Python generation/build/custody entry points, native installer and reproducible clean-machine rebuild without importing the retired stack |
| HeptaRuntime integration | Existing eleven-tool contract and explicit candidate identities | Native worker request/report parity, original operation continuity, immutable installation pins, real SSH/MCP first use and qualified cutover |

The independently deployed Runtime is a separate owner. A new live discovery
and artifact read obtained and independently hashed its complete manifest and
backend profile. Its catalog digest matches `bfea47b`, but its advertised worker
and backend digests differ from that checkout; the backend profile still says
`self_hosted: false`. This observes issued artifact bytes and advertised source
identities, not an independent deployed-file or loaded-process audit. The earlier
historical X230 observation is not substituted for this current observation.
No live worker, service, state root or release pin was migrated by this source
continuation.

## Retirement and completion criteria

### Composite and compiler prerequisites

`hepta/hia_program.py::verify_program` invokes
`hepta/hia_program_composite.py::elaborate_program` before primitive native
admission. The explicitly selected native type session now owns nominal
declarations, generic binding, finite layout, by-value cycles, stored loans and
partial-declaration obligations; the no-selector path retains `_Types`.
`_Elaborator` still owns nominal SSA, record/enum transformations, inactive-slot
cleanup, task helpers, partial tokens, original-field returned-loan origins and
export eligibility. Composite v1 lowers to primitive v6, v2/v3 to v7 and v4 to
v8; changing those schemas would change the retained language.

The next semantic owner is complete nominal operation lowering, preserving all
four composite versions and the native type session's stateful obligations.
The current native JSON compiler frontend accepts v8; its 16 arguments, three
results, 128 functions and 256 blocks per function are smaller than some legal
normalized programs and the complete primitive checker's profile. Type-layout
replacement, full normalization and full compilation therefore need distinct
acceptance gates. A safe but incorrectly lowered program can pass primitive
admission while violating the structured source's meaning.

The retained composite ABI/qualification/bulk/returned-loan/partial tests and
historical `composite-native-72.log` contain actual allocator, refusal, wrong-result
and cross-target controls. They execute normalized code produced through hosted
normalization/emission; their historical results do not make those producers
native or qualify the current complete retained suite.

### Build and installed-runtime prerequisites

`pyproject.toml` still installs the `hia-core` Python distribution with
`hia = hepta.cli:hia_main`. Wheel/sdist source custody packages 24 kernel HIA
sources and the publisher's declared assets, but it is not a complete native
self-rebuild kit: the selfhost source, general stdio/result packers, their build
drivers and default installed native executables are not supplied through that
kernel resource mechanism. The worker request/report entry and its subprocess
custody remain hosted. A native installer must own compiler/packer/source pins,
default selection, executable publication and upgrade/recovery before that
delivery path can replace the Python entry.

The current B0 path is hosted assembly, machine emission and linking through
`assemble_program`, `emit_program_machine` and `compile_program_machine` with
`ld`. B1 onward performs real native HIA compilation, while the generation and
qualification drivers still use Python and its native mapping bridge. A native
delivery needs an explicitly retained bootstrap trust root and native build
orchestration; deleting the current seed/build drivers first would remove the
present clean-machine reconstruction path.

The shared `tools/build_hia_json_preflight.py::build` path now binds the
complete current contract and cold source manifest, as the patch/result builders
already do. This closes the observed stale-source admission gap; source binding
still does not establish the behavior of an application merely built afterward.
Actual application execution, installation and recovery remain distinct gates.

The obsolete high-level source language and compatibility entry were already
removed from the active repository. Remaining hosted components retain actual
callers and responsibilities. Their deletion requires a corresponding native
owner with the same retained semantics, ordinary caller integration, matching
source qualification and recovery evidence. Independent reference controls
cannot be deleted merely because the implementation under test is now native.

The durable Agent is a separate remaining vertical slice: exact
metadata/ref/request protocol, write intent before effect, same-key conflict and
unknown-result behavior, interrupted publication/restart, adoption and rollback.
Then bind that owner to a clean native installer and the actual Runtime provider.
Successful payload transformation does not close these transactional obligations.

Only after those paths and the retained compiler/runtime scope pass complete
acceptance can Python/Rust/other legacy production owners be removed. The
inventory grants no deletion authority and does not mark an unimplemented path
as retired or passed. The final repository should have one HIA-native product;
this report records the work still needed to reach that state honestly.
