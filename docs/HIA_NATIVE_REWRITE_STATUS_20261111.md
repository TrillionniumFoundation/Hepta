# HIA native rewrite: current source, implementation and remaining owners

Baseline audited on 2026-11-10 America/New_York:
`c2d937e5eec734af5c1d5d0519afc7e3a91df58a`.
The repository is `TrillionniumFoundation/Hepta`; the only active remote branch
is `main`. This report does not create a second product line or restore the
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
source files. The new patch adapter adds a hosted custody module while moving
the actual transformation into HIA. File-count ratios are not a useful measure
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

## Remaining implementation owners

| Area | Native implementation present | Work required before retiring the remaining owner |
| --- | --- | --- |
| Assembly/compiler | Direct x86-64 generation, resource checks, original/modified self-compilation, native `assemble` | Full retained language/composite lowering, general linking and all claimed targets; retain the compiler's actual limits separately from the larger checker's limits |
| Primitive Core admission | Declarations, 50 opcodes, SSA/CFG, calls/effects, ownership and loans; standalone checker | Nominal/composite normalization, complete object/diagnostic custody and independently justified equivalence for retained semantics |
| Workspace/project build | Native module graph, naming/privacy, Core materialization and semantic compiler pipeline | Complete project build, library resolution, installation/upgrade/recovery and file/process ownership without hosted orchestration |
| Agent editing | Native slice/snapshot/data helpers and full snapshot-bound patch application | Remaining query, batch/impact/receipt orchestration, durable publication and ordinary full worker protocol |
| Agent state | Native artifact hashing, no-replace file publication and content byte store | Metadata/ref encoding and issuance, namespace/kind authority, SQLite transactions/WAL, request intents, locks, costs, leases, slots, versions and uncertain-operation recovery |
| Runtime and proof | Native kernels and selected runtime/verification applications | Complete retained runtime/library ownership, independent VM/reference roles, proof computation/certificates, exact unknown/refuted/timeout semantics and other target qualification |
| Authoring and packaging | Checked-in HIA source, native compiler and application packers | Replace remaining Python generation/build/custody entry points, native installer and reproducible clean-machine rebuild without importing the retired stack |
| HeptaRuntime integration | Existing eleven-tool contract and explicit candidate identities | Native worker request/report parity, original operation continuity, immutable installation pins, real SSH/MCP first use and qualified cutover |

The independently deployed Runtime is a separate owner. An earlier read-only
audit observed an X230 worker still containing the old language, but that
historical installation is not asserted to be the current live state. A matching
tool catalog does not establish matching executable, worker or backend identity.
No live worker, service, state root, release pin or request was migrated by this
source continuation.

## Retirement and completion criteria

The obsolete high-level source language and compatibility entry were already
removed from the active repository. Remaining hosted components retain actual
callers and responsibilities. Their deletion requires a corresponding native
owner with the same retained semantics, ordinary caller integration, matching
source qualification and recovery evidence. Independent reference controls
cannot be deleted merely because the implementation under test is now native.

The next complete vertical slice is the native durable Agent owner: exact
metadata/ref/request protocol, write intent before effect, same-key conflict and
unknown-result behavior, interrupted publication/restart, adoption and rollback.
Then bind that owner to a clean native installer and the actual Runtime provider.
Successful payload transformation does not close these transactional obligations.

Only after those paths and the retained compiler/runtime scope pass complete
acceptance can Python/Rust/other legacy production owners be removed. The
inventory grants no deletion authority and does not mark an unimplemented path
as retired or passed. The final repository should have one HIA-native product;
this report records the work still needed to reach that state honestly.
