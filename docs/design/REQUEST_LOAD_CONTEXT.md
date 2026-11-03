# Isolated request-owned loader context

This is an experiment stacked on #615 at
`374fa13c0e9b7cf97ab300ee009b4d6afeb68620`, not production integration. It adds no
CLI flag, changes no `hepta/` files, and imposes no global production defaults.
The earlier reader primitive by itself did not solve loading or revalidation.

## Concrete contract

`experiments.request_load.build_plan.execute()` admits the existing native
request, creates one Context with the native Budget's existing monotonic deadline,
and keeps that context across package discovery/inventory, graph loading,
Prepared's extra binding parse, and every fresh graph/identity recheck. No helper
resets counters. A second execute creates a new context. Native stdout/call quotas
remain the existing request Budget, not a new allowance.

The Context is explicit, owner-thread-only, non-reentrant at checkpoint/load
boundaries, terminal after budget failure, and cannot be supplied as a serialized
receipt. A supplied Prepared project must belong to the same context. This is an
ordinary Python ownership convention, not protection against malicious in-process
mutation of objects or callback code.

All limits below are experimental and caller-selected; these values are not a
proposal to silently reject existing production projects:

- Source/header/sidecar/lock: 1,000,000 bytes each; manifest: 64,000 bytes.
- One cumulative reader: 32,000,000 OS-returned bytes and 1,024 read invocations.
- Inventory: 4,096 entries and directory depth 16. Every entry counts, including
  irrelevant files and empty directories, before filtering or sorting.
- Packages: 128 loaded instances, 512 dependency visits, depth 16.
- Modules: 256 parsed modules, 1,024 visits, depth 16. Cache-hit edges count too.
- Ancestor manifest discovery: 1,024 checks across the request.
- Hepta parse calls: 256, at most 20,000 tokens per source and 200,000 tokens
  cumulatively, including EOF. Parser nesting: 48, never above production's 96.
- Metadata parse calls: 256; JSON structural nesting 32 after decoding its supported UTF-8/16/32 encoding. TOML parsing has byte
  and invocation admission only; no independent TOML complexity claim is made.

Reads use opened-descriptor regular-file checks and bounded chunks from #615.
Per-read role caps share the aggregate counters, including rereads and streaming
inventory digests. Once a path has a stricter admitted role, later default reads
of that resolved path retain that cap. Original headers with misleading `.hepta`
filenames therefore cannot gain a larger source allowance during revalidation.
Post-stat growth still consumes at most one overflow sentinel before rejection.
Peak allocation is not equal to the byte counter: chunk joins, decoding, tokens,
ASTs, copying and reports allocate additional memory.

Inventory uses incremental `scandir` with bounded pending directories; only after
all entries are admitted does the original deterministic sort happen. Directory
symlinks are yielded but not traversed, preserving the original package rejection.
Dependency/module counts are cumulative across revalidation, not only unique paths
seen at the beginning of the request.

Token admission happens during lexing: a copied lexer loop appends into a checked
list, so there is no complete unbounded token list before checking the quota.
The next individual token may already exist at the boundary. Source bytes bound
that individual token. The parser uses the admitted tokens without tokenizing
again. The existing parser's iterative tree-depth validation is retained, including
its long-expression-chain refusal. Additional nesting limits are opt-in. These
checks are not a formal parser complexity or AST heap bound.

## Compatibility and isolation

The original package/module algorithms are copied into `experiments/request_load`
with explicit context plumbing, not monkeypatched into production. Their upstream
module/package/lexer/parser file hashes are pinned by a regression test. An
upstream change requires reviewing this experimental fork, not blindly changing
the pin. This duplication is deliberate research isolation and is not the proposed
production architecture.

Within admitted inputs, standalone, locked-package, diamond-import and source-file
symlink reports/identities match the production loader. Stale locks retain
`E_LOCK_STALE`; directory symlinks retain `E_PACKAGE_SOURCE_LINK`. The loader's
existing source-path bindings, graph identity and unchanged checks remain intact.
Budget rejection is a separate RuntimeError type so existing ValueError and
HeptaError catches do not turn exhaustion into a misleading parse/race error.
Ordinary reads/errors retain their old diagnostics where the copied code handled
them; structured budget diagnostics remain a later integration gate.

The first profile rejects all source overrides, including an empty mapping,
before reading. It does not claim compatibility with IDE/in-memory edit flows.
Prepared's default path remains available to existing experiment tests. Explicit
context mode routes the sidecar, all binding source reads, original/private header
reads, extra Hepta parse, identity rereads and graph reloads through the context.
The native build wrapper creates the context after request admission and before
its first graph read. Existing production APIs do not import this code.

## What remains outside this boundary

- Native compiler binaries, driver identity, generated C, artifacts and observed
  sysroot dependencies retain the earlier experiment's separate behavior. The
  C importer consumes the already byte-admitted private snapshot, but its own
  native header parser/probe work is not charged as Hepta parsing.
- Parsing/checking/transformation/deepcopy/serialization are synchronous Python.
  Input/token/count gates limit admitted work indirectly, not a measured heap or
  hard CPU ceiling. Context checkpoints do not preempt blocking filesystem calls,
  metadata operations, C header parsing, checker work or cleanup.
- Directory and source checks do not freeze mutable filesystem topology. Symlink
  replacement and in-place mutation remain subject to the original revalidation,
  not an atomic snapshot or a security boundary.
- Locks still describe the existing content schema. No new lock format,
  authenticated dependency closure, foreign safety or binary authenticity claim.

## Executed controls and qualification

The new suite exercises all six #615 read paths through the context; low remaining
allowance during unchanged()/Prepared reload; empty/irrelevant inventories; depth,
edge and parse/token exhaustion; exact role caps and post-stat growth; stale/valid
locks and identity parity; source symlinks and FIFO refusal; reentrant checkpoints;
metadata depth/counts; independent contexts; absence of Path.read_bytes fallback
for loader/qualification inputs; unrelated project refusal; real native run and
locked build with late mutation preserving the previous output.

Independent review reproduced a UTF-16/32 escaped-quote depth-scanner bypass
and a default Prepared CRLF normalization regression. Both were fixed and added
as permanent controls, with independent adversary rechecks. All 41 new context
controls pass locally. The complete experiment/importer suite runs 136 controls:
135 pass and only the actual Rust reference skips locally because rustc is absent.
The additional 28 production module/package controls require actual Rust for six
cases; hosted qualification must run the complete 164 with no skips or failures.

Run `python -m unittest experiments.request_load.test_context -v`.
The expanded existing exact-head native workflow also runs the original package/
module suite and all earlier char/reader/importer controls, requiring every planned
identity with no skips on both Linux x86_64 and AArch64. Remote results must be
checked against the published commit before claiming that finite matrix passed.

Before any production proposal, replace the research fork with reviewed explicit
APIs, finalize diagnostics and compatibility policy, add workload-based quota
selection, and separately qualify the unmetered native/AST/metadata work above.
