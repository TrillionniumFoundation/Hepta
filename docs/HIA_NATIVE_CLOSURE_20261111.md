# HIA native continuation: source audit and delivery boundaries

This continuation starts from `TrillionniumFoundation/Hepta` main
`c80eb2ecc5d08421a3d124c879edb33cefff2267`. The HIA language lives in this
repository. `hepta-runtime` is a separate deployed process/MCP owner. No
independent repository named HIA was returned by the organization search.

**The complete HIA-native replacement remains open.** The former high-level
language has already been removed. The remaining hosted production modules
still implement supported operations. They cannot be retired by relabelling a
native kernel or a bounded self-compilation run as whole-product equivalence.
The final retirement target remains one HIA-native product with preserved
language semantics, ordinary callers, installation and recovery.

## Exact baseline audit

The frozen tree has 2,532 blobs, including 1,072 Python files, 147 production
`hepta/*.py` modules, 50 HIA assembly files and 12 HIA JSON programs. These counts
are inventory facts, not a semantic completion percentage. The regenerated
`HIA_NATIVE_REWRITE_INVENTORY.json` records indexed current bytes, parsed Python
imports and static callers; it explicitly does not claim every line has a
semantic proof or that dynamic/external caller closure is established.

The installed CLI has 15 actions and is still a Python entry. The independent
native stdio program has five operations with its own scoped protocol. Its path
cannot replace the ordinary worker executable without implementing that worker's
request/report and durable operation contracts.

Frozen main's [Actions run 42949936235](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42949936235)
passed 252 source tests in 396.046 seconds. Its native cold run timed out after
180.091260887 seconds; only six of eleven wrapper checks passed. Thirty stages
were marked complete in the index, and two further stage reports were written
before termination. Those 32 reports contain 3,718 true checks. Eight index
entries remain incomplete: two with reports and six without reports. None of
these incomplete entries or skipped downstream suites is a pass. All 562 declared cold
source entries were independently matched to the frozen Git objects. The raw
artifact digest is `c1d137bf8f54afaff613e725c152e84ecb19cab20fd03f94531e8392ffef11ec`.

Later main also preserves a separate ROG qualification of exactly that same
`c80eb2e` source: **3,931 retained regression tests** passed without errors,
failures, skips or expected failures, and its cold replay passed. The
[original full readback](../review-evidence/hia-native-rewrite-20261111/v61/c80-qualification/full-readback.json)
records the exact tree, all source identities and each step. This independent
machine run does not erase the GitHub timeout, and neither baseline result
qualifies the later merged v62 source.

A current Runtime discovery read and exact manifest-byte hash check found
different worker/backend identities from the frozen main source. The live
backend profile still reports `self_hosted: false`. This is an observation of
issued discovery bytes, not an independent read of every deployed file or loaded
process. No production worker cutover, state-root migration, configuration-pin
update or default-release activation was performed.

## Implemented native responsibilities

### Ordinary worker request payload

[The request kernel](HIA_WORKER_REQUEST_NATIVE.md) implements ordinary JSON
parsing, finite binary64 conversion and shortest printing, canonical byte
production, request schema/field policy, SHA-256 identity, catalog matching and
the tool-name codepoint bound in checked-in HIA. An explicit installed-source
selection connects it to the existing ordinary worker without falling back on
a selected failure.

Independent review found and corrected four real defects in the initial
development candidate: temporary key sorting violated the foreign arena's source
order; reserializing the full envelope imposed a stricter byte ceiling than the
original five-field digest payload; distinct digest diagnostics were conflated;
and `admit(raw, None)` selected plain canonicalization instead of refusing a
missing trusted pin. Original failed observations remain separate from the
fixed v4 tests. The exact 8 MiB counterexample is retained in the regression.

The ordinary service tests exercise completed replay, changed-key conflict,
retained running intent/unknown outcome, malformed requests before store
creation and an actual wheel installation with authoring imports forbidden.
The independent review covers numeric boundaries, Unicode, diagnostic ordering,
private concurrent scratch and native-buffer canaries. These controls establish
the observed responsibility; they do not implement native SQLite or all eleven
tool methods.

### Immutable release publication

[The release installer](HIA_RELEASE_INSTALL_NATIVE.md) implements a complete
bounded multi-file publication operation. HIA checks an operator-pinned package,
safe entry names and modes, complete directory inventory, content and identity;
a fixed Linux syscall adapter holds descriptors, writes/fsyncs files and performs
`renameat2(RENAME_NOREPLACE)`. A HIA packer emits the standalone ELF. No Python,
libc or child executable is required by the installed program at runtime.

Independent actual-host checks found and corrected unnecessary directory-read
authority on ancestors, inherited SGID stage modes, and restrictive ambient
umasks. The operator root is left intact; the installer fixes only its private
process umask and newly created stage mode. Publication preserves existing
releases. A separate read-only `verify` resolves observable bytes after an
interruption or lost receipt. Failed private stages can remain; activation,
administrative staging recovery and reference-aware retirement are still
separate unfinished responsibilities.

### Cold qualification without reducing the gates

Compiler-name fixtures now perform a single combined alpha-renaming operation
with the original input admission and final complete render/parse/semantic
checks. The complete 2,447,154-byte name-reference output remains identical.
Evidence capture hashes the exact bytes written to each ZIP member in one read,
while retaining independent member replay, compressed-byte hashes and final
source/inode/mode/owner checks.

One bounded archive thread seals completed stages while two original oracle
slots continue executing. At most two archive tasks are admitted; a stage remains
pending until sealing succeeds. Every future and sealing failure is observed.
The 180-second qualification deadline, three-second cleanup deadline, all 38
stages, independent reference executions and both compiler fixed points remain.

The isolated cold-repair candidate passed all 11 wrapper checks, all 38 stages
and 5,049 checks in 164.326411014 seconds. Its original compiler generations
agree; its modified second/third generations agree and differ from the original.
All 38 archives, 42,623 member files and 2,396,853,095 uncompressed bytes were
independently replayed. This isolated result does not qualify the later combined
source. Combined-source results belong to the matching contract and retained
evidence for this continuation.

## Combined v61 observations before merging later main

The combined v61 candidate passed a fresh source-only cold replay with
CPython 3.14.10: **11/11 wrapper checks, 38/38 sealed phases and 5,049/5,049
qualification checks**, in 172.841585262 seconds against the unchanged
180-second deadline. The manifest binds 574 declared source files plus the
support contract itself; it does not purport to bind every repository document.
Original B1/B2/B3 bytes agree at
`0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`.
Modified M2/M3 agree with each other and differ from the original compiler.

The ordinary worker suite and its independent adversarial review then passed
**18/18 tests**, without skips or expected failures, using a new application
build admitted by that exact cold report. A separately retained cold-bound
worker build has image SHA-256
`a206d5e0a54fa67a30655461ff970e1810e38070a86972d7b0f3d631b6b6e1dd`.
The cold-bound release installer has executable SHA-256
`3b089aa5c54fc93bf3b0eb0b11018f2dba0b49142e53be78086b5cf9193196d0`.
These bytes match their independently reviewed development images. The final
release development image passed six source/VM tests and thirteen actual
non-root desktop kernel tests; those executions retain their own development
run identity. The cloud environment refused ptrace fault injection, and that
failure remains recorded separately.

The [evidence index](../review-evidence/hia-native-closure-20261111/evidence-index.json)
distinguishes original reports and logs, exact issued artifact bytes, connector
snapshots and derived summaries. Original absolute paths inside retained
reports are left unchanged. Historical failures are preserved alongside fixes;
development and isolated-repair results are not relabelled as combined runs.

The full pre-merge source runner regenerated all 41 components without changing
bytes and ran 267 tests. Its workflow shell fixture had three failed subcases
because this local Python 3.14 installation lacked a `python` alias beside
`sys.executable`. The original failure is retained. Providing a private alias to
the same interpreter made all four workflow controls pass; no source gate was
relaxed. The subsequent v62 source suite is a separate current-source run.

## Integration of later main

While this continuation was running, main advanced to
`647885c5c3ff067b6477011123335ad5a1aef78e`. Its complete Git commit and tree
identities were verified and merged, preserving the native composite-v4
returned-loan origin decisions, the independent controls and evidence, and the
equivalent structural-traversal changes. The combined current profile is
`selfhost-core-linux-x86_64-v62-native-request-release-origins`.
All earlier v61 observations above remain attached to their earlier sources;
they do not qualify this new merged profile.

The first v62 attempt failed after 40.074269915 seconds because the shared
filesystem ran out of free blocks while creating the seed's temporary link
directory. Its wrapper and original `Errno 28` traceback are retained. Completed
historical cold directories were losslessly archived and every regular file's
bytes, mode, UID and GID independently read back before releasing their unpacked
copies. No production source or other worktree was removed.

A fresh v62-r2 run then passed **11/11 wrapper checks, 38/38 phases and
5,049/5,049 checks in 168.469563822 seconds**, with CPython 3.14.10. It binds
576 declared sources plus the contract. A separate standard-library audit
rehashes those 577 entries before and after replay, verifies all six actual
compiler images and phase/process relationships, and reads all 42,661 members
of the 38 ZIP archives through EOF. The independently read payload bytes total
2,396,852,094; manifests add 6,952,530 bytes. Both compiler fixed points remain
valid, and the owned process tree finishes before the unchanged deadline.

The matching v62 application builds reproduce the request and release image
hashes above. The ordinary worker and independent review pass **18/18** tests
under CPython 3.14.10. The complete composite-type and returned-loan-origin
suites pass **28/28** under CPython 3.12.14, including real installed-wheel
normalization. Neither suite has skips or expected failures. Their independent
interpreter identities are retained in `v62/` evidence; GitHub's Python 3.14
workflow remains a separate gate.

The v62 language run also passes **1,242/1,242** checks under both original and
modified compilers, followed by **10/10** assertions over that actual report.
All 41 source generators reproduce their checked-in bytes exactly after the
merge. These checks preserve the existing admitted profile and explicitly do
not establish the unavailable whole-v8 or whole-product claims.

The complete current source-control suite passes **283/283 tests** under
CPython 3.14.10, with no failures, errors, skips or expected failures. Its
before/after declared-source hashes remain identical. The unit runner took
394.074 seconds; preparation plus execution took 402.205244260 seconds.

## Remaining production owners and retirement gates

| Owner | Current actual responsibility | Required closure before retirement |
| --- | --- | --- |
| `hia_program_composite._Elaborator` | Nominal SSA, record/enum operations, task helpers, partial tokens, binding native loan origins to generated entry slots and export eligibility | Complete HIA lowering for composite v1–v4, independent meaning/result/refusal controls and ordinary default integration |
| General compiler/backend | Canonical machine plans, broader retained Core layouts, object/linking and target support beyond the selfhost profile | Native producers for every retained language and ABI target, with explicit profile boundaries, cross-target execution and source-matched qualification |
| `HIAAgentService` and `AgentStore` | Tool methods, refs/namespaces, SQLite/WAL transactions, intents/completions, costs, slots, versions, leases, evaluation, adoption and rollback | Full native ordinary worker with same-key conflict, unknown outcomes, crash/restart, original-operation observation and state continuity |
| Worker and foreign bridge | Administrator parsing, Python object materialization, service entry, installation readback and report serialization | Native complete request/report/service protocol with current code/profile pinning |
| Build, authoring and default CLI | Python seed generation/custody, package hooks, source assembly, complete project orchestration and the 15-action installed CLI | Native clean-machine rebuild from an explicit bootstrap trust root, native module/library build and equivalent default installed behavior |
| Release lifecycle | Initial native bundle installation/readback now exists; active-release choice, staging recovery, upgrade/cutover and retirement remain external | Persistent version/ref ownership, no duplicated effects, restart/rollback and real default activation |
| Runtime and proof | Retained runtime/library owners, independent VM/reference roles and scoped proof computation | Native production replacements with preserved proved/unknown/refuted/timeout semantics; keep independent reference controls |
| `hepta-runtime` deployment | Existing Rust MCP/process owner and a separately pinned hosted worker | Full native worker ABI/report parity, real SSH/MCP first use, old-operation continuity and independently observed cutover |

No supported operation was removed to improve a completion count. No skipped
test was converted to a pass. No historical source or result was assigned the
identity of the new combined candidate. Production deletion is still blocked
by the implemented responsibilities in this table, rather than by missing user
authorization.
