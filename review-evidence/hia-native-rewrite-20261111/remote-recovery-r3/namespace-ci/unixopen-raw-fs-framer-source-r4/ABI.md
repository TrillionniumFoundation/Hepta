# unixOpen raw-effect continuation and live-file FSTAT — source checkpoint r4

This checkpoint contains new HIA authoring source only. It has not been parsed, generated, verified by CoreVM, compiled by B3, or executed natively. The preceding unixOpen parent actual FOLLOW46 component passed 85 semantic cases, 42 protocol controls, 833 VM entries and 833 native entries against 88 selected original C calls; all 18 effects in that component were explicitly foreign. Those counts are not evidence for this new framer.

The new framer owns the mapping of all eight raw effects to the existing shared namespace outer/DMS/FS instance, their complete request bytes, expected original operation and stage, next outer call, FS sequence and syscall sequence, and production of the exact 512-byte parent reply. It does not emit a reply before the actual completed FS result and actual post-completion outer workspace have been correlated.

The fixed issuer still needs implementation and testing. Its descriptor must bind the actual live outer context, generation, result/readonly-workspace lease and complete source request. The private HIAUFP01 header is not external authentication. A Graph ID, copied generation word, or ordinary byte buffer is not namespace authority.

## Original effects and exact FS operation

| Original parent operation | Original stage | FS operation | Inputs and result |
|---|---|---|---|
| 1 getpid | 10 or 11 | 26 | No arguments; actual positive 31-bit PID |
| 8 access | 32 | 27 or new empty-string alias 30 | Exact original path bytes, F_OK; actual errno |
| 9 geteuid | 40 | 16 | No arguments; actual u32 UID, including UID 0 |
| 10 fchown | 41 | 24 | Same logical FD token and original u32 UID/GID |
| 11 unlink | 50 | 9 or new empty-string alias 31 | Exact original path bytes; actual errno |
| 14 close | 62 | 8 | Same logical FD token; ordinary FS consumes its token before actual close |
| 15 fstat | 70 | 15 | Actual original logical FD; complete 144-byte stat result |
| 16 stat | 71 | 18 or existing empty-string alias 29 | Exact original path bytes; complete 144-byte stat result |

Alias selection for a zero-length C string happens in HIA. The actual OS still receives an empty NUL-terminated path and decides errno. The framer does not synthesize ENOENT. The former generic UNLINK operation is 9, not 10; operation 10 is mkdirat. No source or executable used the mistaken verbal mapping.

Paths are raw POSIX bytes, excluding embedded NUL. No UTF-8 requirement, total pathname ceiling, record cap, new call-depth limit or silent truncation is introduced. Integer size arithmetic is checked for u64 overflow before writing or reserving a span.

## Input S: original parent request lease

S is a 128-byte control header followed by the complete original logical parent PENDING output. Its size is exactly 640 plus path bytes.

| Byte offset | Meaning |
|---|---|
| 0 | HIAUFS01 |
| 8 | BEGIN 1 or COMPLETION 2 |
| 16, 24 | Nonzero framer context pair |
| 32 | Strict next framer invocation |
| 40 | Complete parent output extent, 512 plus path bytes |
| 48 | Nonzero immutable source lease |
| 56 | Actual shared outer context ID |
| 64–127 | Zero |
| 128–383 | Original HIANUO01 pending header |
| 384–639 | Complete original HIANUQ01 request header |
| 640 onward | Complete original raw pathname bytes |

The parent scope, call, action, operation, stage, filename lease, FS scope, last FS sequence/syscall sequence, peer 6, process lease and errno are checked for agreement. Opcode/stage/argument shapes are checked before any lower request is constructed. COMPLETION must preserve every byte of BEGIN S except command bytes 8–15. The complete saved request is retained until consumption; neither a partial digest nor a reconstructed subset substitutes for its bytes.

## Input R: fixed issuer's actual shared-outer observation

R has a 128-byte HIAUFP01 header followed by, in order, the complete lower request, its complete logical output, and the actual outer workspace. All spans are subtractively checked against the actual input extent. The header has kind 1 or 2 matching S, request/output/workspace lengths at 16/24/32, actual context ID at 40, generation at 48, actual native return at 56, actual result/workspace lease at 64, actual completed outer entry serial at 72, actual process lease at 80, and zero reserved bytes 88–127. The process lease must equal the original parent's process lease. The same context allocation generation must remain equal on completion; its actual entry serial must strictly advance. This matches the fixed carrier, where CONTEXT_SEQUENCE is assigned only when a context is created and ENTRY_SERIAL increases on each image invocation.

BEGIN contains no request/output, only the actual ready workspace. COMPLETION contains the exact HIA-issued lower request, completed output and post-call ready workspace. It must have the same context and context allocation generation, with a strictly newer actual entry serial. The fixed issuer must prevent a mutable or substituted snapshot from being presented under this header. The HIA framer checks state/identity/extent consistency; it does not establish provenance for arbitrary caller-supplied R.

## Dynamic workspace and GROW

The first 256 bytes store framer state; the next 256 contain the event. Full immutable BEGIN S is copied at 512. A complete lower request is placed at align8(512 + len(S)); the 512-byte reply is placed after align8(request offset + len(S)). Every addition and rounding is checked for u64 overflow.

Initial state must be zero. Ready states permit only the strict next invocation. BEGIN capacity failure emits GROW without issuing a lower command or committing a new invocation. The trusted caller must retry the same private immutable input while growing only the workspace; recomputation is pure. Emitted GROW metadata contains no old pending lease. Once PENDING is issued, the complete request/input identity is fixed. COMPLETION needs no additional allocation because reply space was already reserved.

An accepted completion becomes DONE. It cannot be consumed a second time. A new BEGIN requires the next invocation. Invalid framing marks permanent BAD whenever at least 8 workspace bytes exist; workspaces smaller than 8 bytes cannot physically store a poison marker and the return still rejects. Original short-workspace behavior is retained as a representational limit, not described as persistent poison when no marker fits.

## Lower request and actual completion

The lower request is HIANDJX1 USER with the actual same shared outer scope, next call and source lease. It carries the complete HIANFR03 request and original path bytes. FS call sequence and syscall sequence must both advance by exactly one for these eight single-primitive operations. Request bytes, returned original FS caller/operation/sequence, full logical extent, actual role-6 completion and cleared pending fields are checked before parent publication.

Stat success requires the complete 144-byte result. The FS header's device, inode, mode, UID, GID, size and link-count fields are checked against that actual returned payload. Failure requires the exact empty payload and zero result fields. UID 0 is valid. Successful operations preserve the parent's previous errno; failures propagate the actual OS errno. PID/UID paths cannot accept an invented error reply.

The parent reply is exactly 512 bytes. It contains the original scope/call/action/op/stage; original request bytes at 256; the original ABI fields at 152=context ID, 160=generation, 168=actual completed entry serial and 176=original complete lower-source lease; exact next FS/syscall counters; and the original operation's result projection. It never adds COMMIT, ROLLBACK, retry or success publication.

## Registered-file FSTAT command 12

The existing generic FS command 11 continues to reject access to a token registered in the main DB directory. unixOpen's late verifyDbFile stage needs a real FSTAT after registration. The new command 12 is a distinct read-only continuation, not a weakening of command 11.

It requires a live file handle, a live parent node, a unique exact registered FS token, zero extra arguments/payload, operation 15 and the strict next FS call. The same file/node/token relationship is checked again when the actual DMS/FS result completes. Only FSTAT is permitted. CLOSE, locks, writes, token retargeting and arbitrary descriptor access remain rejected. The existing single registration FSTAT behavior is unchanged; the late original verification FSTAT is a separate original caller operation.

The source patch is recorded as unique exact replacements over the FS9 outer. Every byte outside those replacements is equal to the base. This is a textual proof only, not an actual HIA result.

## Remaining scope and mandatory next gates

The new code covers eight raw effects. Allocation, process reset, global unused-FD reuse, temporary-name generation, robust-open loop, creation-mode lookup, URI lookup, node registration and logging retain their own pending peers until joined. The complete initializer, put/get, 31 relational operations, transaction log, multiwriter migration and installed ordinary Store still remain open.

Before activation, the new FS9, DMS10, outer command 12 and framer require fresh authoring/CFG/Core validation, original B3 10 CPU/20 wall/256 MiB and the original source profile limits. All original 42 physical cases, 33 packer cases, 84 old/new VM/native packer comparisons and 85+42 parent controls must remain represented in the complete joined gate. New full-state framer controls must include all eight raw operations, empty/non-UTF8 paths, UID 0, actual stat fields, retired/mismatched handles, mismatched complete request, stale/wrong context/generation, sequence exhaustion, GROW and persistent rejection. The same actual FS instance must supply results; a Python business callback cannot be counted as that connection.

All original 900 aggregate, 90 CPU/180 wall/1 GiB process and 4M VM steps/32 MiB arena/64-depth limits remain unchanged. No claim that the new source fits these gates is made before an actual run.

## Static r2 correction retained

The r2 source checkpoint wrote the four nonzero parent receipt fields as result-lease/context/generation/outer-call. The retained parent validates that these fields are nonzero but its documented/fixture ABI assigns context/generation/entry-serial/source-lease. That nonzero admission is not evidence that the r2 metadata was correct. r3 restores the exact original meanings, reads an explicit actual entry serial and process lease from the trusted issuer descriptor, checks the process against the immutable parent request, and requires the completed serial to advance. The emitted source lease is the same one used in the complete lower request and returned original FS caller field. r2 was never parsed, generated, compiled, or executed. Its original bytes and this source-level finding remain retained.

## Static r3 generation correction retained

Reading the exact fixed carrier ceb21c40b4287b1eff4e998d61fdfcfa59fb3110 shows that CONTEXT_SEQUENCE is a creation generation, while ENTRY_SERIAL advances per image call. r3 incorrectly required both generation and serial to increase. r4 requires the exact same generation and a strictly greater serial. The concrete context ID is a private issued handle for the actual process/context allocation; it must not confuse a valid root node number zero with a missing issued handle. No synthetic new generation may be invented to make an actual same-context result fit. r3 remained entirely unexecuted.
