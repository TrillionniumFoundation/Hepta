# FS9 C-string aliases for the native unixOpen peer

Status: AUTHORING ONLY. No AST, assembler, HIA generation, B3, VM, actual image, syscall or combined test has executed this revision. There is no workflow activation in this delivery. The original 42-group timeout remains FAIL. All preceding frozen inputs remain untouched.

## Concrete interface gap

The new complete unixOpen parent permits a non-NULL filename whose first byte is NUL, as the original selected Linux C path does. The existing raw OPEN_CSTR28 and STAT_CSTR29 can carry that empty C string. ACCESS27 and UNLINK9 reject an empty byte span before making a syscall. Following a real failed journal open with EACCES, original C may call access on the same empty filename. A private fault-injected open can expose this route; no actual native counterexample has been run for this new gap. The parent adapter must not manufacture ENOENT or skip an original operation.

Two new operations carry the same explicit arguments and output shapes as their old counterparts, with empty path additionally allowed:

| New operation | Existing counterpart | Actual Linux x86_64 syscall |
| --- | --- | --- |
| 30 ACCESS_CSTR | 27 ACCESS | access, 21 |
| 31 UNLINK_CSTR | 9 UNLINKAT | unlinkat, 263 |

Correction to an earlier planning message: existing opcode 9 is unlinkat; opcode 10 is mkdirat (258). No code or executed evidence ever used that mistaken verbal mapping.

For nonempty paths the new aliases retain the corresponding old validation. No embedded NUL is accepted. The HIA owner appends exactly one NUL, and the unchanged fixed carrier checks the complete logical payload and final NUL before the real syscall. The private caller/FD token and argument checks remain. ACCESS requires no directory token, mode 0..7 and zero unused fields. UNLINK retains the existing directory token lookup and unsigned32 flags constraints. These operations return the actual raw syscall result; neither carrier nor parent synthesizes success or errno. Ordinary old opcodes 1..29 retain their decisions and mutation order.

## Exact changes

PATCHES.json contains complete before/after pins and every literal replacement. Applying each list forward yields the complete new file. Applying every inverse in reverse order yields every original byte.

The FS owner extends its opcode bound and existing path family to 30/31. Only the two new aliases join the empty-string exception. No old descriptor creation, retirement, syscall counter, GROW/ACK or result logic changes.

The fixed ASM changes only its maximum 29 to 31 and the final dispatch tail: old 29 still goes to the same STAT helper; 30 jumps to the existing ACCESS helper; 31 jumps to the existing UNLINKAT helper. All actual syscall bodies, path/extent/guard checks, namespace leases, syscall error handling, CLOSE and EINTR rules are byte-identical.

The outer issued-request gateway changes only its two maximum-opcode comparisons and logical module/output revision name. Its full immutable request checks, caller/action correlation and prohibition on bypassing registered DB descriptor policy remain. The inner trace validator adds exactly syscall-map entries 30:21 and 31:263; no VM comparison, full buffer assertion, source pin, expected count or budget is removed. The independent entry-selection optimization candidate is not included.

## DMS proof transfer

The actual pinned DMS9 source_program is 70707 bytes, SHA256 95e13ccf13d9780c06e089773133479a44fd83e6d9fc9fe5f0a40820c7946e3e. The new DMS10 source_program is the same length, SHA256 be06bdfccb352998a53eb09f572f0f77fc00c6bc76d98060537d85442cd9491e. The only DSL change is the single gateway comparison dms_read(s, 64) > 29 to > 31. No new buffer read, alias, resize, parameter rebind, branch guard or byte-reader implementation is introduced.

Reversing the new bound to 24 produces the original reviewed DMS8 source_program exactly, SHA256 7fe09da5b8d59c14d1b5cd6fbc65b4c937677e410356d843a74affc62770d310. The new helper requires both the new exact source digest and that full reversed original digest before applying the original f0/header/call-origin analysis. This remains a strict source proof, not a hash allowlist or external authentication mechanism. The workspace >=8192 and source >=320 guards, dms_length totality, fixed u64 shift semantics, entry short-circuit exception, unknown-alias failure and original analysis body remain unchanged.

The old/new source_program hashes above were obtained by mechanically reproducing the frozen literal substitution and VALUES suffix, first verifying the exact old known digest. That is not Python AST execution, HIA generation, or a native result.

## Required next execution

Before activation, derive all new source/image/compiler/runner pins in a fresh build with the unchanged 128-function /1536-block /8192-op /256-block-per-function /16-parameter profile and original B3 10 CPU /20 wall /256 MiB /1 MiB limits. Retain the whole original 42 groups, 33 packer tests and 84 oldVM/newVM/native controls under their original aggregate budget, and add real empty access/unlink operations with complete request, raw syscall ACK, trace and whole VM/native bytes. The ongoing cost diagnostic must finish before changing original test execution organization.

The parent-to-actual-FS framer and fixed private issuer are subsequent work. This source revision grants no Store authority, does not make external byte headers trustworthy, and does not close SQLite migration, SQL31 transactions or ordinary Store.
