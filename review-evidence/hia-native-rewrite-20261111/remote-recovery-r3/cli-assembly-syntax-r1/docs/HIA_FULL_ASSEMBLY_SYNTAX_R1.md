# Full public assembly syntax owner, new revision 1

Status: **NEW AUTHORING ONLY**. There has been no AST generation, native compilation,
native entry, CLI action, semantic admission, renderer or cold qualification for
this revision. The previous bootstrap compiler assembly mode is not this owner.

## Original contract and coverage

The reference is exact commit
0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5,
hepta/hia_agent_assembly.py, 15,216 bytes, SHA256
e37095496bf159ad573a31214d4d73e916648b4f0664edb541014f54681fbc03.
The owner implements _source and _parse_assembly_document, including the complete
public limits: 1,048,576 source bytes, 16,384 lines, 16,384 bytes per line,
256 functions, 4,096 blocks, 16,384 operations and 256 items per list.
The compiler compiling this owner still has its original distinct
128-function / 1,536-block / 8,192-operation / 16-block-parameter profile.

Whole-source type/length/UTF-8 checks precede control/BOM checks, then total
line count, then every line's byte/CR check, then any syntax interpretation.
Only LF splits lines and one trailing CR is removed. Only ASCII SPACE/TAB are
stripped at a line edge. Regex whitespace and list strip use all CPython
Unicode 15 whitespace scalars. All list item counts and all empty items are
checked before validating each name or parameter.

Functions preserve the original params, returns, effects, entry and optional
return_loans validation order. Operations preserve args, out, attrs order.
Original grammar recognition order and terminator/function/block transitions
are explicit HIA state. Each error emits its entire original exception text,
error code class, exact line or None and syntax phase.

The exact strict preflight source is pinned to Git blob
2198579e4e1882c44593f1c7b9253ec788a90f78, SHA256
293e22e217cba119dad1c7a4e04b5a9cd714cbeafdfdc4c9b15f4f716557896c.
Its algorithm is reused by an explicit development AST transformation:
all reads use the requested source span and the key table and stack are
rebased into disjoint private regions. Source helpers receive the same private
workspace. The preflight's status return is widened from u32 to u64 without
changing any rejection or grammar branch. No runtime Python parser is invoked.

Attributes first use 2,048 nodes / depth 16; return_loans first uses
257 nodes / depth 2. The second decode preflight uses the original
262,144 nodes / depth 128. The first strict gate already excludes floats,
duplicate decoded keys, unpaired surrogates and nonfinite literals.
The subsequent HIA integer-production check applies the actual command digits
setting after the two preflights, before object/list shape validation. It
accepts unlimited digits only when that actual setting is zero. Source strings
and JSON numbers are not converted by a host callback.

## Entry and event

The real wrapper is R/W/W and immediately borrows its second argument read-only.
The semantic entry is source read, command read, workspace mutable. Input source
and command are immutable private issued leases. They are not external authority.

Command is exactly 96 bytes / 12 little-endian u64 words:

| Word | Meaning |
| --- | --- |
| 0 | HIAASC01 |
| 1 | Version 1 |
| 2 | Nonzero session lease |
| 3 | Nonzero request sequence |
| 4 | Source kind: 0 unsupported Python type, 1 exact str as surrogatepass UTF-8, 2 exact bytes |
| 5 | Actual integer digit limit: zero or at least 640 |
| 6 | Actual source byte extent |
| 7–11 | Zero |

Kind 1 capture mechanically preserves Python code points. It does not decide
admission. Character count happens before encoding rejection, and byte count
after encoding rejection. A malformed surrogatepass transport is private BAD.
Kind 2 preserves the byte-length-before-UTF-8 ordering.

Workspace minimum is 163,840 bytes. It contains control state, literals, a
disjoint 8,192-byte JSON stack region and a 131,072-byte JSON key region. Those
physical capacities cover the largest possible 16,384-byte JSON line and the
original second preflight; they are not new language admission quotas.
Source bytes are copied after the first GROW. Syntax executes in a counting pass.
Only a completed syntax construction can request the exact output allocation.
A writing pass then reproduces the same syntax JSON, and its final byte count
must equal the measured byte count.

Event at workspace offset 256 is exactly 128 bytes / 16 words:

| Word | Meaning |
| --- | --- |
| 0 | HIAASE01 |
| 1 | 0 constructed; 1 GROW; 2 original semantic refusal; 3 private BAD |
| 2–3 | Exact lease and sequence |
| 4 | Original message ID, zero on construction |
| 5 | One-based source line, zero for None |
| 6 | Entire original _source gate passed |
| 7–8 | Complete output span offset and length |
| 9 | Source character count when established |
| 10 | Exact input byte count |
| 11 | GROW required workspace |
| 12 | Original E_HIA_ASSEMBLY_LIMIT class, otherwise zero |
| 13–15 | Zero |

The native return is 128 for a completed construction or semantic refusal,
0xfffffffe for GROW, or 0xfffffffd for BAD. Any BAD after a full valid workspace
borrow sets permanent poison. An undersized workspace cannot safely establish
that invariant; its fixed caller must discard the lease.

A command change on any retry is rejected. After source copying, a same-length
source mutation on the output GROW is also rejected. Before that copy the fixed
issuer must retain exactly the same immutable source; a repeated header is
not source authentication. Native control tests explicitly preserve this limit.

## Result lifetime and semantic boundary

A construction result is **complete syntax JSON**, not a Core receipt.
It preserves Python dictionary insertion order, including functions before
exports, blocks before return_loans, operation op/args/out/attrs and every
attribute map's original key order. String and integer JSON spellings may remain
the original admitted spellings; they represent the same constructed values.
The result has no additional 8 MiB or 262,144-node quota.

The caller must protect/copy the complete output view before releasing or
reusing this workspace. The later object-front-door owner must parse this issued
construction without a public raw JSON precheck, apply the original forward
bounded snapshot traversal, then the reverse structure traversal and byte
accounting, then canonicalization and actual primitive admission. Sending this
JSON directly to public raw44 is not equivalent.

Public assemble_program wraps later Core refusals as HIAAssemblyRejected with
the original code/text, phase core_verification and no guessed syntax line.
diagnose_assembly includes source SHA/bytes only if the whole _source gate passed.
A separate native coordinator will preserve these behaviors.

The public renderer remains a separate required owner: actual initial admission,
primitive v6/v7/v8 and structured-input refusal, complete canonical text,
then a fresh complete assembly and canonical Core roundtrip. No compiled
bootstrap subset can substitute for that path.

## Fresh validation and evidence

The new corpus includes all three primitive schema headers, all 29 Unicode
whitespace scalars in each grammar/list role, invalid UTF-8 and surrogatepass
boundaries, whole-source first-error controls, list/count/name/type precedence,
exact 256-function and 4,096-block limits, source/line limits, original JSON
limits and digits, the line frontier preceding the nominal operation budget,
all terminators and deterministic lexical mutations.

The reference's construction objects are compared with exact ordered
kind-preserving JSON bytes; Python equality alone is not used. Every refusal's
entire message, code, line and prefix-completion condition are compared.
Each actual native entry preserves full source, command, workspace before/after,
event, return and guard bytes through lossless content-addressed storage.
Private controls include every reserved command field, repeated terminal calls,
persistent poison, changed command and copied source on GROW, corrupt needed
state and undersized workspace borrows.

This is a new corpus. Its exact expected inventory is saved before execution,
and the final result must execute that entire inventory. It inherits no old
CLI, publication, compiler or assembly counts. No result is yet claimed.
