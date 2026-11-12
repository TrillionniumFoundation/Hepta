# Native completed-call capsule mechanics — inactive source r1

This file accompanies Git blob 3df087271e4a7bb3258be5e87580f8cb3d56e728.
The fragment is 9,129 bytes, SHA256
a8e08c861ae6ece09b296c0696e642bf2ae63a4047ffefdbd50c5cf650c181f2.

No assembler, relocation checker, Core verifier, B3 compiler, VM, image entry
or physical process has run this new fragment. It has no executable entry
point. It is not a replacement for the full fixed carrier and cannot by
itself qualify an ordinary UnixOpen or Store operation.

## Actual source relationship

The fragment is written against the exact FS9 fixed carrier:
ceb21c40b4287b1eff4e998d61fdfcfa59fb3110. That carrier is unchanged here.
The companion HIA coordinator remains source revision2:
abbb7f40338e7b099e855281d7dab9ff64834eed, source-only checkpoint
6dc855298f38217710cf9a2b1f7ced4fa2a5ce8a.

The pending integration must allocate fixed roles7(parent),8(framer),9(issuer)
beside the existing role6 shared filesystem outer. The actual role9 context
owns pointers to exactly those three live contexts. Neither stdin nor a
Python fixture may set those pointers or invoke the completion/capture
helpers. Arbitrary raw pointers, headers, cached traces and caller-supplied
ACKs are outside this channel.

The original fixed carrier's guards, context registry, memory mutex and
primitive syscall paths are not modified by this fragment.

## Required fixed caller edges

1. The dispatcher allocates and copies a new exact first operand into the
   target's REQUEST, makes it physically read-only, sets CURRENT_DESC and
   CURRENT_LENGTH to that complete REQUEST, then calls begin.
2. begin validates membership against the three actual fixed context
   pointers and checks the real descriptor. It allocates a monotonically
   increasing process-local input lease, marks the call in flight and
   invalidates any previous completion.
3. The actual image or role6 continuation runs. The existing entry counter
   and native return are recorded by the fixed invocation path. A nested
   role6 call may use ACK for later entries; its original REQUEST is retained.
4. Only the real completion edge calls complete. It requires a strictly
   newer actual entry, one current in-flight call, a real u32 return and
   all original REQUEST/OUTPUT/WORK mappings frozen read-only.
5. capture is permitted only from this actual completed record and only to
   one of three role9-owned capture descriptors. It emits the full header
   and every logical byte of original REQUEST, OUTPUT and WORK.
6. The role9 HIA coordinator must then validate the private correlation and
   choose its next native action. The capsule helper does not interpret
   statuses, decide an errno policy, synthesize success or resume the parent.

GROW preserves the actual immutable input and in-flight call; begin must
not be called a second time for the same replay. Distinct HIA-issued calls
may have equal input bytes but receive distinct actual input lease values.
A completed capsule may be recopied for a coordinator's own GROW replay;
it cannot become a new completion or bypass the HIA action/call checks.

## Operands and permissions

The existing carrier physically changes OUTPUT and WORK back to read-only
between image entries. This permits a complete immutable snapshot. The
capsule's flags80/88/96 describe the original invocation ABI permissions:

- First operand is read-only for roles6/7/8.
- Second operand is read-only only for the R/R/W framer role8. Roles6/7
  originally had a mutable output operand.
- Third operand is the original mutable workspace for all three roles.

All three real mappings must nevertheless be physically read-only when
capture occurs. This clarifies the wording of the preceding HIA ABI draft:
the flags are not a claim that the frozen workspace mapping remains writable.
No source implementation change is needed for that clarification.

## Exact private metadata

The added fields occupy2496..2631 in the fixed4KiB context, above the existing
LAST_MEMORY_CALL at2480. The three40byte capture descriptors occupy1200..1319,
after existing trace/scratch bytes and before the old NSML2304 fields.
The original source has no literal/context field use in those new regions;
actual composition must still assert all declared ranges are disjoint.

| Offset | Field |
|---:|---|
|2496|role9 master pointer, set only by fixed boot|
|2504|actual fixed context ID6/7/8|
|2512|current actual immutable input lease|
|2520,2528|requesting native coordinator call and action|
|2536,2544,2552|actual completion entry,return,valid|
|2560,2568,2576|master-only fixed FS,parent,framer pointers|
|2584,2592|master process identity and next input lease|
|2600,2608|reserved integration root call and return edge|
|2616,2624|in-flight marker and entry serial before the call|

The helper validates role9/root ownership before following any member.
It compares a source pointer with a registered fixed pointer before reading
that context, then requires role, actual ID, master link, nonzero live
generation and not-retired state. The capture must match the current
ENTRY_SERIAL and ENTRY_RETURN exactly; a later entry invalidates it.

The source input counter refuses exhaustion before advancing. Descriptor
allocation follows checked u64 additions for128+input+output+workspace;
no new filename, byte, node or Store-record quota is imposed.

## Capsule and new evidence trace

Capsule format remains HIAUIC01,128byte header plus the three complete
logical operands, in exact order. It includes actual role/context/generation/
entry/return, actual input allocation lease, original entry permissions,
actual process identity and requesting call/action.

The fragment writes a new96byte trace header with magic HIAUIT01 and kind5,
followed by that complete capsule. The twelve header words are:

magic,kind,actual-final-entry,capsule-bytes,actual-role,context-ID,actual-return,
actual-source-lease,requesting-action,requesting-call,generation,zero.

Existing native BEFORE/AFTER and primitive records remain unchanged.
The new reader must correlate a capsule with the actual earlier native
records and retained original REQUEST; it must not count this mechanical
trace as an additional native entry or a successful filesystem operation.

## Still missing and required next gates

The complete fixed dispatcher, role8 read-only second-operand entry path,
boot/context allocation, stable original-input association, private BEGIN/
CHILD channels, role6 return-to-parent path, exact final512byte ACK transfer
and tracing reader remain to be composed and tested.

The required gate includes native-only capture, full old/new VM and native
return/input/output/workspace comparison, actual failed primitives,
GROW without producer repetition, stale completion/source-lease/context
rejections and exact canaries. Every source and final HIA/image/ELF must be
pinned. Original B3 10CPU/20wall/256MiB/1MiB, native90process-tree CPU/
180wall/1GiB/core0,900aggregate,4M VM steps,32MiB arena,depth64 and all original
profile limits must remain unchanged.

Remaining nonraw UnixOpen peers, get/put, all31 SQL operations, migration,
multiwriter/durable publish, ordinary Worker and installed activation remain
open. This checkpoint changes none of their results and carries no prior
native case count.
