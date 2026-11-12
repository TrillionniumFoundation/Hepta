# Fixed native UnixOpen / raw-FS issuance carrier — source checkpoint r2

## Current status

This checkpoint supplies concrete fixed x86-64 dispatcher code and the corresponding nine-image HIA publisher. It has **not** been parsed with Python, assembled, Core-verified, compiled with B3, or executed in the VM or natively. The performed checks are pure source-string identity, unique substitutions, complete inverse recovery, label-reference consistency, and metadata-range checks. They are not assembler or product tests.

The existing HIA coordinator r2 remains exact Git abbb7f40338e7b099e855281d7dab9ff64834eed. The completed-capsule fragment remains exact 3df087271e4a7bb3258be5e87580f8cb3d56e728. This checkpoint composes them with the FS9 carrier ceb21c40b4287b1eff4e998d61fdfcfa59fb3110 and the new dispatcher. That shared namespace branch uses DMS10. It does not replace, rerun, or inherit the separately successful original42 DMS9 qualification.

The complete ordinary UnixOpen and Store API are still open. In particular, no SQL31 transaction, put/get publication, migration, installation, or Worker success is established by these sources. The next actual gate must exercise this new combination and retain all failure originals.

## Fixed live contexts

The original startup still creates the actual DMS root, FS child, and role6 shared namespace. The new boot allocates one stable private role7 UnixOpen parent, role8 raw-effect framer, and role9 issuance coordinator. Their stable context identities are 7, 8, and 9; the existing shared context is 6. Each fixed context is allocated once and has generation1. The old role6 ROOT_LINK remains self; the new UI_MASTER field is separate. Dynamic DB/Map/memory context selection and generations remain owned by the existing HIA/registry.

The 4 KiB metadata layout adds four 40-byte guarded-buffer descriptors at1200..1359 and scalar fields2496..2687. The old metadata and scratch ranges are disjoint. The HIA workspaces are separate guarded mappings and cannot write these native metadata fields.

The old direct invocation wrapper changes only two mechanics: the fixed image-table upper role is9, and role8's second actual operand remains read-only. Its original HIA f0 signature still uses the RWW top ABI and an explicit borrow.read; physically protecting that second mapping read-only preserves its intended complete-input behavior. Roles1..7/9 retain the original RWW permissions. Every invocation still receives exact logical extents, has pre/post canary checks, and produces full native input/output/workspace trace records.

## Actual continuation

1. The actual parent role7 executes BEGIN, or a previously issued native ACK, until it returns a pending effect, a terminal return, or refusal. Parent GROW repeats the same immutable REQUEST and preserves workspace bytes; it does not repeat an effect.
2. At an actual pending return, native code captures the complete original parent call input, complete output and workspace. It also captures the latest actual completed shared-FS input/output/workspace.
3. The native dispatcher creates the private role9 BEGIN channel from those exact completed capsules. HIA role9 decides whether this is one of the eight supported raw effects. Non-raw effects remain explicit pending.
4. For a role9 CALL event, native code selects only its already registered role8 or role6 context. Context, generation, previous actual entry, coordinator call and next action are checked. Both requested logical source spans and read-only permissions are checked before any child copy or call.
5. Role8 receives exact issued first and second read-only inputs plus its retained workspace. A returned child GROW is delivered to role9 as an actual completed capsule. Role9 issues the next same-input child request; the carrier does not invent a semantic retry.
6. The actual shared role6 receives the complete issued HIANDJX1 request. Its original nested DMS/FS/DB/Map/memory machinery runs unchanged. The original REQUEST stays separate from subsequent inner ACK inputs. Only the actual outer terminal returns control to role9.
7. On role9's final success, native code checks that the actual parent entry, generation, call and pending action have not changed. It transfers the exact 512-byte ACK view from role9's read-only workspace into the parent's new immutable REQUEST, then resumes the actual parent.
8. Other parent effects remain pending. There is no host fallback that supplies a successful scalar or an arbitrary ACK. The parent remains active, and the development transport refuses any further command while that unresolved pending operation remains live.

The syscall mapping and errno/error/parent-state decisions remain in the existing HIA framer, shared FS and parent. The native dispatcher handles only fixed context selection, guarded owned buffers, exact span copies, permission changes, real calls, actual completion capture and transport.

## Development predecessor input

This source has a deliberately limited development entry transport. It is not an installed Store interface or public header-authentication mechanism. The still-unimplemented ordinary namespace producer must ultimately own the original parent BEGIN and its filename/process/FS scope bindings.

At boot, stdout reports an 8-byte length followed by a64-byte HIAUIB01 boot record containing the actual process identity, fixed context identities6/7/8/9, generation1 and4096-byte page size. These numbers are observations, not transferable capabilities.

Each development request is an8-byte full-frame length, followed by:

| Offset | Field |
|---:|---|
| 0 | HIAUIP01 |
| 8 | 1 for original shared-FS USER; 2 for original parent BEGIN |
| 16 | Complete USER byte count |
| 24..63 | Zero |
| 64.. | Exact USER bytes |

Command1 is wrapped into the original role6 USER channel; it cannot provide the role6 internal ACK channel. Command2 requires the original HIANUO01 command1 BEGIN, never command2 ACK. Its process-identity word must be zero in the development input; the carrier copies the whole original BEGIN and then fills only that word with the actual captured process identity. The complete final immutable image input is traced. Other initial parent fields remain explicit private predecessor input; this checkpoint does not falsely authenticate them as ordinary Store state.

No transport command accepts a completed capsule, context address, role8/9 input, result header, native entry counter or parent ACK. EOF can terminate the development process while a non-raw effect is pending, but no completion claim is made. There is no host reset of a poisoned or still-pending HIA workspace.

## Complete begin and completion evidence

The original BEFORE/AFTER/primitive traces remain byte-exact. Two new HIAUIT01 record kinds carry the private issuance relationship:

- Kind6 is written immediately after a new immutable REQUEST has been installed and before its first native entry. It records actual role/context/generation, starting native-entry counter, actual new input lease, requesting call/action, and the complete original REQUEST bytes.
- Kind5 is written only for a real returned call. It records the exact same role/context/generation/input-lease/requesting call/action association and the actual final native-entry serial. Its payload is the full128-byte HIAUIC01 capsule plus the complete original REQUEST, complete second operand and complete workspace.

The completed source cannot be reconstructed from the last ACK alone. The complete original REQUEST is a separately retained owned mapping. A later strict trace reader must pair each kind5 capsule with its matching kind6 beginning and the complete intervening actual native BEFORE/AFTER records, including any nested role6 activity. No prior trace is accepted as live runtime input.

The existing capsule helper is unchanged. The new dispatcher wraps its begin helper to emit kind6. The old source-only dispatcher r1 lacked that additional begin-source trace; both revisions are retained and neither has executed.

## Deterministic composition and publisher

The composer checks complete bytes/SHA256/Git identities of the base, capsule fragment and dispatcher. Five unique edits change only:

- the role6 boot continuation to the new fixed boot;
- second-operand protection for role8;
- fixed image-table role bound6 to9;
- role6 actual terminal return routing through the new private master;
- the table's zero-initialized capacity56 to80 bytes.

It then appends the two new local-label fragments before the original table. Deleting that exact append and reversing the five unique edits restores the entire original FS9 carrier byte-for-byte. The global entry/table/end symbol names remain unchanged. Zero relocation is still a mandatory future assembler gate; source label checks do not establish that gate.

The HIA publisher is derived from the actual FS9 three-pass publisher. It validates exactly nine ascending nonempty role entries before output GROW or writing. It computes total size, writes aligned table entries and then images using the same three-pass recurrence. Its header is HIAUIPK1; all images remain at most1 MiB under the existing image ABI. The fixed template digest is the complete newly composed source identity. Numeric return offsets remain proved below2^32 for this fixed template. No parent function, filename or Store-record quota is introduced.

## Required first real gate

The next executable delivery must include a complete pinned closure, native boot/BEGIN adapter, canonical generated HIA for all9 roles plus the publisher, actual per-role profiles and compile receipts, and strict direct invocation/trace observation. The planned gate must cover actual parent-produced raw requests, native ACK resumption, real failed syscalls, GROW before/after actual child completion, permanent refusal, replay/call/action/generation mutation, no external completion route, and unresolved non-raw effects without synthetic success.

Original semantic/framer/parent controls remain separate evidence until rerun in their explicitly named new gate; none are silently inherited. In particular, the completed original42 DMS9 run is not restarted by this checkpoint.

B3 stays10 CPU/20 wall/256 MiB with1 MiB output/workspace. Actual native subjects remain90 whole-process-tree CPU/180 wall/1 GiB/core0 and must be reaped with the existing parent-death/timeout ownership. VM windows retain4,000,000 steps/32 MiB arena/64 call depth. The original900-second aggregate includes final source checks when an aggregate gate is selected. Function/block/operation/parameter/SSA profiles and zero relocation are not raised to accommodate this source.

## Files and evidence boundary

The composed ASM is exact source text, not an assembled executable. The new HIA publisher is authoring source, not a compiled image. No successful runtime result is claimed by this checkpoint. The source-only report records every input/output digest and the complete inverse text operations, preserving all earlier source and qualification failures.
