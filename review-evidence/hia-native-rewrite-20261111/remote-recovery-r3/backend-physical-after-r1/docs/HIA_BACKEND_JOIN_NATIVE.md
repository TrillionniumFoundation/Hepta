# Native post-Core backend join — development ABI r1

Status: NEW SOURCE ONLY. No AST, HIA generation, B3, VM or native result is claimed for this composition. The prior Function, wrapper, complete Emitter and ELF inventory observations remain separate evidence. This new component requires fresh source-bound images and its own complete oracle comparison.

## Scope and original order

The exact reference is hepta/hia_program_native.py, Git blob 1d0e0344f8300b11b5dd505cbea655170aba5be1, SHA256 bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c. The reference outer function owns, in order: target check; implementation-file digest; VerifiedProgram kind; full Core re-admission; original/canonical identity; borrowed-export normalization; complete plan snapshot/validation; plan digest; complete Emitter; artifact byte budget; independently checked ELF structure/symbols; implementation-file digest recheck; final HIAProgramMachine fields.

This revision concretely implements the suffix beginning with borrowed-export normalization. Its HIA controller receives a privately issued, actually admitted Core Graph, the unnormalized plan and foreign-export captures, actual original/Core digests and the before/after implementation-file digests. The 320-byte header is a private transport and does not authenticate a foreign Graph or filesystem result. The upstream native target/VerifiedProgram/identity/re-admission/file-custody integration is OPEN. The tests use exact reference admission for that explicit precondition; they do not call it during native continuation.

The exact suffix sequence is:

1. Actual HIA prepare mode 0 checks and normalizes the raw borrowed-export manifest.
2. If the plan is not None, a fresh private child runs the actual plan snapshot, bounded GraphWire scan/emit and checked-plan semantics. The complete native canonical plan is retained readonly, the whole child is retired, and actual incremental SHA hashes the plan.
3. A second fresh child runs the unchanged eleven-role complete Emitter against the original Core/plan/foreign Graph. It cannot reuse the retired plan child's mutable state.
4. The native command issuer reads the actual Emitter inventory and original Graph names. The post owner checks the original 64 MiB object limit and builds the complete expected-export command.
5. The independent actual ELF inventory owner checks the emitted object bytes, qualified ELF64/machine62 structure, complete symbol inventories and the closed ABI.
6. The implementation digests are compared in HIA. An actual inspector error precedes the stale-implementation error.
7. Actual incremental SHA hashes the complete emitted object and text. The post owner produces every original nonbyte machine field; it also exposes machine_text_sha256 as an explicitly additional later-build field.
8. The parent publishes a readonly 512-byte descriptor. All referenced successful byte views remain owned by this parent until release/teardown.

No host selects names, register assignments, instruction bytes, symbols, relocations, ELF sections, hashes of emitted data, canonical plan bytes or final metadata. Development Python authoring and the fixed development C carrier remain explicit trusted build/mechanical code. This is not yet an installed pure-HIA build path.

## Finite role table

| Actual role | Owner | Operands |
| --- | --- | --- |
| 1 | Emitter prepare | R/R/W |
| 2 | Function frame plan | R/R/W |
| 3 | Function lowering tape | R/R/W |
| 4 | Code command issuer | R/R/W |
| 5 | Scalar/borrowed wrapper tape | R/R/W |
| 6 | Wrapper command issuer | R/R/W |
| 7 | Persistent x64 encoder | R/W/W |
| 8 | x64 finalizer | R/R/W |
| 9 | Emitter finish/registry | R/R/W |
| 10 | ELF writer | R/R/W |
| 11 | Complete Emitter controller | R/W/W |
| 12 | Plan plain-data snapshot | R/R/W |
| 13 | Complete bounded GraphWire scan | R/R/W |
| 14 | Complete bounded GraphWire emit | R/R/W |
| 15 | Checked-plan semantics | R/R/W |
| 16 | Checked-plan controller | R/W/W |
| 17 | Independent ELF structure/symbol inventory | R/R/W |
| 18 | Expected-export issuer and final metadata | R/R/W |
| 19 | Actual incremental SHA256 | R/W/W |
| 20 | This outer controller | R/W/W |
| 21 | Graph/inventory to post command issuer | R/R/W |

Only role 20 is entered as a root. It may enter role 16 or role 11 through one active finite child at a time. A plan child may invoke logical roles 1..4, translated to actual 12..15. An Emitter child may invoke logical 1..10 unchanged. Neither child can create another controller or choose arbitrary roles. Raw CALL cannot target role 20.

The existing pure and persistent owners are rebuilt from their frozen full sources. New role numbers live in the outer runtime-assets map; old source manifests keep their original role fields. Rebinding the five plan roles is explicit and does not rewrite their original manifests.

## Immutable initial input

HIABBI01 is 320 bytes followed by exactly one complete GraphLease. Little-endian u64 words 0..11 are:

| Word | Meaning |
| --- | --- |
| 0 | HIABBI01 |
| 1 | Version 1 |
| 2 | Nonzero outer lease |
| 3 | Nonzero logical request |
| 4 | Nonzero Graph lease |
| 5 | Nonzero persistent Code lease |
| 6 | Nonzero plan-child lease |
| 7 | Nonzero Emitter-child lease |
| 8 | Graph root ID |
| 9 | Full Graph byte extent |
| 10 | Actual structured-origin flag, 0 or 1 |
| 11 | Exact current integer digit limit |

Words 12..15 and bytes 256..319 are zero. Bytes 128..159, 160..191, 192..223 and 224..255 contain respectively the actual Core SHA256, original-input SHA256, implementation-before SHA256 and implementation-after SHA256. The outer, plan and Emitter leases are pairwise distinct. The root is an actual three-element list [Core, rawPlan, rawForeignExports]. All exact supported Graph kinds, insertion order, alias/cycle information and scalar payloads come from the private issuer; the header does not confer admission.

The plan is not replaced by a host-validated plan. A non-None plan must complete the actual snapshot and bounded wire policy before semantic validation. The old flags2/sort path, 8 MiB wire limit, depth/node/digit policy and all first-error ordering remain unchanged.

## Parent slots and lifetimes

Slots 0..3 are empty readonly, full immutable input, 1 MiB controller workspace and 128-byte root event. The workspace layout keeps the shared common fields below the fixed private controller ranges.

| Slots | Meaning |
| --- | --- |
| 4 | Pure command |
| 5 | Child ACK, up to 320 logical bytes |
| 6 | Temporary normalization workspace |
| 7 / 8 / 9 | Child immutable input / private workspace / event |
| 10 | Native normalized manifest and borrowed source |
| 11 | Complete native canonical plan, retained readonly |
| 12 / 13 | Native post command / private post workspace |
| 14 / 15 | Native inspector command / private inspector workspace |
| 16 / 17 / 18 | SHA input / 32-byte output / 1184-byte state |
| 19 | Complete final metadata JSON, readonly |
| 20..34 | Child logical slots 4..18 |
| 35 | Final descriptor, readonly |
| 36 | Complete actual semantic error text, readonly |
| 37 / 38 | Native capsule / native command-issuer workspace |

A child slot maps 0→0, 1→7, 2→8, 3→9 and n≥4→16+n. Plan retirement releases all mapped 20..34 and 5/7/9/8. The normalized manifest and retained canonical plan are outside that set. The Emitter's actual text/object/registry remain mapped to parent 30/31/32 after its terminal; the parent copies no substitute object.

CB metadata occupies 24000..24383, seven digests 25000..25223 and saved actual descriptors 25400..25911. Outer state begins at 30000. These ranges do not overlap common WIRE/CAPS/OBS. Every actual child continuation receives the full observed header and payload plus its own lease/sequence, through a parent-issued ACK. Parent mechanical sequence and child sequence are separate monotonically checked fields.

## Successful descriptor

HIABMR01 has 512 bytes. Words 0..31 are:

0 magic; 1 version; 2 outer lease; 3 request; 4 Graph lease; 5 Code lease; 6 plan lease; 7 Emitter lease; 8..10 object slot/offset/extent; 11..13 text slot/offset/extent; 14..16 metadata slot/offset/extent; 17..19 registry slot/offset/extent; 20..22 canonical-plan slot/offset/extent, all zero for None; 23 has-plan; 24 version 0..4; 25 normalized foreign count; 26 function count; 27 export count; 28 completed Code sequence; 29 structured flag; 30 completed Emitter serial; 31 complete registry record count.

Bytes 256..479 contain seven full digests: Core, original input, implementation before, implementation after, object, text and plan. Plan digest is zero for None. Bytes 480..511 are zero. Current object/text/registry slots are 31/30/32; metadata is 19; plan is 11 when present. The descriptor is a private set of lifetime-bound views, not an external serialization of Python buffer objects.

The ordinary HIACDE01 terminal has operation7 and the exact last parent sequence. Domain0 is success, 1 is MachineEncodingError, 2 is HIAProgramNativeRejected and 4 is object-symbol/structure rejection. The checked-plan child uses internal domain3, but the parent translates it to domain2 while preserving the complete text, matching the original validate_block_layout_plan compatibility wrapper. Domain3 is not emitted as a public backend exception by this join. Words6..8 identify the complete readonly result/error view. Words9..15 are metadata bytes, object bytes, text bytes, plan bytes, function count, export count and request. Errors preserve the complete actual UTF8 text, rather than reconstructing it from a host enum.

## Post command and event

HIABCQ01 and HIABPC01 are private native producer frames. The query mechanically concatenates a 512-byte header, all native normalized 32-byte foreign rows and the actual complete HIAEMP01 inventory. Role21 reads only the original Graph's actual function-name views and emits the post command's original-function-index name table. It never uses a host-selected list of exports.

The command's 512-byte header includes exact leases/request/root, actual registry/object/text extents, Code lease/sequence, function/global/foreign counts, plan version/structured flag and contiguous table/pool extents. The original function-index name rows are 16-byte offset/extent records. Graph string rows must have object-ID word0, code-point count equal to the admitted ASCII identifier byte count, and zero other reserved words. The earlier unexecuted issuer r1 with an incorrect string-row test remains separately retained.

Role18 mode0 checks the object budget and actual registry before producing the full HIAMIC01 expected-export command. Mode1 follows completed independent object inspection and checks the two implementation hashes before final serialization. Each mode uses complete measure then fill, returns exact needed size, and cannot publish partial metadata. The parent rejects a semantic error substituted after a successful GROW phase.

## Evidence and limits

The new schedule is 22 groups, 133 cases and 72 private permanent-poison controls. It includes two strict all-final-slot/return/event/ACK comparisons between the full-CAS mechanical harness and the new C carrier; twelve scalar signatures; plan versions1..4 and complete layouts; borrowed arities1..8 and sorted names; eight original error-order pairs; twelve raw-plan errors; five late errors; actual 128/129/1024-function and 65536-byte frame boundaries; two actual-object corruption tests before independent inspection; initial/ACK/child/pure/GROW/hash poison controls.

The oracle is the exact full emit_program_machine, not just _Emitter.render. All nonbyte dataclass fields and full object/text/metadata/plan bytes are compared. A private changed-implementation-hash fixture is recorded as such, not claimed to prove filesystem custody. A private object corruption changes the same actual emitted bytes before the independent inspector; its complete before/after object is retained.

Small crosschecks, all private protocol controls and corruption cases retain every byte of all three operands before and after every actual native entry, full commands/ACKs, guard/canary and hardware readonly evidence. Other whole semantic/boundary cases use the fixed C carrier's complete image/input/event/ACK trace and full final slot bytes; they do not claim all intermediate workspaces. Lossless xz retirement happens only after all comparisons, close, full decoded byte equality, exact lengths/hashes/modes and a saved manifest; failures retain raw evidence. These new scopes do not replace any prior 26-wrapper/39-Function evidence.

Every B3 child retains 10 CPU seconds, 20 wall seconds and 256 MiB. Each builder and test retains aggregate 90 CPU seconds, 180 wall seconds, 1 GiB and core0. All compiled HIA retains128 functions,1536 blocks,8192 operations,256 blocks/function,16 block parameters and numeric SSA suffix<2048. max_block_ops is measured, never separately limited. No public Core, frame, text, artifact, export, plan or identifier quota is tightened or relaxed.

The proposed CI freshly compiles 21 actual images, validates each complete canonical HIA/document/profile/image/receipt, runs only this new schedule, independently checks source/image identities before/after, and streams the entire raw evidence archive and member ledger back byte-for-byte. Prior successes are not inherited. The public native admission/file-custody prefix, full compile_program_machine filesystem/linker path, installed dispatcher, complete pure-HIA source construction and full-suite qualification remain OPEN.
