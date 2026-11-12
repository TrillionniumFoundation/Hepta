# Pure HIA x64 encoder leaf — first implementation ABI

Status: NEW AUTHORING. No generation, compiler, native or installed qualification is claimed.

Reference: exact 0ef `hepta/hia_machine_x64.py`, Git
8e87bd317c5f61e00993bb0bf8d803c5385d6556, 11,057 bytes,
SHA256 8795fb4e5034673401f5f6a5a60e57872c48a3982dbdcb4d3b8198ee7b3f41a9.
The source contains 44 public callable methods, one public `offset` property,
the constructor and five private helper methods. This leaf covers the constructor
and all 45 public entries. It does not execute an assembler or ask a host to
produce instruction, relocation or object bytes.

## Ownership and original ordering

The encoder owns code bytes, scratch-register renaming, immediate modes,
the complete label dictionary, branch fixups and call relocations.
The finalizer borrows that actual issued state and actual code, copies the code,
patches fixups in their original order, and emits the complete relocation values.
It does not mutate the encoder state. Repeated finalization is deterministic.

Every original operand check retains its order. For example mov_rr checks src
before dst; load checks dst then base then disp32; condition checks precede
register checks; ALU operation checks precede dst and immediate. Semantic failures
consume the private command sequence but otherwise preserve the original state
effects. In particular branch/call prefix bytes and their fixup/relocation record
remain committed when the subsequent four-byte placeholder fails; setcc preserves
a successful MOV when its later SETcc fails. No rollback invents stronger
atomicity than Code. The finalizer also preserves the original partial-branch
corner case: replacing the final incomplete placeholder can extend the returned
copy by up to four bytes beyond the original 64 MiB code buffer. The original
finalize checks the input length only; downstream ELF limits remain independent.

No label-count, total command-count or metadata-byte quota is added. The original
64 MiB code cap, 512-character arbitrary Unicode labels, 192-character ASCII call
symbol grammar, signed displacement and immediate domains are unchanged.
Private u64 extents/sequences must be representable; an overflow is a protocol
failure, not a new public policy.

## Encoder input and workspace

The encoder entry has the native R/W/W signature:
first immutable command+argument Graph; second owned mutable code arena; third
owned mutable metadata workspace. Distinct actual buffer leases are mandatory.

The first 64 bytes are eight little-endian u64:
[HIAXCC01, 1, sessionLease, commandSeq, operation, graphBytes, rootID, 0].
The remainder is the complete private argument Graph with magic HIAXGR01.
It has the existing 64-byte Graph header, 64-byte nodes and u64 edges. The root
is the exact list of arguments. Every operand's type, magnitude, strings, map
keys and edges come from this mechanical graph, not host admission.

Kinds 0..9 have the original Graph value representation. This private profile adds
kind 10 for an exact bytearray (byte payload) and 11 for an inherited-behavior
str subclass (WTF-8 payload and codepoint count). All original exact-type checks
reject these unless the original operation accepts them: emit accepts 9/10;
shift's equality with "cl" and scratch-map key equality accept 4/11. The issuer
copies the builtin value without calling an override. Arbitrary foreign
__eq__/__hash__/truth-value callbacks, direct mutation of Code internals and
direct calls to underscore helpers remain explicit integration boundaries.
The ordinary native backend uses none of these: it calls public methods and
reads len(Code.data), which maps to the offset result.

Graph scalars preserve exact integer sign/magnitude, bool, Unicode (including
lone surrogates), bytes, bytearray, container kinds and unsupported values.
String character counts are recomputed in HIA; the aux count must match.
The header/lease is correlation only. The fixed issuer must preserve immutable
input identity, including during GROW; arbitrary supplied frames are not trusted.

The code arena has a 64-byte native header followed by Code.data bytes.
The metadata workspace has a 128-byte event, fixed state/scratch and a growable
offset-based registry beginning at 4096. All retained strings are copied into
the metadata arena before the input lease is reusable. GROW requests exact
required code/workspace capacities and occurs before any command commit.
The fixed caller grows both arenas without changing their existing bytes and
repeats the same immutable command. Neither ordinary code emission nor registry
append may be repeated after a completed command.

A private framing/state error returns FD and permanently poisons a workspace
large enough to hold its state; the caller must retire the complete lease even
when the supplied workspace is too short to record poison.
An init semantic rejection also ends that lease, matching a constructor that
never produced a usable Code object. Ordinary later MachineEncodingError keeps
the existing code/registry usable.

## Operation table

0 init(scratch_registers, move_immediate, alu_immediate)
1 align(boundary), 2 offset(), 3 emit(value), 4 label(name),
5 jmp(target), 6 jcc(condition,target), 7 call(symbol),
8 mov_rr(dst,src), 9 mov_imm(dst,value),
10 load(dst,base,disp), 11 store(base,disp,src), 12 lea(dst,base,disp),
13 load_u8(dst,base,disp), 14 store_u8(base,disp,src),
15 add, 16 sub, 17 and_, 18 or_, 19 xor, 20 cmp, 21 test (two operands),
22 alu_imm(op,dst,value), 23 shift(op,dst,count), 24 shift_imm(op,dst,count),
25 shift_cl(op,dst), 26 shl(dst,count), 27 shr(dst,count), 28 sar(dst,count),
29 imul(dst,src), 30 imul_rr(dst,src),
31 mul, 32 imul_full, 33 div, 34 idiv, 35 neg, 36 bitnot (one register),
37 cqo(), 38 setcc(condition,dst), 39 cmov(condition,dst,src),
40 push(reg), 41 pop(reg), 42 ret(), 43 leave(), 44 ud2(), 45 finalize().

The argument list carries the complete effective signature; omitted Python
default disp=0 is inserted mechanically by the signature adapter. Wrong arity
is a private command error, not an invented MachineEncodingError.

## Events and finalization

Encoder event at workspace offset 0 is 16 u64:
[HIAXCE01,1,action,lease,commandSeq,operation,errorID,neededCode,neededWork,
 codeBytes,definedLabels,fixups,relocations,payloadOffset,payloadBytes,aux].
Action 0 completes an ordinary operation; 1 requests GROW; 2 is the original
MachineEncodingError; 3 is BAD; 4 publishes actual state for the finalizer.
Return values are 128 for action 0/2/4, FE for GROW, FD for BAD.
The offset result is codeBytes. Error payload is complete WTF-8 text.
No status bool replaces original errors.

Operation45 does not fabricate bytes. It makes the actual code and metadata
ready for the separate finalizer, whose internal signature is R/R/W (ordinary
R/W/W wrapper only borrows the second input read-only). Finalization validates
the matching actual state/code headers and complete referenced spans.
Its 128-byte event is sixteen u64:
[HIAXFE01,1,action,lease,completedSeq,errorID,neededWorkspace,
 graphOffset,graphBytes,finalCodeBytes,fixupCount,relocationCount,
 errorOffset,errorBytes,privateReason,0].
Action 0 succeeds, 1 requests GROW, 2 reports MachineEncodingError, 3 is BAD.
The finalizer workspace minimum is 4096; success Graph starts at offset 4096.
Return values are 128, FE, FD as for the encoder. A rejected pure finalizer
cannot write its read-only inputs: the fixed caller retires the source lease on
FD. It never claims to record poison in those read-only inputs. The output Graph has
root [exact finalized bytes, complete relocation list], with original dict
insertion order offset/symbol/type/addend. All Graph nodes, edges, strings,
integer magnitude bytes and patched machine bytes are produced in HIA.
The actual output must be consumed or copied before reusing that finalizer
workspace. It is a value result, not a compiler or executable qualification.

## Validation plan

Use original B3 with 10 CPU seconds / 20 wall seconds / 256 MiB and preserve
the existing 128-function/1536-block/8192-op/16-block-parameter gates.
Split kernels if necessary, never increase compiler limits. Each independent
test process keeps 90 CPU / 180 wall / 1 GiB.

Compare every method/condition alias/register pair/immediate mode and each
semantic failure's complete code/labels/fixups/relocations to the exact original
Code oracle. Exercise partial-commit boundaries near 64 MiB, repeated finalize,
unresolved Unicode and surrogate labels, metadata GROW and input reuse,
constructor rejection ordering and all public aliases. Retain actual native
source/images, all input/state/output bytes and canaries in lossless paged CAS.
Reuse the original executable corpus with the native encoder adapter; host
reference Code is oracle only, never an encoding fallback. ISA/linker checks
remain development evidence distinct from source-matching cold qualification.

## New development evidence format

Every actual entry reads and hashes every byte of all three complete logical
buffers before and after execution. Guarded mappings retain two 16-byte
canaries and inaccessible outer pages; source inputs are physically read-only.
Content-addressed zlib pages are verified by decompression on first save and
again by full page hashing at completion. A snapshot records full length and
SHA-256 plus either an initial complete page map or exact changed-page rows
relative to the previous snapshot of that same buffer identity. Applying every
page delta is checked to reproduce the current complete page map. No buffer
is truncated or replaced with a partial excerpt; immutable-page deduplication
does not cache mutable file reads or permit skipping source rechecks.

The original executable/disassembly unittest file is preserved byte for byte.
Its Code binding is replaced only in the development test module with an
adapter that calls these two actual HIA images. Its original ELF writer is a
test link-container oracle, not a production encoding fallback or a claim of
native complete build. All instruction bytes and fixups originate in HIA.
Independent operation groups also compare the exact original Code object's
code, labels, fixups and relocation state after successful and failing calls.

Current source is NEW and unexecuted. Generation, two B3 compilations, all
component groups, eight separate 64 MiB boundary processes, and the original
executable corpus must actually complete before a PASS is claimed.
