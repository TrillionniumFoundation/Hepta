# Native ELF64 ET_REL writer — private issued-value ABI, revision 1

Status: NEW AUTHORING. No AST, generation, B3, VM, native, object-linking, installed,
cold or whole-build result is asserted by this document.

The semantic reference is hepta/hia_machine_elf.py, Git blob
cad2e6d21dccc95ad3cfd368da42964ec52d4bb7, 7,026 bytes, SHA256
c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101.
The reference MAX_OBJECT_BYTES is 67,108,864 and MAX_SYMBOLS is 65,536.

## Inputs and authority

The three native operands are Graph read lease, command read lease, and private
mutable workspace. The exported machine ABI remains R/W/W; its HIA wrapper only
borrows the second operand for reading. Both input mappings are physically
read-only in the development executor.

The Graph uses the already issued HIAGRF01 representation: a 64-byte header,
64-byte nodes, u64 edges and an absolute-offset scalar pool. Its root is an exact
list with four values in this order:

1. text_alignment
2. code
3. symbols
4. relocations

All ordinary value distinctions needed here remain represented: null, bool,
arbitrary signed integer magnitude, binary64, surrogatepass string, exact list,
exact dict, tuple, unsupported object, and immutable bytes. The input issuer
only freezes these representations and object references. It does not validate
ELF policy, sort inventories, normalize fields, resolve names, or construct any
ELF byte. A complete mechanical capture is not an incremental public resource
admission claim.

The lease number and header are correlation fields, not authentication. An
ordinary coordinator must hold the actual immutable producer mappings and exact
source/image bindings. This is not an API accepting externally supplied Graphs
as trusted objects. Foreign Python callbacks, custom equality/hash behavior,
subclass-key equivalence and mutation during capture are outside this private
issuer slice; they are not silently presented as full arbitrary-Python API
equivalence.

Command is exactly 96 bytes, twelve little-endian u64 words:

| Word | Meaning |
|---|---|
| 0 | ASCII HIAELC01, as little-endian u64 |
| 1 | version 1 |
| 2 | nonzero Graph lease, equal to Graph header word 1 |
| 3 | nonzero request sequence |
| 4 | exact Graph byte extent |
| 5 | root ID, equal to Graph header root ID |
| 6–11 | zero |

The workspace minimum is 4,096 bytes. Shorter workspace is a private ABI error.
There is no new node, JSON, depth, call-count or total-session quota. Every used
Graph node and edge has checked bounds before it is read. Graph transport
arithmetic is checked for u64 overflow.

## Pure retry and returned views

This is a pure value operation, not a persistent session. Each entry rebuilds
its private indexes from the same two immutable input leases. On GROW the caller
allocates the returned extent and repeats the operation; it may retain or clear
the old workspace because the owner initializes its own state. The fixed caller
must keep the same input bytes for that retry. Header equality alone does not
prove this. A private BAD invalidates the caller's borrow; no stale event is
consumed.

The return is 128 for a completed semantic outcome, FE for GROW and FD for BAD.
The workspace begins with this 128-byte, sixteen-word HIAELE01 event:

| Word | Meaning |
|---|---|
| 0 | HIAELE01 |
| 1 | version 1 |
| 2 | action: 0 ELF, 1 GROW, 2 MachineObjectError, 3 private BAD |
| 3 | Graph lease |
| 4 | request sequence |
| 5 | exact semantic error ID, otherwise zero |
| 6 | required total workspace bytes |
| 7 | result view offset |
| 8 | result view byte count |
| 9 | local defined function count |
| 10 | global defined function count |
| 11 | distinct undefined name count |
| 12 | relocation count |
| 13 | selected text alignment |
| 14 | terminal processing phase, diagnostic only |
| 15 | private ABI reason, otherwise zero |

For action 0 the view is the complete ELF object. For action 2 it is the complete
ASCII MachineObjectError message. GROW and BAD have no result view. The view is
valid only in the current workspace and until its next use; the coordinator
copies or lends it read-only before reusing that workspace.

## Exact semantic order

The HIA owner performs the original order, including early complete-inventory
checks and late byte measurement:

- exact int alignment in {16,32,64};
- nonempty exact immutable bytes, length at most 64 MiB;
- exact lists, 1 <= definition count < 65536, relocation count <= code length // 5;
- each definition in input order: exact four-key dict, name regex, duplicate /
  exact bool / offset / size / span checks;
- sorted function-span overlap;
- each relocation in input order: exact four-key dict and exact integer
  offset/type/addend first, then name, then actual E8 followed by four zero bytes;
- sorted relocation overlap, with original minimum distance 5;
- complete distinct symbol inventory plus null and section entries <= 65536;
- deterministic names, local/global/undefined groups and all section layout;
- complete object length <= 64 MiB, after all preceding semantic validation.

The complete original twelve error strings are emitted by HIA. No host exception
message factory decides a production semantic result.

Name lookup uses a bounded-by-inventory AVL index rather than collision-sensitive
hash admission. Function spans and relocation records are sorted in place by a
HIA heapsort. ASCII name comparison matches the reference regex's admitted names.
There is no additional collision, probe or recursion quota.

## Exact bytes and explicit nonclaims

HIA writes the whole ELF64 header, null symbol, .text section symbol, all local
hidden function symbols, global exported functions, undefined imports, PLT32
RELA records with addend -4, both string tables, six section headers plus the
null header, alignment padding and nonexecuting .note.GNU-stack section.

This owner is not a disassembler and does not prove general ISA validity.
E8-placeholder checks, declaration/range checks and original symbol visibility
are retained exactly. It does not invoke a source translator, assembler, linker
or Python ELF constructor at runtime. GNU readelf may inspect completed test
objects as an independent diagnostic, never as the emission mechanism.

The independent development oracle invokes the unchanged original Python writer.
Tests compare complete bytes or the exact error class/message; source/image
bindings, full input/output/workspace bytes, return codes and canaries are kept.
Planned coverage includes every validation stage and explicit first-error pairs,
arbitrary integer boundaries,
bool-vs-int, exact field inventories, all alignments, ordering/permutations,
overlap/E8 controls, complete 64 MiB output boundaries, 65,536 symbol accounting,
GROW and malformed private framing.

Actual generation must fit the original bootstrap profile. Each B3 compile stays
10 CPU seconds / 20 wall seconds / 256 MiB. Each actual test group stays 90 CPU
seconds / 180 wall seconds / 1 GiB. If one image does not fit, split ownership;
do not raise those limits. A completed leaf does not close general Core lowering,
shared linking, public build, installed dispatch or cold qualification.
