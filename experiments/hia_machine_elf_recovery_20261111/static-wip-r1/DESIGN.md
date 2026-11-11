# HIA ELF continuation ownership and remaining work

## Public behavior

The retained API is write_elf_object(code, symbols, relocations,
text_alignment=16). It accepts exact immutable bytes, exact lists of exact
record dictionaries and the original nominal symbol/PLT32 profile. This slice
preserves the complete original source as an oracle; it does not redefine the
API as packelf's narrower byte profile.

Original refusal priority is alignment, code, inventories, each definition's
record/name/duplicate/global/offset/size/end, definition overlaps, each
relocation's record/offset/type/addend/name/E8 placeholder, relocation overlap,
symbol count, and final complete-object byte limit. The original expression
order and repeated dictionary accesses matter when foreign dictionary keys
invoke user code and mutate later values.

HIA controls the phases and native decisions. The bridge only performs the
specific operation named by the pending request. It must not batch future
observations or precompute a final host layout.

## Frame and transport

The mutable private frame begins with HIAELF01. Header words are phase at 8,
sequence at 16, pending at 24, request at 32, four operands at 40..64,
acknowledgement at 72, needed capacity at 80, and result length at 88. Three
56-byte observation facts begin at 512. Each fact carries kind, numeric
observation, flags, length, identity handle, payload offset and prefix count.
Scratch atoms start at 768, 1600 and 2432. A 65,536-bucket name table begins at
4096; dynamic nodes start at 528384.

Kinds distinguish exact int, bool, str, bytes, list and dict, opaque values and
key-set projection. Native arguments avoid copying arbitrary strings before
their type is admitted. Bounded UTF-32 prefixes preserve code points and
surrogates for admitted comparisons; opaque identities remain in the bridge.
Arbitrary integer observations carry sign and a separate wide flag.

Returned status 1 requests one observation; 2 and 3 request work/output growth;
4 is an internal native continuation; zero is a terminal complete byte result.
The terminal native phase is 220. Native errors map to the old public exception
type and message. A private wrapper consumes the pending permission before
executing an effect, closes it on BaseException and closes the session in run's
finally path. These source guards require fresh actual lifecycle controls.

## Issued operations

| Op | Mechanical observation/effect |
|---|---|
| 1 | One public argument |
| 2 | iter(object) |
| 3 | next(iterator), preserving StopIteration completion |
| 4 | Actual set(row), with a bounded key projection |
| 5 | Foreign set comparison with the exact required literal key set |
| 6 | One, two or three actual dictionary subscriptions in requested order |
| 7 | Actual dict(row) copy |
| 8 | bool(value) |
| 9 | Actual opaque addition or subtraction |
| 10 | Opaque scalar or tuple comparison |
| 11 | Set a native-selected key/value in a mechanical host map |
| 12 | Fetch from that map |
| 13 | One code subscript |
| 14 | One code slice |
| 15 | Copy the admitted complete immutable code bytes |
| 16 | Original unsigned-Q scalar conversion semantics |

Map operations preserve real hashing/equality. The bridge does not choose
symbol order, offsets, indices, table layout, visibility or section values.
Opaque arithmetic and comparison remain foreign effects, as they do for the
original Python object API; admitting their final compatibility requires
matching the original ordering of those effects.

## Native output

The policy owns name validation and interning; local/public/undefined grouping;
name and symbol indices; original visibility; overlap and E8 checks; PLT32
relocations with addend -4; all .text, .rela.text, .symtab, .strtab, .shstrtab and
.note.GNU-stack bytes, alignments and section headers; and the ELF header.
The output is seven sections including the null section. Every byte of the
image is constructed by HIA, with bulk moves only for already-admitted data.

The 64 MiB final object limit is distinct from the admitted machine-code
length. The two reserved symbol entries count toward the 65,536-symbol limit.
No compiler, runtime or qualification limit is enlarged by this checkpoint.

## Foreign sort dependency

The reconstructed r1 algorithm uses a bottom-up stable merge. Matching final
ordinary order does not establish equality of comparator calls, exception
priority or mutation observations for all Python objects. The exact official
CPython v3.12.14 and v3.14.4 listobject.c sources were read during the earlier
investigation. They differ in run discovery and comparison behavior. Their
raw source identities are recorded in BASE_INPUTS.json when available.

A valid completion must move the required ordering control into HIA and issue
foreign comparisons in the retained runtime's actual schedule. Delegating the
complete sort to Python would leave a substantive policy owner in Python.
Rejecting formerly accepted foreign mutations after the fact would narrow the
API. Neither is treated as closure here.

## Next acceptance gates

Fresh source generation and native admission; exact original complete writer
differentials including effects and exception object/context; 64 MiB and full
symbol capacity; malformed ACK, repeat and BaseException one-shot controls;
full 51 caller IDs with complete returned artifact metadata and bytes; selected
old writer denial across actual child processes; real linker/dlopen/disassembly;
and installed wheel resources using -I -S -B. Source/manifest/image identities
must remain stable before and after each gate. A current matching cold report
is a separate requirement for qualification, not supplied by development.
