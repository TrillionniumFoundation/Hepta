# Native path values — implementation contract in progress

This file records the fixed integration boundary being implemented. It is not a
qualification receipt and grants no execution authority. The original
`HIABVQ01` request domain and `HIABVP01` seven-role packer remain unchanged.

## Shared actual value objects

`HIABVQ02` uses the existing 128-byte value request and existing independent
capability nodes, and accepts only operations 25–31. `HIABVQ01` continues to
accept only its original operations 0–24. Operation 25 creates a native object;
operation 26 atomically inspects one. Operations 27 and 28 are the separately
implemented actual dictionary iterator. Operations 29–31 carry explicit
consumption and retained-mapping cleanup facts; their exact contract is in
`HIA_RESULT_VALUE_NATIVE_CLEANUP_ABI.md`.

The new exact value kind is 8. Lists and dictionaries store this actual object
through ordinary arena edges. No dictionary of supplied addresses or claimed
path strings substitutes for this object.

| Operation 25 input | Meaning |
| --- | --- |
| A, at 24/32/40 | Actual environment value; retained as an arena graph edge |
| B, at 48/56/64 | Actual exact str/bytes base for a declared scalar subclass; zero for an ordinary object |
| C, at 72/80/88 | Actual immutable class-name string value |
| arg0, at 104 | Native class base: 0 ordinary object, 4 str subclass, 7 bytes subclass |
| arg1, at 112 | Captured native class method entry; zero means no filesystem method |
| tail | Empty |

This private creation operation is used by a source-bound native class factory.
The actual immutable code containing its method must remain mapped throughout
the value context lifetime. A caller-supplied conversion result or verified
flag is not accepted. The factory must own the executable closure; neither this
metadata record nor a nonzero address itself proves executable custody.

The object owns a 64-byte metadata allocation. It records entry at 0, class base
at 8, environment object at 16, base object at 24 and class-name object at 32.
Remaining words are zero. Release, mark and cycle collection traverse all three
actual graph edges. No native callback runs under the value registry lock.
Cyclic environment/container/object graphs are collected by the same arena
owner.

Exact type inspection remains kind 8. A str/bytes subclass retains original base
hash, equality, scalar-byte copy, length and JSON-export behavior. Ordinary
objects use identity equality and reject unsupported scalar or JSON operations.
The method is not called merely by storing, copying, hashing or collecting a
path value.

Operation 26 needs output capacity 8320. The ordinary 128-byte result header
retains kind and identity information. The additional 128-byte `HIAVNO01`
record begins at output 8192:

| Relative offset | Meaning |
| --- | --- |
| 0 | HIAVNO01 |
| 8 | Class base |
| 16 | Actual captured method entry |
| 24 | Zero |
| 32/40/48 | Fresh independently owned environment capability |
| 56/64/72 | Fresh base capability, or an actual None capability |
| 80/88/96 | Fresh independently owned class-name capability |
| 104..127 | Zero |

The three capabilities publish together. Short output creates none. Allocation
failure frees every unpublished node; no partial owned reply is returned.
Conversion borrows the source object strongly, obtains this real descriptor,
releases the value lock, calls the method and later drops its temporary owned
references.

The separate iterator kind 9 owns a 64-byte data allocation. Its sole child is
the dict at data+0; data+8 expected size, +16 raw cursor, +24 remaining yields,
+32 mode, +40 active/sticky-size-error/exhausted, +48/+56 zero. Its scalar length
is zero and length/chunk operations raise the actual TypeError status. The
iterator author owns next/compaction policy; the common owner only traces its
real child.

The shared dictionary owner preserves raw entry positions through deletion,
and compacts only at actual insertion resize or Unicode-to-general conversion.
The conversion runs in a distinct continuation phase, so failed arena growth
retains its retry state. A non-exact-str insertion converts before its fresh
lookup, even when the key later compares equal to an existing exact string.

## Native conversion policy

The shared conversion role is `native_path_value`. Its two semantic modes are
0 `os.fspath` and 1 single-argument `Path` coercion. Filesystem absolute-path
assembly and symlink resolution are separate consumers. MV uses the former;
BG uses the latter.

Both modes inspect actual value types. Exact str/bytes and their actual native
subclasses bypass `__fspath__`. Other native objects invoke their captured
method outside all value/object registry locks. Method results are actual owned
value capabilities and are freshly inspected; a method cannot return a
caller-asserted result kind.

The native callable reply must distinguish actual TypeError-family control flow
from other Exceptions and BaseExceptions. A class-name string in an exception
dictionary is not used to infer inheritance.

CPython 3.14.4's Path constructor catches TypeError from os.fspath, restores the
original argument, then raises its own Path argument TypeError. Other exceptions
propagate with their actual owned identity. A successful method returning bytes
reaches the Path type check and names the returned object's actual type. A
successful filesystem method returning str is accepted. The generic os.fspath
mode keeps its distinct original error text and str/bytes acceptance.

Final request/context/callback layout is being connected after the actual
value-object and iterator roles are compiled. This contract deliberately does
not claim support for arbitrary live foreign-interpreter objects, nor equate
native class metadata with a filesystem verification result.

## Construction

The new eight-role `HIABVP02` packer is independent. Header size is 88 bytes:
magic, role count 8, eight role lengths, mode 0 object/1 flat. Roles are owner,
core, import, export, JSON capture, binary64 formatting, scalar conversion and
the actual dict iterator. Each role stays within 4 MiB and complete text within
16 MiB. Fixed entry dispatch selects iterator role 8; the unused role 7 remains
invalid. The readable new mechanical bridge is 590 bytes and has no path or
iteration policy.

Development source candidates are not qualified native products. No final
source authority or public whole-runtime success is inferred from this file.

