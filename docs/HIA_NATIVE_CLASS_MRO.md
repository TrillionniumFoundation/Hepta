# Native class linearization component

This component implements C3 merging for actual class identities. Its current
evidence is development execution and the original HIA language verifier.
It has not been built or executed by the captured native compiler, and it does
not complete the public class factory, MRO mutation, method lookup or executable
closure ownership.

## Private input

The six-word pure entry is `native_class_mro(source, source_n, output, output_n,
workspace, workspace_n) -> u32`. A class owner constructs this frame only after
it has validated and strongly retained its actual bases under the class lock.
The helper does not turn externally asserted integers into type authority.

`HIAC3M01` has a 64-byte header: magic, direct-base count, total number of MRO
entries, and five zero words. Each direct base follows as its actual nonzero
identity, MRO length, and that many identity words. Each base's first MRO element
must be itself. Identity words are opaque full-u64 values; there is no signed or
32-bit narrowing. Lists appear in the declared base order. The caller inserts
the implicit object base when required; the zero-base frame is used only by the
owner's root-type construction.

The workspace requirement is `96 + 32*base_count +
8*(total_mro_entries + base_count)`. All arithmetic and spans are checked before
access. No fixed class-count, inheritance-depth or aggregate byte limit is added.
The workspace is mutable calculation scratch, with the required output size at
offset 0 and required workspace size at offset 8 when representable.

## Reply

The output is `HIAC3R01`, status, result count, a zero word, and result identities.
Status 0 is the merged base linearization, excluding the new class itself.
Status 1 identifies the first duplicate base in the original pair-scan order.
Status 2 returns unique unresolved sequence heads in their original insertion
order, for the class owner's later full error formatting.

The entry returns 0 for a complete reply; `0xfffffffd` for a malformed private
frame; `0xfffffffe` for insufficient output; and `0xfffffffc` for insufficient
workspace. Short output and private refusal do not change output bytes. The
class owner must not publish a class on a nonzero status or entry return.

The order is based on CPython's actual `pmerge`, `check_duplicates`, and
`set_mro_error` paths in [CPython 3.14.4 typeobject.c](https://github.com/python/cpython/blob/v3.14.4/Objects/typeobject.c).
The development oracle creates actual classes in the locally running CPython
3.12.14, compares successful `__mro__` identity sequences, and compares duplicate
and conflicting-head decisions. These mathematical comparisons are not a claim
that all class-layout, metaclass or public error semantics have migrated.

## Remaining ownership work

The class factory must own actual base/MRO graph edges and callable closure
references, perform fresh method lookup, preserve dynamic class mutations, and
implement the actual PurePath and ScalarMultiversionRuntime base checks. Path
construction must return a real typed PosixPath instance. A class-name string,
raw method address, supplied MRO array or resolved path string is insufficient
to establish those public behaviors. Existing value profiles remain unchanged
by this pure helper.
