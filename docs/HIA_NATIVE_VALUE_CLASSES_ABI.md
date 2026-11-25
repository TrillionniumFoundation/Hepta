# Actual shared class graph — private ABI

This is a source-only component checkpoint. No native HIA image has been
constructed for this profile. The exact authors, real x86 effect capsules and
original interpreter comparisons have been exercised separately. Public
class/function/Path compatibility remains open as listed below.

## Request domain

The existing 128-byte value request layout is retained. `HIABVQ01` accepts
only operations 0–24 and `HIABVQ02` only operations 25–31. New `HIABVQ03`
accepts only operations 32–39. Header words at 16, 112 and 120 are zero.
There is no tail. The three capability fields remain A at 24/32/40, B at
48/56/64, C at 72/80/88. Unused capabilities are zero. Responses use the
existing `HIABVR01` layout. All value drops continue through the correlated
`HIABVQ02` 29–31 / `HIABVR02` protocol; this profile adds no cleanup shortcut.

| Operation | Actual inputs | Result |
|---|---|---|
| 32 | `arg0` fixed catalog ID, no caps | New independent cap for the canonical class |
| 33 | A str name, B list of actual class caps, C dict namespace | New class with actual retained bases and C3 MRO; namespace is copied |
| 34 | A class, B str attribute name; `arg0=0` C actual value, `arg0=1` delete | Mutate the actual class namespace/name under the same value mutex |
| 35 | A class, B instance environment, C inherited data or zero | New class-backed kind8 instance; canonical exact str/bytes constructors return an independent cap for the exact base |
| 36 | A actual value | New cap for its actual class; legacy Q02 objects have no class authority and return TypeError status2 |
| 37 | A actual value, B actual class | `G_N` / response48 is the actual MRO membership result |
| 38 | A class, `arg0=0` name / 1 bases / 2 MRO / 3 namespace | Name cap or independent shallow container copy; internal vectors are not exposed as mutable storage |
| 39 | A class or class-backed instance, B str name | Fresh lookup of the first matching actual class namespace in the current MRO |

The ordinary value statuses are retained. Class-private status16 denotes a
duplicate base, 17 an inconsistent C3 merge, 18 a layout/base/immutability
refusal, and 19 a class mutation not yet implemented. In particular,
`__bases__` reassignment currently returns 19; it is not silently treated as
an ordinary namespace key. These statuses are not yet the complete public
Python exception adapter.

## Canonical catalog

IDs are fixed by the captured owner, not supplied names:

1 object; 2 type; 3 int; 4 bool; 5 float; 6 str; 7 bytes; 8 list; 9 dict;
10 NoneType; 11/12/13 dict key/item/value iterator; 14 PurePath;
15 PurePosixPath; 16 PureWindowsPath; 17 Path; 18 PosixPath; 19 WindowsPath;
20 ScalarMultiversionRuntime; 21 BaseException; 22 Exception; 23 TypeError;
24 ValueError; 25 OSError; 26 RuntimeError; 27 MemoryError.

Class names are mutable text; they never determine catalog identity.
Creating another class named `ScalarMultiversionRuntime` or `PosixPath`
does not make its instances members of those canonical classes.

## Actual graph and compatibility

Class objects are kind10. Their data block contains name and namespace
object references at 0 and 8; base count at 16; MRO count at 24; inherited
layout at 32; fixed catalog identity (zero for custom classes) at 40; parser
identity at 48; zero at 56; then the actual base and MRO object vectors at
64. The MRO includes the class itself. All edges participate in ordinary
marking, cycle collection, edge release and allocation rollback.

Class-backed kind8 keeps the old 64-byte native object allocation. The
existing environment/base/name fields at 16/24/32 are retained; field40 is
the new actual class edge. Legacy Q02-created objects keep field40 zero.
For class-backed objects, old inspect26 now reads the current name through
the actual class instead of a per-instance frozen name. Its three output
caps remain atomic. Old legacy objects retain all previous fields and
behavior. Method execution has not been enabled by this name change.

Inherited str and bytes data retain ordinary value/hash semantics. Path
instances hold a copied list of actual raw string parts. No new aggregate
path byte limit is imposed. Internal class/base/MRO counts use checked
u64 arithmetic and the growable arena rather than a fixed class-count cap.
The fixed catalog has 27 entries; that is not a limit on user classes.

Catalog roots occupy arena152 (published prefix count) and 160..375
(actual class references). These lie before the unchanged free-list table
at512. Catalog construction publishes each complete class atomically;
failed allocation leaves only the complete prefix. Context destruction
still requires all external capabilities gone and actually unmaps the
arena through the existing owner.

## Packaging

`HIABVP03` is a separate 104-byte pack request: magic, count10, ten role
lengths, mode at96, followed by the actual flats. Roles are owner, core,
import, export, capture, format, number, dict_iterator, classes, class_mro.
Mode0 emits general ET_REL; mode1 emits the full 6Q flat. The original
4MiB per-role and 16MiB text limits remain. Earlier pack request domains
and images are unchanged. `hia_result_value_class_bridge.S` is the readable
616-byte fixed mechanical capsule; production HIA packaging emits those
bytes directly.

## Remaining public boundaries

This checkpoint does not claim complete metaclass/layout/descriptor
semantics, `__bases__` reassignment, arbitrary class attribute hooks,
actual owned native callable capture/execution, or the full PurePath and
Path method family. A class-backed runtime value also does not by itself
create or validate an initialized MV provider capability. The public
runtime factory must perform the actual constructor and bind that owned
provider. BG's first `isinstance` gate remains ahead of numeric options,
bridge paths and baseline verification.
