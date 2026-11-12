# Exact integer arithmetic in the Core owner

This development integration connects one explicit HIA integer companion to
the existing Core lowering scope. HIA owns ADD, SUB, NEG and INVERT for exact
built-in integers. The original Core packet, its 39 images, numeric comparison
companion, UNPACK companion and original 32 mandatory gates remain present.

The HIA kernel and the integer transport bridge are byte-for-byte the inputs of
the completed independent development qualification recorded in commit
`4c473fa7a1c2adf52655bda2da3b57a4f3c0883e`. That separate run used a qualified
v89 compiler and completed four methods and 107 cases, including a carry across
an operand larger than 8 MiB and malformed acknowledgement controls. It is not
a matching-source cold or whole-Core qualification of this integration.

## Dispatch and admission

`HEPTA_HIA_CORE_INTEGER_MANIFEST` selects the optional companion while an
explicit Core owner is admitted. The manifest binds the HIA source, ABI,
Python transport bridge, selection module, native image and the Core compiler
SHA. The strict builder accepts only a completed cold report whose complete
source manifest matches the current source. An invalid explicit selection
raises; an empty explicit path does not silently disable the companion.

The companion is captured with the Core scope and participates in the Core
owner cache and implementation identity. ADD and SUB keep the original target
lookup, left read and right read order. NEG and INVERT keep their original
target lookup and single operand read. The eligibility checks use the already
bound target and already read values. A custom operator, an integer subclass,
bool, an in-place operation or a rebound callable keeps its original dispatch.
In particular, bool inversion keeps CPython's warning and warning-as-error
behavior.

The integer image uses 256-byte input and output buffers and a 640-byte
workspace. Every data window contains at most 32 limbs of 32 bits each. HIA
chooses the windows, carry and borrow propagation, sign, output bytes and
minimal signed result extent. No new integer-value policy cap is introduced.
The ABI's representable byte offsets must fit u64.

## Qualification boundaries

The ten original source/Core-VM methods remain, including their arithmetic
oracles, protocol refusal cases and terminal permission checks. They have a
portable default fixture and retain the explicit create-only evidence option.
The source generator becomes the 63rd entry after the original 62 entries;
explicit output still refuses to overwrite an existing file.

Additional source controls cover admission identities, stale or malformed
manifests, source changes after selection, optional scope capture and resource
packaging. Synthetic image objects in those controls never map or execute a
native image. Current matching-source cold, integrated full Core116, installed
integer behavior and default activation remain unqualified until their own
complete original execution evidence is obtained.

The matching-cold qualifier now enters the numeric qualifier once, which enters
the UNPACK qualifier once and then the complete original Core116 once. All
three companions share the actual current B3 compiler and current source
manifest. This chain remains inside the existing 180-second caller owner with
3-second cleanup. The original 18 component methods use the existing second
owner with the same limits; the original 32 mandatory gates are unchanged.

`tools/qualify_hia_core_integer_callers.py` observes the original exact-type
eligibility decision without repeating target lookup or operand reads. A
normal `IntegerSession.step` return, a native DONE status, a normal `finish`
return, the outer primitive return and the complete method result have separate
records. A raw native entry that later fails output validation is not a normal
step return. A DONE followed by a failed result construction is not a successful
materialization. `tools/hia_core_integer_qualification.py` independently joins
the full six compile originals, image, nested reports, current source identities
and installed results before accepting the observation.

The installed v2 argument schema names all three manifests explicitly. Its
integer observations include the ordinary caller, four separate 1025-bit
window probes and eight changed-or-missing source refusals with restoration.
The four probes must each observe at least two READ and two WRITE returns,
one DONE and one successful materialization. They do not add to or replace any
of the original 116 methods. Fifteen additional source and synthetic controls
check this qualification machinery; they provide no native execution evidence.

## Remaining runtime work

Python still owns object identity, registry entries, allocation, reference
lifetime, exact type admission, sign and bit-length transport, magnitude byte
materialization and the final `int.from_bytes` allocation. The transport may
allocate a whole magnitude and result; fixed native windows do not make the
host memory constant. Multiplication, division, remainder, shifts, other
bitwise operations and foreign object behavior remain outside this integer
companion. This integration does not close the whole HIA rewrite or authorize
retirement of those owners.
