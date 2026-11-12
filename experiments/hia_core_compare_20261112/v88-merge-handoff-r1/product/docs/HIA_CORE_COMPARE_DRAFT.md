# Exact builtin numeric comparison owner — isolated draft

This candidate moves the complete decision for the six opcode-13 numeric
predicates into a new HIA companion. It does not activate that companion by
default and does not claim that the nineteen object primitive families, the
CPython runtime, allocation, installed packaging, or complete Core callers have
been qualified by the source controls described here.

## Scope and retained behavior

Only an actual exact `bool`, `int`, or `float` on both sides and the unchanged,
already-bound builtin `_operator` callable for the requested mode qualify for
the numeric image. The outer operation first binds `_COMPARE[operation]`, then
observes the left handle, then the right handle, once each. A replacement made
while reading an operand does not rebind that earlier callable. Subclasses,
foreign values, replacement targets, and `in`/`not in` invoke the bound original
target. Foreign `!=` is never rewritten as a negated foreign `==`.

The unselected branch retains the original opcode expression. The remainder of
`LoweringSession`, including its 128-byte requests, one-use observation,
registration, exception closure, handoff and returned/yielded bookkeeping, is
unchanged. All thirty-nine Core HIA sources and its ABI are fixed by an
independent forty-file fixture. The complete original 15 + 51 + 50 caller IDs
and their single 180-second owner are unchanged and have not been run for this
candidate. New companion failures do not fall back to Python comparison.

The selected ordinary domain uses the admitted `NativeCoreLowering` and its
normal handle registry. Mutation of private session fields, replacement of
captured builtin/type anchors, unsafe C extensions, allocator exhaustion,
traceback frame identity, tracing of additional helper frames and arbitrary
private registry mutation combined with finalizers are not proven equivalent.
The finite foreign controls establish call/binding/exception order, not an
unrestricted reference-count or debugger equivalence theorem.

## Numerical representation and HIA algorithm

There are three descriptor kinds. A Boolean carries its 0/1 bit. An integer
carries a 64-bit **limb count**, the most-significant limb width, and its sign;
using a limb count avoids imposing a 64-bit *total bit length* ceiling. A float
carries the exact IEEE-754 binary64 bit pattern. The integer descriptor has no
fixed byte-size policy limit. The addressable Python-object/ABI word model is
still finite; this is not a claim of physically unbounded storage.

HIA first produces one of `LT=0`, `EQ=1`, `GT=2`, or `UNORDERED=3`:

1. NaN is unordered for every operand, including itself. Infinity is classified
   before finite magnitudes. Both zero signs normalize to zero for ordering.
2. Different signs decide the order. A shared negative sign reverses only the
   eventual finite/infinite magnitude relation.
3. Two integers/Booleans compare limb count and top width, then request
   magnitude windows from most significant to least significant. A difference
   ends the comparison; equal windows continue down to limb zero.
4. Two non-NaN floats compare their unsigned IEEE magnitude fields after sign
   classification, including infinity.
5. Mixed finite float/integer comparison uses exact dyadic integers scaled by
   `2**1074`. An integer over 32 limbs exceeds every finite binary64 magnitude.
   Otherwise a bit-position comparison decides unequal top positions; matching
   top positions need at most 32 integer limbs. HIA aligns those words with the
   float significand's binary exponent and compares every relevant 32-bit word.
   No integer is rounded or converted to float.

A separate HIA predicate function maps all four relations to all six results:
unordered is true only for `ne`. The host validates numeric ABI ranges; it does
not recalculate the relation or predicate.

## Fixed streaming protocol

The new `HIACMP01` ABI is independent of the unchanged outer `HIALOW02` ABI.
Each entry has exactly 256 input bytes, 128 output bytes and a fresh 512-byte
workspace. A window contains at most thirty-two 32-bit little-endian magnitude
limbs. The output request gives the side, starting limb and exact count. The
reply echoes those fields and the monotonic sequence; unused header/payload
bytes must be zero. An invalid acknowledgment seals the HIA state. The adapter
consumes observation/entry/result permissions before effects and seals after
every `BaseException`, including accounting failure after a real entry return.

The host representation leaf lazily caches a positive magnitude byte string,
as the existing `ForeignGraphObserver.limbs` does. It sends only the requested
128-byte-or-smaller window to HIA. The cache may occupy O(integer size) Python
memory; it is not copied into the fixed native workspace and has no 8 MiB
policy gate. Allocation, integer sign-extension/bit-length/byte conversion,
IEEE packing, actual object ownership and memory errors remain hosted. A later
HIA object runtime must replace these representation leaves to close that
boundary. Source controls include real integers beyond 8 MiB and comparisons
that finish from summaries without materializing a magnitude at all.

## Admission and scope capture

`HEPTA_HIA_CORE_COMPARE_MANIFEST` is an optional explicit selector. Its manifest
binds the HIA source, ABI, bridge, selector, immutable image and the same compiler
SHA as the selected Core39 bundle. The Core scope caches the selected companion
or its absence. Warm source drift is checked against admitted bytes; invalid or
missing selected input is a refusal. The backend implementation identity adds
both new bridge files and the actual admitted companion identities.

The proposed builder requires the existing matching-source cold admission and
unchanged `compile_stage` (20-second wall, 10-second child CPU and 1 MiB compiler
output). That image-size limit is separate from integer value size. No native
compile or cold build is authorized or performed by the current source phase.
Resource registration, declaration closure, generated docs, installed wheel,
matching-cold gate and full-harness successor remain subsequent integration
work; this isolated draft does not alter root's frozen v87 tree or old gates.

## Validation contract

Eleven fixed source controls author/verify/roundtrip the public Core program,
check unchanged compiler caps, execute it through the independent Core VM, and
compare against retained builtin operators. They cover all twenty-four
relation/predicate combinations, bool/int equality, signed zero, NaN payloads,
infinity, subnormals, 2**53 neighbors, maximum finite binary64, signs, limb and
window boundaries, arbitrary-size integer transport, replacement targets,
foreign rich comparisons, contains, original left/right exception order,
admission drift and one-use/terminal failure behavior.

Native image loading, native compiler execution, original eighteen UNPACK
controls, original Core116, remote Actions and cold qualification are forbidden
in this phase. The interpreter is evidence of HIA source semantics only. A
later native request must freeze the actual source/image/compiler/ABI inputs,
the original compiler budgets and complete original callers before execution.
