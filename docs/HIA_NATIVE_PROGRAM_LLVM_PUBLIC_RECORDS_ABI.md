# Native HIAProgramLLVM record

This component adds a real immutable record to the existing single Value
graph. It retains the fifteen-role HIABVP08 image layout and all original
request domains.

## Canonical classes

Q05 operation 99 accepts only argument 104 equal to 46 or 47. Capability,
tail and other argument fields must be zero. It returns an ordinary strong
class capability.

| ID | Canonical class | Direct base |
|---|---|---|
| 46 | HIAProgramLLVM | object |
| 47 | HIAStaticBudgetRejected | ValueError |

The original operation 87 still accepts only 38 through 42; operation 98
still accepts only 43 through 45. Neither is expanded by this component.

## Record construction and fields

Q05 operation 100 takes a real list or tuple of exactly nine field references
as capability A. Optional capability B selects an actual class whose MRO
includes canonical HIAProgramLLVM. All other arguments, C, tail and reserved
fields must be zero. Without B the record uses canonical class 46.

The fields are text, sha256, core_sha256, implementation_sha256, exports,
profile, target, input_sha256 and layout, in that order. The resulting node
has actual kind 12, class and field graph edges, and exposes each field through
the existing Q04 operation 43. It is not a tagged dictionary.

The original frozen Python dataclass does not validate its field annotations
at construction. This primitive likewise retains arbitrary actual field
objects, including mutable containers, without granting verification or
compilation authority. The immutable record shares those field objects and
keeps them alive; their contents do not become immutable merely because the
record is frozen.

Existing native record equality requires the same actual class and compares
all fields. Hashing uses the existing real tuple/record algorithm; mutable
unhashable fields reject hashing. The gate compares exact numeric record
hashes and Python 3.14.4 NaN/identity equality behavior. Mutable field aliases,
real subclasses and record/container cycles are exercised through native
capabilities and final graph counts.

## Evidence and remaining public work

The new component passed 17 groups, including 90 non-annotated field values,
all nine field identities, original defaults represented as actual values,
subclass identity, numeric/NaN equality and hashes, mutable aliases,
malformed requests and final native cycle collection.

All six original component gates, all six original campaigns with the
original 300/660-second limits, and the existing records, resources,
VerifiedProgram, exception, protocol, packer, managed-edge, invocation,
invocation-custody, truth-prerequisite and deferred-capture gates were
rerun against this exact native image.

This fixed nine-field constructor is the lower-level primitive for the
public LLVM owner. Public positional/keyword/default argument binding,
fresh emission and all-field origin validation, actual command logging,
bounded_resource_limits, specialized exception construction and final
enclosing runtime remain separately tracked.
