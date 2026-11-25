# Native immutable multiversion values

This component owns arbitrary nonnegative decimal values and individual strong
references. It does not establish that the entire multiversion runtime is
complete. Public generation, epoch, accounting and error-order integration is
qualified separately.

The native HIA policy allocates immutable values, validates live capabilities,
serializes registry changes with an actual kernel futex, and releases memory.
The mechanical bridge supplies syscall, atomic compare/exchange, malloc, free,
copy and the fixed pure decimal role. It does not decide admission or ownership.
No Python or C business logic is in the runtime path.

## Private six-word entry

`hia_mv_values(input, input_bytes, output, output_bytes, context, context_bytes)`
uses a shared 256-byte context and a disjoint output of at least 512 bytes for
each invocation. The caller initializes the context exclusively, retains it
through every active call, and owns each returned capability. Source and output
must not alias. Context and memory capabilities are private trusted composition
interfaces, not caller supplied public addresses.

The input is a 128-byte little-endian header with optional decimal bytes:

| Offset | Field |
|---|---|
| 0 | `HIAMVU01` |
| 8 | 0 initialize, 1 create, 2 retain, 3 drop, 4 increment, 5 add, 6 subtract, 7 compare, 8 copy, 9 destroy |
| 16 | Zero |
| 24, 32, 40 | A capability: node address and two nonce words |
| 48, 56, 64 | B capability, only for add/subtract/compare |
| 72 | Decimal byte length; only create has a tail |
| 80..127 | Zero |
| 128 | Canonical decimal digits for create |

Initialize, create and destroy require both capability triples to be zero.
Other unary operations require the B triple to be zero. Canonical digits are
`0` or a nonzero digit followed by digits, with no fixed numeric width.

A completed reply returns zero and begins with `HIAMVUR1`:

| Offset | Field |
|---|---|
| 8 | Status: 0 success, 1 invalid reference, 2 invalid digits, 3 subtraction underflow, 4 allocation failure, 5 lifecycle/PID failure, 6 syscall failure, 7 copy output too small, 9 invariant failure |
| 16, 24, 32 | New capability, or zero |
| 40 | Result digit length |
| 48 | Comparison: 0 less, 1 equal, 2 greater |
| 56 | Owning PID |
| 512 | Copied digits for copy |

Malformed private input or insufficient minimum output/context returns
`0xfffffffd`. The bridge may use its private output continuation before this
refusal, so the outer frame does not promise the pure value role's untouched
output property. Copy output shortage is a structured status 7. No arithmetic
result or public counter is silently truncated to u64.

## Ownership and synchronization

Every returned reference is a distinct 96-byte allocation containing its owner,
object link and fresh 128-bit nonce obtained with `getrandom`. Lookup first walks
the live registry under its mutex and validates the nonce before dereferencing
the referenced object. A stale or foreign capability is rejected. Values are
immutable. Retain allocates another ownership node instead of incrementing a
finite machine reference counter. The last reference removes its immutable
value from the registry and frees it. Destruction refuses while references are
live, then permanently closes this context.

The shared context contains its magic, PID, live reference head, closed flag
and 32-bit futex mutex. Invocation continuation fields live in the private output
and therefore cannot overwrite another thread's operation. Forked children
cannot operate on the parent's initialized context. Allocation failure unwinds
only allocations made by that attempt and leaves existing values and references
usable. Lifecycle closure does not forcibly invalidate another caller's live
reference.

## Pure values and native construction

The fixed companion is `unsigned_decimal_values.hepta`, using `HIAUVL01` and
`HIAVLR01`. Its complete return convention and independent 4,024-case evidence
are in the unsigned decimal documentation. Its result length is a u64 field,
not the entry's u32 return value. This owner adds actual allocation and lifetime
semantics to that already qualified arithmetic.

`multiversion_values_packer.hepta` accepts `HIAMVUP1`, role count 2 and two u64
lengths, followed by actual policy and pure-value flats. Each role is nonempty
and at most 4 MiB. It emits the canonical seven-section ET_REL object exporting
only `hia_mv_values`, with fixed `malloc` and `free` imports. The existing native
shared linker creates the executable shared object. The readable mechanical
source is `tools/hia_multiversion_values_bridge.S`; running the assembler is
only a development provenance check and is not required by native construction.

## Actual qualification

The checked image is 152,336 bytes, SHA256
`7bc67d8cc2bba8d323d333493cc9fdfbba88d46907f452246b41bd466d32f4e8`.
Seven functional groups made 6,930 actual native invocations. They include
independent integer comparisons, values crossing machine widths, a 1,048,577
digit carry and borrow, stale and foreign capabilities, fork rejection, and 16
actual threads repeatedly retaining, computing and dropping references.

Sixteen allocation/lifetime cases inject failure at actual native allocation
call sites. They verify unchanged prior values, lock release, successful retry,
and exact allocation/free balance, including 1,001 simultaneous references.
Twenty-four native packaging cases verify exact ET_REL/shared ELF bytes,
mechanical provenance, private framing, short outputs, transactional refusal
and the original role capacities. All passed; complete reports and source pins
are embedded in `HIA_MULTIVERSION_VALUES_NATIVE.json`.
