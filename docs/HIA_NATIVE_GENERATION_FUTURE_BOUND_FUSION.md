# Native bound Runtime / Future fusion

This component combines the bound Runtime owner, its actual provider capsule,
the current 13-role Value implementation and the Future implementation in one
native image. It is a qualified component; public construction, callable and
managed Future ownership, complete background execution and the final release
remain separate gates.

## Construction

The new private packer protocol is `HIAGFUP2`: a 520-byte header identifies
63 length-delimited roles. The existing `HIAGFUP1` and owner profiles retain
their previous semantics. Each role remains limited to 4 MiB and the final
text to 16 MiB. The compiler keeps its original function, block and operation
budgets.

The native packer lays out 56 unique code bodies. It removes 686,499 bytes of
identical position-independent code and places exactly one 2,861,387-byte
Value body in both the object and linked image. Runtime and Future dispatch
through that same entry and the same native Value arena.

The bound provider capsule has three fixed imports into the same carrier,
effects dispatcher and Value entry. Its four allocator relocations are rebased
to its actual capsule position. All seven unresolved holes are checked before
writing output. No request-supplied function pointer performs these bindings.

The native source closure contains 69 source-bound modules from the qualified
bound owner plus nine additional double-compiled modules. Native packer bytes
match an independent object oracle; the HIA runtime linker produces the shared
image. Python authors and qualification code are development tools only.

## Actual qualification

The retained tests exercise 141 malformed packer and short-buffer controls,
with unchanged sentinel bytes on rejection. Fourteen original coupled resource
and owner cases cover both release orders, shared binding, concurrent last
references, pending Runtime and Lease retirement, Future cleanup, public
lifecycle, active destroy, typed calls, actual OS failure retention and sealed
tool-bank custody.

The two Future ownership cases additionally compare actual native addresses:
their Value entry equals the Runtime entry, and their Value arena is the
owner's actual arena at offset 512. These checks do not substitute for the
pending full public Runtime, Future or background API gates.

See `HIA_NATIVE_GENERATION_FUTURE_BOUND_FUSION_QUALIFICATION.json` for exact
source and product hashes, captured build provenance and retained evidence.

## Reproduction

`tools.qualify_hia_generation_future_bound_fusion` accepts the retained native
compiler, a qualified bound-owner build and its exact HIA source snapshot.
It independently checks every captured source/flat pair, compiles additional
roles twice, executes the native packer and native linker, checks the original
byte oracle, and runs the coupled tests with the actual normalizer, proof and
builder executables. The snapshot is an input custody mechanism for this
development qualification; the final production graph must build the same
sources directly.
