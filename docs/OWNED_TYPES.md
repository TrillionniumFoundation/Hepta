# Owned data types and single-origin returned borrows

This extension implements Buffer-bearing structs, enums, generic data types,
and `Result<Buffer<u8>, E>` in the Rust-backed hosted profile. It replaces the
earlier Copy-only restriction on **data type instantiations** described in
`ADTS_GENERICS.md`. Generic **functions** retain their implicit Copy constraint.
Native checks and builds still run the pinned Rust 1.90.0 compiler. Frontend
acceptance alone is not a complete borrow proof or a native execution result.

## Whole-value ownership

```hepta
struct Packet<T> { bytes: T, tag: u32 }
enum Envelope<T> { Empty, Data(T) }

fn create(size: usize) -> Result<Packet<Buffer<u8>>, u8>
effects {alloc, block} {
    match try_buffer(size) {
        Result::Ok(bytes) => {
            return Result::Ok(Packet { bytes: move bytes, tag: 3 });
        },
        Result::Err(code) => { return Result::Err(code); },
    }
}

fn consume(packet: take Packet<Buffer<u8>>) -> usize effects {alloc, block} {
    let count = len(packet.bytes);
    drop(move packet);
    return count;
}
```

A type is owned if its concrete arguments or nominal fields/payloads contain
a Buffer. The owning instance is tracked as one whole value. Initializing a
resource field, passing ownership, assigning a new local owner, and returning
a named owner require explicit `move`. Fresh constructors and fresh owning
function results may initialize a resource position directly. The existing
direct Buffer return spelling continues to require `return move value`.

Resource parameters use `take`, `read`, or `mut`; plain value parameters cannot
hide ownership. Every normal scope exit and early return must have consumed
all owned values. Branches that continue must agree on live owners. Loop and
short-circuit rules apply to aggregates in the same way as top-level Buffer.
Moved aggregate fields cannot subsequently be read or borrowed.

`drop(move value)` and `release(move value)` recursively destroy a whole owned
data value. They infer `alloc` and `block`, matching the conservative hosted
deallocation effects. There is no user-defined destructor protocol in this
extension. Resource aggregates do not implicitly clone, acquire a garbage
collector, or permit reassignment. Named fields may be borrowed without moving
their enclosing owner. Partial field moves are deliberately rejected: use a
consuming enum match to unpack payloads, or borrow and eventually drop the
whole struct.

Generic data declarations need no unconditional Copy bound. A generic data
type with Copy payloads remains Copy; an instantiation with Buffer payloads is
owned. Concrete declarations that contain Buffer never derive Copy. Generic
functions such as `identity<T>(x: T)` still require Copy type arguments; this
release does not pretend to implement ownership-polymorphic function bodies.

## Consuming matches

```hepta
let pending = create(64);
match move pending {
    Result::Ok(packet) => { drop(move packet); },
    Result::Err(code) => {},
}
```

`match move pending` consumes the aggregate. Matching an owning function call
or fresh constructor directly is also permitted. Every owned payload becomes
an immutable owner local to its arm and must itself be transferred or dropped
on all normal exits. A mutable local can be introduced with
`let mut bytes = move payload;`. An owned `_` payload is rejected rather than
silently discarded. Scalar/Copy `_` payloads retain their previous meaning.

All variants must be covered exactly once. Nested owned enums can be unpacked
with another consuming match. There is no implicit `?` propagation or hidden
drop at an early return. Even an `Err(1)` value of a resource-bearing Result
type carries the outer type's owner obligation until matched or dropped; the
checker does not silently make ownership depend on an assumed active variant.

Task and TaskGroup handles remain restricted to their creating scopes and must
be joined. They cannot be wrapped in an ADT, returned, or passed to `drop`.
Cancellation and Sender remain borrowed runtime capabilities. Resource arrays,
resources behind raw pointers, and nested `Buffer<Buffer<...>>` remain outside
the profile. These restrictions are checked again through generic payload
instantiation, including indirect wrappers, so a generic declaration cannot
hide an unsupported container.

## Fallible byte allocation

`try_buffer(size)` has type `Result<Buffer<u8>, u8>` and effects `{alloc, block}`.
It evaluates the size once, starts with an empty Vec, and uses
`Vec::try_reserve_exact`. A failed reservation returns `Err(1)`; success fills
the reserved bytes with zero and returns their owner. The error deliberately
does not distinguish capacity overflow from allocator refusal. A zero-length
request succeeds with an empty buffer.

The native implementation uses no further allocation to initialize the
already-reserved u8 storage. This gives a fallible allocation operation for
bounded migrations that preserve their allocation-failure branch. It is not
a promise that the operating system cannot terminate an overcommitted process,
that every external allocator reports failure correctly, or that arbitrary
malloc programs can be translated. Original C reads of uninitialized memory
are not justified by Hepta's zero initialization. Existing `buffer(size)`
retains its infallible/abort behavior and its `panic` effect.

## Returned borrows with one source

```hepta
struct Packet { bytes: Buffer<u8>, tag: u32 }

fn bytes(packet: read Packet) -> read [u8] effects {} {
    return read packet.bytes;
}

fn writable(packet: mut Packet) -> mut [u8] effects {} {
    return mut packet.bytes;
}

fn sum(input: read [u8]) -> u64 effects {panic} {
    let mut total: u64 = 0;
    for i in 0..len(input) { total = wrapping_add(total, input[i] as u64); }
    return total;
}
```

A borrowed-return function has exactly one `read` or `mut` input parameter.
Its returned place must derive from that input, possibly through fields,
indexing, or another single-origin borrowed-return function. A `mut` return
requires a mutable source. Borrowing a local, a fresh allocation, or an owned
parameter for the return is rejected. Multiple borrowed inputs are rejected
until explicit lifetime relationships are implemented. Runtime capabilities
cannot escape through borrowed returns.

The result is a place for immediate reading, indexing, assignment when mutable,
or reborrowing, for example `sum(read bytes(read packet))` or
`writable(mut packet)[0] = 7`. Copy values can be read by value from this place.
Resource values cannot become new owners, even via an explicit move. This
extension has no first-class local reference variables and no stored borrowed
fields; `let alias = read packet` is still rejected.

Rust lowering uses real `&T`/`&mut T` returns with the unique input lifetime.
Real rustc checking rejects overlapping returned borrows and moving an owner
while a returned borrow is still needed by an enclosing call. These cases are
tested as native negative tests; the bootstrap frontend is not claimed to
independently prove all these lifetime relationships.

## Fields and backend boundaries

The Rust backend can borrow disjoint named fields, including two different
Buffer fields of one owner, while keeping the enclosing value live. The
independent C backend now distinguishes statically disjoint named struct
fields. It rejects the same field, ancestor/descendant overlaps, and unproved
array-index disjointness. It continues to reject effectful nested borrowed
argument evaluation conservatively.

Owned data and returned borrows have no new C ABI. The independent C backend
rejects resource ADTs and every borrowed-return declaration, including unused
ones. Scalar pointee types must not be mistaken for by-value returns by IR or
interface consumers. `Function.return_mode` records `value`, `read`, or `mut`;
the pointee remains in `return_type`.

The checker exports `is_owned_type(program, type)` for semantic consumers and
records encountered owned expression types in `CheckResult.owned_types`.
Classification alone does not validate a type or discharge an ownership
obligation. Generated Rust contains JSON `hepta-source` comments before
statements and declarations for source diagnostic mapping; these are source
metadata and have no intended machine-code behavior.

## Executable evidence and limits

`tests/test_owned_types.py` executes nested resource ADTs, success and failure
Result payloads, tuple payloads, early-return ownership transfer, real task
cancellation, and reported worker failure. A native instrumented allocator
counts actual allocations and frees for recursive aggregate drops. A separate
allocator deliberately returns null for one request size and confirms that
`try_buffer` returns Err and the process continues; capacity-overflow and
zero-length paths are exercised separately.

`tests/test_borrowed_returns.py` executes read/mutable returned borrows, chained
reborrows, Copy reads, a real no_std object, disjoint resource fields, and
matching Rust/C nested-field behavior. It verifies local-reference escapes,
owned-result theft, runtime-capability escape, unsupported C borrowed returns,
and native overlapping-borrow rejection.

`examples/owned/buffers.hepta` is a small imported ownership library with
fallible creation, filling, checksum, forwarding, and explicit close;
`examples/owned/main.hepta` exercises it through the real module loader.

The resource guarantee covers normal control-flow exits. The hosted compiler
still uses `panic=abort`; panic, process termination, and OS termination are
not a promise that destructors execute. Cancellation remains cooperative and
has no proven deadline. This work is neither a proof of whole-language
soundness nor evidence of a performance advantage over Rust.
