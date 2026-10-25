# Stored borrows in explicitly scoped records

Hepta can store shared and mutable references in records with explicit lifetime
parameters. The reference Rust backend performs the actual region and alias
checking. This is a bounded language increment: it does not implement a general
lifetime/trait system or an independently proved borrow checker.

```hepta
struct Bytes<'a> { data: read 'a [u8], label: u64 }
struct Edit<'a> { data: mut 'a [u8] }

fn bytes<'a>(source: read 'a Buffer<u8>, label: u64)
    -> Bytes<'a> effects {} {
    return Bytes { data: read source, label: label };
}

fn edit<'a>(source: mut 'a Buffer<u8>) -> Edit<'a> effects {} {
    return Edit { data: mut source };
}
```

`read 'a T` and `mut 'a T` are stored field types. A record's lifetime parameters
state the regions its fields may refer to. Its instances contain ordinary Rust
references; there is no hidden box, reference count, dynamically allocated
handle or lifetime extension. This describes the lowering, not a measured
performance advantage or a proof of compiler refinement.

## Construction, use and copying

Construct a reference field with an explicit `read` or `mut` borrow. The borrow
must refer to an existing named place, a supported projection, or an existing
returned borrow. A fresh owner must be bound before it can be borrowed.

```hepta
fn main() -> Unit effects {alloc, block, panic} {
    let owner = buffer(4);
    let first = bytes(read owner, 9);
    let copied = first;
    assert(len(copied.data) == 4);
    assert(first.label == 9);
    release(move owner);
}
```

A reference field automatically denotes its referent in expressions.
`copied.data[0]` reads an element of the borrowed slice; `len(copied.data)` reads
its length. A stored reference to an owned Buffer or another owning record does
not acquire ownership of that referent. `release(move view.owner)` and similar
attempts to move an owner out through a reference are rejected.

A record containing only shared references and Copy fields is Copy. Copies
carry the same native lifetime restrictions. Releasing an owner before a later
use of any copy is rejected by rustc. Releasing it after the references' last
use can be accepted; Rust's nonlexical lifetime rules determine that boundary.
The prototype does not add lexical scope extension or hidden ownership to a
shared view.

Lifetime arguments are inferred in record constructors and function calls.
An explicit local annotation can use `Bytes<'_>`. Named lifetime arguments in a
signature must be declared by that record or function. `'_` is not permitted as
a declaration parameter or as a substitute for a named signature lifetime.

## Mutable views are affine values

A record containing a mutable reference, directly or in a nested view, cannot
be copied. Its whole value or a supported nested record field must be moved
explicitly. The Hepta resource checker requires every such value to be consumed
on each normal path. Use `drop(move view)` to end the view, or pass/return it
through an explicit ownership transfer. Dropping a view does not free the
referent and does not itself introduce allocation/blocking effects.

```hepta
fn forward<'a>(view: take Edit<'a>) -> Edit<'a> effects {} {
    return move view;
}

fn change<'a>(view: take Edit<'a>) -> Edit<'a> effects {panic, write} {
    let mut local = move view;
    local.data[0] = 7;
    return move local;
}

fn main() -> Unit effects {alloc, block, panic, write} {
    let mut owner = buffer(4);
    let view = edit(mut owner);
    let changed = change(move forward(move view));
    drop(move changed);
    assert(owner[0] == 7);
    release(move owner);
}
```

The original `view` is unusable after its transfer. Mutation through a stored
mutable field requires a mutable local root, or a mutable parameter root, and
contributes the `write` effect. A shared field never grants mutation, including
when the containing local is mutable. The Rust checker additionally rejects
overlapping mutable/shared references across fields, records and function calls.

The field modes describe reference access, not an automatically inferred
destructor protocol. A view cannot contain an owning Buffer beside references
into that Buffer. Self-referential owning records are outside this profile.

## Multiple lifetimes and nested records

Distinct named parameters allow independent owners:

```hepta
struct Joined<'left, 'right> {
    left: Bytes<'left>,
    right: Bytes<'right>
}

fn pair<'left, 'right>(left: Bytes<'left>, right: Bytes<'right>)
    -> Joined<'left, 'right> effects {} {
    return Joined { left: left, right: right };
}
```

Functions can receive a shared view by value, return it by value, or transfer a
mutable view with `take`/`move`. Nested mutable record fields retain partial-move
tracking: transferring `outer.inner` invalidates that field while an initialized
Copy sibling remains readable. Existing partial-owner rules still apply.

Region identifiers are bound by their own declarations. Calling a function does
not import its lifetime names into the caller. The structural checker compares
type shapes while the emitted Rust signature retains the declared lifetime
relationships. Rust rejects a returned view into a shorter local or into an
unrelated input region, including through nested construction or calls.

This profile permits at most eight distinct named lifetime parameters per
record/function. It has no explicit outlives clauses, higher-ranked lifetime
bounds, lifetime defaults, static references or mixed lifetime/type parameter
declarations. Passing views as `Copy`/`Owned` type-generic arguments is also
rejected. Those limitations are not silently inferred away.

## Existing `from` origins remain binding

An immediate borrowed return can use explicit lifetimes while retaining its
selected source:

```hepta
fn first<'a, 'b>(source: read 'a Buffer<u8>, unrelated: read 'b Buffer<u8>)
    -> read 'a u8 from source effects {panic} {
    return read source[0];
}
```

The return lifetime must equal the explicitly selected origin parameter's
lifetime. `-> read 'b u8 from source` is rejected here. Returning a different
input is also rejected by the existing `from` check. Using a distinct `'b` for
the unrelated argument prevents its lifetime from being unnecessarily tied to
the returned `'a` reference. The library example stores the result in a
`Head<'a>` field and releases the unrelated Buffer before using that result.

Every read/mut parameter and immediate borrowed return in a function declaring
lifetimes must name its lifetime. Existing functions without lifetime parameters
retain their previous single-origin inference or explicit `from` behavior.
Returning a borrowed record by value does not use `from`; its explicit field
and signature lifetimes define the native relationships.

## Capability and backend boundaries

The following remain rejected:

- Standalone stored-reference local values or ordinary by-value reference
  parameters. References are stored inside declared view records in this
  increment; existing immediate read/mut parameter and return syntax remains.
- Owning payloads mixed into view records, reference-to-view/reference fields,
  unsupported recursive view layouts, stored views in enums, arrays, type
  generic arguments, Buffer elements or raw-pointer pointees.
- References hiding Task/TaskGroup, Sender, Cancellation, IoReactor or IoRequest capabilities, and
  raw-pointer fields in view records.
- View lifetimes at C ABI boundaries, `repr(C)` borrowed records, and lifetime
  parameters on `main`. No C layout or foreign lifetime contract is invented.

The independent C backend emits `E_C_BORROW_STORAGE` for the entire new profile,
including an unused view declaration. Sequential resource IR, concurrent
protocol IR and the scalar HMIR pilot likewise reject the profile. They do not
claim to validate storage regions they cannot represent. The descriptive HSIR
and CFG can retain lifetime declarations, field types, parameter lifetimes and
return-origin metadata, while their proof claims remain false.

An analysis report for this profile includes `borrowed_storage` with
`native_lifetimes_required=true`. With `native=False`, the report is explicitly
`frontend_only` and `native_lifetimes_checked=false`, even when the structural
frontend accepts a program that Rust later rejects. Successful actual native
checking sets that field true. This remains a native Rust check of emitted
code, not a proof of the Hepta-to-Rust translation or of foreign unsafe code.

## Reproducible qualification and diagnostics

```sh
python -m hepta run examples/borrowed_storage/main.hepta --json
python tools/qualify_borrowed_storage.py --output /tmp/borrowed-storage.json
python -m unittest tests.test_borrowed_storage
```

The two-file library executes reference construction, shared copies, two
lifetimes in nested records, mutable transfers and writes, returned `from`
references, non-origin owner release and final owner cleanup. Its assertions
and output require the value `275`. Four additional native programs exercise
scope shortening, disjoint owned fields, nested mutable field transfers and
per-iteration mutable-view consumption.

The qualifier runs five valid native programs. Ten other candidates must pass
the structural frontend and fail actual pinned Rust metadata checking for
owner release under a copied view, owner read/write under live views,
overlapping reference fields, local escape and unrelated return regions.
**Those rejected candidates are never linked or executed.** Twenty-two additional
frontend controls check affine use, borrowed owner theft, `from` mismatch,
scope/arity and explicitly unsupported storage shapes. The unit suite also
builds a real reference-only `no_std` object.

Native rejection records retain the exact generated source, actual metadata
command, complete JSON diagnostic transcript, compiler identity and mapped
Hepta source spans. Valid executions retain checked frontend identities,
nonempty native artifact hashes and actual output. Reports and artifact
directories cannot overwrite an earlier attempt; failures keep their partial
observations.

`validate_borrowed_storage_report` binds the current source/compiler identity,
every expected case exactly once, current source lowering, pinned toolchain,
successful native builds and executions, compile-only rejection transcripts,
source mappings and each rejected backend/IR profile. It also rejects missing
checks, changed bodies/results, boolean-as-integer counts, duplicate cases and
inflated proof claims. It does not run a rejected candidate or authenticate
arbitrary fabricated third-party JSON. Historical machine paths remain
historical; rerunning in another checkout produces a new report.
