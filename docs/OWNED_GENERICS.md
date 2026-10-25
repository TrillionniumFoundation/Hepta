# Finite ownership constraints for functions

Generic functions accept two checked constraints: `Copy` and `Owned`.
An omitted constraint remains `Copy`, preserving existing programs. These
are built-in capabilities, not an extensible trait system.

```hepta
fn forward<T: Owned>(value: take T) -> T effects {} {
    return move value;
}

fn dispose<T: Owned>(value: take T) -> Unit effects {alloc, block} {
    drop(move value);
}

fn finish<T: Owned, E: Copy>(value: take T, ok: bool, error: E)
    -> Result<T, E> effects {alloc, block} {
    if !ok {
        dispose::<T>(move value);
        return Result::Err(error);
    }
    return Result::Ok(move value);
}
```

`Owned` accepts supported sized resource values: Buffer, resource-bearing
structs, enums and Result, including nested supported data instantiations.
It excludes Copy values. `Task`, `TaskGroup`, `Cancellation` and `Sender`
remain scoped capabilities and cannot be smuggled through either constraint.
Resource arrays, raw pointers to resources and nested resource buffers remain
unsupported even when an abstract Owned parameter is substituted into them.

Every function body is checked under its declared constraints, including
functions that are never called. A `T: Owned` value requires take/read/mut
parameter modes; initialization, forwarding and return require explicit
ownership transfer. Every normal exit must discharge its owners. Consuming
matches on `Result<T, E>` expose the corresponding Copy or Owned payload
obligation. Early returns, continuing branches, loops and short-circuit
expressions retain the existing ownership rules. `drop` infers alloc/block;
a generic destructor helper cannot hide those effects.

Neither constraint implies methods, arithmetic, comparison, allocation,
custom destructors or a particular representation. Abstract Owned values can
be transferred, dropped, wrapped in supported ADTs, or borrowed. A generic
returned view still needs one declared input origin (inferred for a unique
borrowed input, otherwise selected using `from parameter`) and cannot escape from
a local owner. Named partial field moves also work in uninstantiated generic
bodies; `PARTIAL_PLACES.md` defines restoration and cleanup. Stored references,
multi-origin lifetime parameters and user-defined traits remain open language work.

## Instantiation and native execution

Calls supply explicit type arguments. A generic function can call another
generic function using its own parameters when their constraints satisfy the
callee. An Owned parameter cannot silently satisfy Copy, and Copy cannot
silently satisfy Owned. The interface hash and semantic IR include normalized
constraints, so changing Copy to Owned is an interface change; spelling an
existing implicit Copy constraint explicitly is not.

Rust lowering uses `T: Copy` for Copy parameters and ordinary sized Rust
parameters for Owned. The Hepta frontend enforces the resource capability;
the Rust backend checks concrete ownership and borrowing and monomorphizes
the function. The implementation introduces no boxing, vtable or additional
allocation to implement a generic call. This is a lowering property, not a
universal performance claim. Raw Rust callers are not a substitute for the
Hepta instantiation gate, and generic functions have no stable C ABI.

Native tests retain a case in which the Hepta frontend accepts aliased
generic `mut`/`read` arguments and Rust rejects the borrow conflict. Frontend
acceptance does not replace the native gate. Panic-abort or forced process
termination still does not guarantee that destructors run.

## Independent generic resource verification

`hepta.resource-ir.v2` introduces function-scoped opaque type parameters,
identified by the declaring function and parameter name. Each has exactly
one Copy or Owned constraint. The standalone verifier imports no source
parser, checker or AST, and checks every generic body once under these opaque
types, including uninstantiated declarations. It does not sample a Buffer
specialization and present that as a universal generic-body check.

Every generic call carries explicit type arguments. The verifier checks:

- Declared type arguments exist, are in the caller's scope and meet the
  callee's sized Copy/Owned constraints.
- Ownership and borrowed argument/result types agree after substitution.
- Every substituted aggregate has the complete payload shape declared by
  the generic type. A forged `Box<Buffer<u8>>` cannot silently replace the
  `Box<T>` resource field with a copied scalar.
- Type parameters cannot escape their declaring function, appear as
  unbound declarations, or masquerade as foreign generic ABI contracts.
- Generic ownership transitions, drop, loans and CFG joins obey the same
  rules as concrete resource functions.

Type depth, type tables and graph sizes stay bounded. Substitution memoizes
shared type subgraphs. Legacy v1 concrete graphs remain accepted; v1 cannot
contain the v2 generic type feature. Source hashes are still correlation
metadata, `source_binding_verified=false`, and the IR is not a native codegen
input. The resource model does not prove source-to-IR refinement, Rust codegen
refinement, effects, arithmetic, termination or whole-language soundness.
Concurrency IR is still unsupported even though native generic cleanup can
run inside the existing non-generic task workers.

## Executable evidence

The two-file `examples/owned_generics` library implements forwarding, disposal,
fallible finishing, recovery with a backup owner, owned success/error choice
and returned views. Its executable exercises success, error and early-return
paths with concrete Buffer and resource-bearing Packet instances.

```sh
RUSTC=/path/to/rustc python -m unittest tests.test_owned_generics -v
RUSTC=/path/to/rustc python -m hepta run examples/owned_generics/main.hepta --json
RUSTC=/path/to/rustc python -m tools.validate_resources --output /tmp/new-resources.json
```

The native tests additionally observe real allocator/free calls across both
Result branches and early returns; two tracked resource allocations across
cooperative cancellation and reported worker failure; and an allocator's
actual refusal followed by recovery through a generic Result forwarding
function. Negative graph mutations remove a generic destructor, duplicate an
abstract move, omit or falsify call type arguments, escape a callee parameter
and corrupt a substituted payload shape. None of these test results replaces
the complete source-bound release qualification.

The feature snapshot and its 397-test focused regression run are archived in
`evidence/owned_generics/manifest.json`, with hashes for every changed compiler
input, example, test module and report. That archive describes its recorded
compiler snapshot; the complete integrated release must be rerun after other
compiler changes.
