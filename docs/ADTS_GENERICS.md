# ADTs, exhaustive matching, and checked generics

This document describes an implemented bootstrap subset. The compiler parses
these constructs into the shared AST, checks every generic body, and lowers
checked operations to Rust 1.90.0. Native validation and builds still require
the real pinned compiler. A frontend-only result does not establish native
borrow correctness or successful code generation.

## Algebraic data types

An enum contains named unit variants or positional payload variants:

```hepta
pub enum Event {
    Idle,
    Point(i64, i64),
    Done(bool),
}

fn score(event: Event) -> i64 effects {panic} {
    match event {
        Event::Idle => { return 0; },
        Event::Point(x, y) => { return x + y; },
        Event::Done(success) => {
            if success { return 100; }
            return 1;
        },
    }
}
```

Construct values with `Event::Idle`, `Event::Point(4, 7)`, or
`Event::Done(true)`. Unit variants omit parentheses. Tuple payload arity and
types are checked. Enum names and variants occupy resolved source namespaces;
they are never copied into Rust as arbitrary source fragments.

Enum payloads are sized. They may contain Copy values or owned Buffer-bearing
values. Owned payloads require consuming matches, explicit ownership transfer,
and discharge on all normal exits; see [OWNED_TYPES.md](OWNED_TYPES.md) for
the implemented resource rules. Task, TaskGroup, Cancellation and Sender
remain scoped runtime capabilities and cannot be hidden inside an ADT.

## Match semantics

`match` is a statement. Its scrutinee is evaluated once. Each arm has an exact
qualified variant pattern and a block. Each variant must appear exactly once.
Unknown variants, duplicate arms, missing arms, wrong enum names, and payload
arity errors produce positioned diagnostics before native validation.

Payload names introduce immutable bindings visible only in their arm. A `_`
payload ignores a Copy field. Ignoring an owned payload is rejected. It is possible to write `Result::Err(_)` for a Copy error; a `_`
catch-all arm is not supported. Guards, nested patterns, alternatives, integer
patterns, match expressions, and implicit arm return values are also not
supported. Each arm must use the same statement syntax as a function body.

Matching a `read` parameter copies selected Copy payloads. Owned enum values
use a consuming match and produce fresh payload obligations. No reference escapes from a pattern.
Native Rust checking still validates aliasing of surrounding read/mut calls.

Effect inference visits every arm, including arms whose contents appear
unreachable to a reader. Every normally continuing arm must leave the same
linear owners live. Returning arms must consume all incoming owners before
returning. Existing unsafe requirements, resource clauses, and transitive task
worker effect restrictions apply within matches.

## Generic structs, enums, and functions

```hepta
struct Pair<T, E> { left: T, right: E }
enum Maybe<T> { None, Some(T) }

fn identity<T>(value: T) -> T effects {} {
    return value;
}

fn choose<T>(value: read Maybe<T>, fallback: T) -> T effects {} {
    match value {
        Maybe::None => { return fallback; },
        Maybe::Some(payload) => { return payload; },
    }
}
```

Generic **function** type parameters have an implicit `Copy` and sized bound.
Generic data declarations can also be instantiated with supported owned values;
their concrete ownership follows the payloads. There is no trait declaration
syntax. Generic function code can move or copy a parameter, borrow
it for a call, access known generic struct fields, construct or match known
generic enums, and pass it to another explicitly instantiated generic function.
Generic code cannot assume numeric, equality, ordering, or other operator
support. An unused function containing `return value + 1;` for an abstract `T`
is rejected even when no call instantiates it.

Calls require explicit type arguments:

```hepta
let number = identity::<u64>(17);
let pair = Pair::<u64, bool> { left: number, right: true };
let option = Maybe::<Pair<u64, bool>>::Some(pair);
let answer = choose::<Pair<u64, bool>>(read option, pair);
```

Constructors can obtain their arguments from an exact expected nominal type:

```hepta
let pair: Pair<u64, bool> = Pair { left: 17, right: true };
let option: Maybe<Pair<u64, bool>> = Maybe::Some(pair);
```

Expected types propagate into constructor fields and enum payloads. There is
no general Hindley-Milner inference, inferred function type argument list,
overloading, specialization, trait dictionary, const generic, higher-kinded
type, lifetime generic, higher-order function, or closure implementation here.
Type parameters cannot duplicate each other or shadow a declared or reserved
type name. Each generic struct/enum parameter must occur in a field or payload;
phantom parameters are rejected. Generic `main` and generic C boundary
functions are rejected.

The backend emits ordinary bounded Rust generics and concrete turbofish calls.
Rust performs monomorphization for instantiated code. The frontend checks every
body parametrically; it does not postpone type/effect/resource checks until a
template is called. This is not a new independent machine-code backend or a
proof of generic type soundness. Rust compilation and code-generation limits
still apply, including limits on pathological recursive instantiation.

## Built-in Result

`Result<T, E>` is a reserved, two-parameter enum with `Ok(T)` and `Err(E)`
variants. It is Copy when both parameters are Copy; supported owning payloads
make the concrete Result an owner. It lowers to `core::result::Result<T, E>`;
Copy instances work in the supported no_std profile:

```hepta
fn divide(a: i64, b: i64) -> Result<i64, u8> effects {panic} {
    if b == 0 { return Result::Err(7); }
    return Result::Ok(a / b);
}
```

Both success and failure cases must be handled by an exhaustive match. There
is no `?` operator or implicit exception effect. `Result<Buffer<u8>, E>` and
supported resource-containing instantiations use the explicit consumption rules
in [OWNED_TYPES.md](OWNED_TYPES.md). Result values may be nested inside generic structs/enums. Explicit
constructors use `Result::<u64, u32>::Ok(9)` when no expected type exists.

## Layout, ABI, and resource limits

By-value layout cycles are rejected across structs, enums, and instantiated
generic fields. The layout check tracks which generic arguments occur by
value, so pointer indirection such as `Link<T> { pointer: raw const T }` may
break a recursive layout cycle. Pointer validity, lifetime, alignment,
initialization, and aliasing remain unsafe obligations; layout acceptance does
not establish them.

Enums, Result, and generic structs have no promised stable C ABI in this
release. They are rejected at exported/imported C boundaries, including behind
raw pointer declarations. Generic `repr(C)` structs are rejected. Existing
nongeneric supported `repr(C)` structs and explicit C declarations retain
their previous behavior. Use an explicit supported C representation and a
conversion function when crossing that boundary.

Copy ADTs and their constructors do not introduce heap allocation or an
implicit garbage collector. Calls inside payload expressions retain their
declared and inferred effects. This implementation does not establish a
general performance advantage over Rust, compiler semantic equivalence,
whole-language soundness, bounded cancellation latency, or deadlock freedom.

## Executable evidence

`tests/test_language.py` runs source through the public pipeline and executes
native binaries for success/failure Result paths, multiple generic
instantiations, borrowed matching, nested generic reconstruction, tuple
variants, mutable generic calls, and linear owner consumption across match
arms. It builds a no_std object as well. Negative cases cover unsupported
generic operators, nonexhaustive/duplicate patterns, payload and arity errors,
resource hiding, C boundary restrictions, transitive worker effects, and a
1050-node nominal layout cycle.

Cross-feature tests pass runtime GroupReport values through Result and generic
functions, consume TaskGroup owners in exhaustive match arms, reject Sender
retention, and reject unsafe worker effects hidden behind generic calls or
match arms. Runtime type discovery also covers an otherwise unused enum
payload or an explicit generic argument.

A dedicated test confirms that a generic mutable/read alias can pass the
limited frontend and is then rejected by the real Rust borrow checker. This
keeps the validation boundary visible instead of labeling frontend acceptance
as native correctness.
