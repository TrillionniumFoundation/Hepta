# Core hosted primitive ownership audit

## Outcome and scope

The next useful complete value-control owner is fixed positional **UNPACK (arity 1–4)**. This is an implementation plan, not a new native implementation or an activation change. The current Core product remains the exact 946f3fd candidate and retains nineteen explicitly hosted primitive classes.

The preceding native development run is fully sealed in [842be83d](https://github.com/TrillionniumFoundation/Hepta/commit/842be83dc63de511d4a4fcb461ddf546e4689d91): all 39 native units compiled, and the original complete **15+51+50 = 116** methods ran within one unchanged 180-second owner, with three seconds of cleanup grace. Preparation took 16.384195745 seconds in its own report; the complete qualifier reported 96.67554662 seconds. This is development evidence. It does not establish matching-source cold qualification, full retained qualification, or removal of the Python object runtime.

This audit changes no product source, selector, limit, test expectation, or default. The exact source pins are in SOURCE-PINS.json. A new read-only IR scan imported only the frozen authoring IR module and parsed its frozen policy. It did not render HIA, compile a native image, import the product backend, or run a product test.

## Measured static surface

The new scan found **36 modes, 2,428 IR instructions, 312 literals and 1,830 primitive effect sites**. These are static source sites. The actual 116 report records native step returns by group/mode/unit/status; it does not record primitive opcode frequency. Neither the site counts nor the earlier 4,861,760 step returns identify an individual primitive as a measured runtime bottleneck.

| Opcode | Primitive | Static sites | Current host work | Dependency for migration |
|---:|---|---:|---|---|
| 1 | GLOBAL | 102 | Ordered helper-map, module namespace and builtins lookup, then NameError construction. | policy |
| 2 | ATTR | 495 | getattr(object, name). | object-runtime |
| 3 | SET_ATTR | 34 | setattr(object, name, assigned). | object-runtime |
| 4 | ITEM | 236 | object[key]. | container-runtime |
| 5 | SET_ITEM | 7 | object[key] = assigned. | container-runtime |
| 6 | CALL | 463 | Dynamic target(*positional, optional keyword/mapping), up to four direct positional arguments. | foreign-runtime |
| 7 | PACK | 60 | Build list/tuple/set/dict from HIA-selected handle vector. | container-runtime |
| 8 | ITER | 52 | iter(object). | foreign-runtime |
| 9 | NEXT | 52 | next(iterator), with StopIteration converted to exhaustion flag. | exception-runtime |
| 10 | TRUTH | 123 | int(bool(object)). | scalar-and-slot-runtime |
| 11 | BINARY | 80 | 24 ordinary/in-place operator choices; current policy uses8 suboperations. | scalar-and-slot-runtime |
| 12 | UNARY | 9 | operator.pos/neg/invert; current policy usesneg only. | scalar-and-slot-runtime |
| 13 | COMPARE | 83 | eq/ne/lt/le/gt/ge plus in/not-in. | scalar-container-and-slot-runtime |
| 14 | UNPACK | 20 | CPython fixed assignment unpack of1..4 targets; current policy20 sites. | recommended-next |
| 15 | SLICE | 2 | Allocate slice(low, high, step); no index normalization here. | value-allocation |
| 16 | APPEND | 6 | list.append(object, item), deliberately bypassing overridden .append lookup. | container-runtime |
| 17 | IMPORT | 3 | Three actual relative imports: VALUE_REGISTERS, code_options, emit_wrapper. | foreign-runtime |
| 18 | RAISE | 1 | raise exception/class selected by HIA. | exception-runtime |
| 19 | GENERATOR | 2 | Create a real Python generator whose body decisions and yields are HIA-controlled. | foreign-runtime |

There is also host work outside the opcode list: decoding the literal pool into Python objects, handle identity and lifetime, method argument binding and class allocation, real generator objects, and the separate byte-ABI wrapper. A claim that “all nineteen are moved” would still need to account for these paths.

## What is already controlled by HIA

The generated units choose original method/helper control flow, operand handles, loops, branches, effect order, returns, handoffs and the two lazy generator bodies. Identity tests are HIA handle comparisons. Literal truth folding occurs in the authoring compiler for actual source literals. Those facts do not make the runtime values at mutable handle positions immutable.

The primitive adapter still implements whole Python operations. In particular GLOBAL contains ordered lookup/error policy; PACK owns construction loops; UNPACK delegates cardinality and error policy to Python assignment; NEXT owns exhaustion handling; and all numeric, comparison and object protocols execute through Python. Moving those decisions is substantive work. A new dispatch label or a HIA call that simply returns the old Python operation is insufficient.

## Per-primitive migration boundaries

### 1. GLOBAL

HIA can own lookup order and miss/error selection; map containment/getitem, exact attribute effect and exception construction remain explicit leaves.

Required semantics: No eager name cache; preserve live namespace mutation and distinguish AttributeError from errors raised by mapping operations.

### 2. ATTR

A complete object lookup owner needs MRO, data/non-data descriptors, instance storage and __getattr__ fallback; isolated exact-object layouts may come first.

Required semantics: Descriptors and metaclass hooks, bound method identity, exception timing and mutation prevent treating this as a scalar read.

### 3. SET_ATTR

Object-runtime owner can choose descriptor versus instance storage and mutation order; actual foreign descriptor calls stay explicit.

Required semantics: __setattr__, descriptors, deletion/replacement finalizers and read-only errors.

### 4. ITEM

HIA container/text owners must handle index conversion, bounds, slices, dictionary lookup and result identity.

Required semantics: Exact container type does not remove key/index/equality hooks; dict and sequence subclass dispatch differ.

### 5. SET_ITEM

HIA container owner chooses indexed mutation/resize/hash collision and replacement sequence.

Required semantics: __setitem__, __index__, hash/equality, mutation during lookup and overwritten-object release.

### 6. CALL

Keep a documented foreign call transport; migrate named callees only through separately admitted complete owners.

Required semantics: Binding error order, **mapping protocol, descriptors, arbitrary callable effects and reentrancy cannot be replaced by a generic native label.

### 7. PACK

HIA can own construction loops and pair/insertion decisions; a collection allocator/ownership layer is required for full replacement.

Required semantics: Set/dict hashing and equality, duplicate keys, insertion order, allocation failure and partial cleanup.

### 8. ITER

A full iterator-acquisition owner needs type-slot/legacy sequence dispatch; raw foreign iterator acquisition can remain a named observation for other owners.

Required semantics: __iter__ call/result validation, sequence fallback and exact error semantics.

### 9. NEXT

HIA can own exhaustion/error continuation once a primitive yields value/exhaustion/error without changing handled exception state.

Required semantics: StopIteration subclasses, PEP479 generator behavior, arbitrary next callbacks and lifetime of exception/value objects.

### 10. TRUTH

HIA truth owner needs live exact-type observations, length/number facts, and explicit foreign truth/length effects.

Required semantics: No assumption that mutable handle slots1/2/3 retain None/False/True; __bool__/__len__ ordering and invalid returns must be preserved.

### 11. BINARY

A signed arbitrary-precision numeric owner can implement integer operations; a broader operation owner also needs sequence/text and reflected/in-place dispatch.

Required semantics: Overflow/zero/shift errors, bool/int distinction, NotImplemented/subtype priority, float/complex behavior, object identity and foreign operators.

### 12. UNARY

A signed scalar runtime can own complete unary operation decisions, with explicit foreign slot invocation.

Required semantics: Arbitrary precision, bool conversion, numeric subclasses, NotImplemented/error text and float signed-zero/NaN.

### 13. COMPARE

HIA scalar/container comparison owners need type-specific result construction and explicit foreign comparisons/membership.

Required semantics: __ne__ is independent of not __eq__; rich comparison may return an opaque object; membership returns bool and can iterate/hash/compare.

### 14. UNPACK

Recommended next complete bounded control owner: acquisition, n+1 fetches, cardinality decisions, diagnostic choice, ordered cleanup and result publication in HIA.

Required semantics: Requires raw slot/type facts, faithful pending-error and temporary-reference handling, and explicit3.12/3.14 diagnostic profiles.

### 15. SLICE

HIA can own a slice value representation after handle/value storage exists; exporting a real Python slice still requires allocation.

Required semantics: Do not invoke __index__ or normalize at construction, since the current slice constructor stores arbitrary component objects.

### 16. APPEND

HIA-owned list storage/mutation can eventually replace it; otherwise retain the exact base-list append observation.

Required semantics: Accepts list subclasses, bypasses their append override; allocation and old storage lifetime remain observable.

### 17. IMPORT

Keep module import as an explicit external effect; HIA selects the import and its original point.

Required semantics: Import hooks, sys.modules identity, circular import state and side effects are Python runtime semantics.

### 18. RAISE

HIA can decide rejection/error construction; the Python boundary still needs faithful final exception raising.

Required semantics: Exception class instantiation, active handled context, cause/context cycles and traceback behavior cannot be replaced by returning a code.

### 19. GENERATOR

Retain suspension/throw/close transport as an explicit runtime seam until a generator/object runtime exists.

Required semantics: Lazy outer iterator evaluation, send/throw/close, GeneratorExit, PEP479 and generator-frame lifetime.


## Recommended first complete owner: fixed UNPACK

The runtime accepts fixed arities one through four. The frozen policy uses twenty sites: fifteen two-target assignments, four three-target assignments and one four-target assignment. A complete owner should cover the existing runtime arity-one shape too; its absence from these twenty sites is not a reason to silently remove it.

A separately admitted HIA value-control image can sit behind the existing outer opcode 14 observation. The outer Core session would still expose one consume-before-effect observation and either publish its complete result or terminate. Inside that observation, HIA—not a Python assignment or a host loop—would select acquisition, each next operation, the one excess probe, the count branch, error text and cleanup order. This preserves the existing outer protocol instead of exposing half-completed unpack observations to callers.

This is a proposed integration shape, not a frozen ABI. It may allow the current 39 Core source images to remain byte-identical, while adding a new value owner image. That fact must be established from actual generation. The bridge, bundle, identity dependencies, installed resources and composed evidence would still change and require new validation; old 116 results cannot certify the new composition.

### Necessary sequence

1. HIA admits the supplied arity and selects iterator acquisition at the original point. The bridge reports the raw success/error and relevant type/slot facts without evaluating user attribute or length hooks early.
2. HIA asks for at most n values, one at a time, keeping an ordered temporary-reference ledger. Exhaustion before n selects the short-input error. Other errors are retained for correct cleanup and propagation.
3. After n values, HIA requests exactly one additional next operation. Exhaustion completes the assignment; another value selects the long-input diagnostic. The excess value is released at the original relative point.
4. HIA chooses any exact-type length fact needed by the interpreter profile and constructs the diagnostic text. Host code may allocate the selected exception object but must not decide which diagnostic applies.
5. HIA chooses the release order for acquired values and the iterator. The bridge performs those reference operations with the required pending-error state, then publishes a complete result or propagates the original error once.

### Four prerequisites must be resolved before implementation is called equivalent

**Type and slot facts.** Generic iterability errors use the underlying iteration slot, sequence predicate and type name. Looking up Python-level attributes such as __iter__ or __name__ can itself invoke hooks and does not prove equivalent facts. Any C API/ABI observation must be explicitly bound to the supported interpreter and exercised on that ABI.

**Pending error state.** Catching an error in one Python callback and releasing temporaries in a later continuation can alter sys.exception(), exception context, and finalizers. A transport returning only a handle and an error code is insufficient. The pending-error capsule and cleanup state need a concrete design and actual controls.

**Reference lifetime.** The current session registry keeps registered values alive. Interim unpack values and iterator state cannot simply be registered there and kept until the enclosing method returns. Doing so can move user finalizers across subsequent callbacks. The new temporary ledger needs transfer/release ownership, including aliases and partial failure.

**Interpreter behavior.** The original assignment may use generic or specialized interpreter paths. Public observable results, exception arguments, relevant callbacks and cleanup must be checked against the retained original on the actual interpreter profiles; a source excerpt alone does not prove the complete operation.

## A concrete CPython version difference

The complete official sources are pinned in PRIMARY-SOURCES.json:

- [CPython v3.12.14 Python/ceval.c](https://github.com/python/cpython/blob/v3.12.14/Python/ceval.c), Git blob 3985b52649cc827ccb4b919b1ed7cf7d06f6a32f.
- [CPython v3.14.4 Python/ceval.c](https://github.com/python/cpython/blob/v3.14.4/Python/ceval.c), Git blob 377b4644eddd2a848ddad1e99ee22e1525b93f67.

Both generic unpack routines obtain an iterator, fetch the target count, make one excess probe, and have an ordered error cleanup. They also rewrite a particular non-iterable TypeError using underlying type/slot facts.

The 3.14.4 routine, after releasing an excess value, checks exact list/tuple/dict size. If the size exceeds the target count, its too-many-values error includes the actual count. The 3.12.14 routine uses the older expected-count-only diagnostic. The implementation therefore cannot select one text globally and claim both profiles. This is an actual source difference; no new native or oracle differential was executed for this audit.

The C error cleanup releases acquired values in the reverse acquisition order represented by its downward-growing stack, then releases the iterator. This is a starting specification to validate, not permission to ignore the specialized bytecode and outer-frame lifetime behavior.

## Remaining work after UNPACK

A reusable **signed integer and text value runtime** would serve UNARY, part of BINARY, TRUTH, comparisons, indexes and formatting. It must implement arbitrary precision and exact result semantics; the current HIA u64 arithmetic is not a substitute. In-place/reflected methods, bool/int distinctions and opaque comparison results remain explicit foreign dispatch unless separately implemented.

A **collection/object runtime** is needed for PACK, ITEM, SET_ITEM, APPEND, attributes and some comparisons. Exact builtin containers can contain foreign keys, values or index objects, so an exact outer type does not eliminate callbacks. Ordered hash/equality, mutations during lookup, insertion order and reference release all belong in the design.

GLOBAL is a smaller independent policy candidate: HIA could own the current helper→namespace→builtins order and miss handling. It should be pursued as its complete ordered operation, not as a cache that freezes mutable module state.

CALL, IMPORT, final RAISE, and real GENERATOR suspension are explicit foreign runtime boundaries for the present design. Dynamic calls can enter existing separately admitted native Code/ELF owners, but an arbitrary callable remains arbitrary. The host primitive list must continue to describe that fact.

## Required validation for the next candidate

Retain the original fifteen component methods and original 51 and 50 caller methods, all within their current complete default 180+3 gate. Do not remove, rename, split or broaden their success interpretation. Keep each native compile's 20-second wall / 10-second CPU / 1MiB bounds and every existing Core cap.

Add a distinct finite matrix covering arities1–4; empty/short/exact/long input; exact list/tuple/dict; subclasses and custom iterators; sequence fallback; errors at acquisition and each next/excess point; StopIteration subclasses; mutation; aliases; reentrancy; ambient and pending exception context; and temporary/finalizer release. Poison the retained assignment-unpack path so the new operation cannot silently fall back. Require actual new-image step evidence and the installed isolated child with -I -S -B and emptyPATH.

The singleton TRUTH proposal previously marked BLOCKED stays blocked: the runtime object tables and low-level observation boundaries are mutable/observable. No optimization based on handle1/2/3 is admitted here. Performance must be measured on a source-bound candidate; static site counts do not justify changing a budget.

## Evidence custody

The first local IR scan was observed before an executor reset but its unsealed raw JSON became inaccessible. It is not presented as durable recovered bytes. The new inventory is a separate real read-only scan of the same five fully verified source inputs, with its own full raw JSON, script and process receipt.

A local primary-source writeback had added one trailing LF to each C source. The mismatch was observed, and the complete expected hashes of the one-byte-shorter copies were checked before correcting them. The canonical reference bytes in this audit are the original Git-fetched raw strings, not those unverified local copies. This transport event is unrelated to product semantics.

The completed842 native evidence and original ZIP were already Git-published before either reset and remain independent. This audit does not rerun or relabel the earlier failed/unknown operations.
