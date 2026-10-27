# C++ resource composition implementation migration

`hepta.cpp_composed_migrate` extends the actual implementation-migration path
to a bounded class containing **two through four independently owned byte
buffers**. It translates the composite constructor, move constructor,
default nontrivial destructor, scalar methods and complete lifecycle function
into Hepta. The resulting implementation links no original C++ object and
contains no foreign call or unsafe block. This is separate from the C++
handle/scoped bridge, whose foreign implementation remains C++.

The profile is `cpp20-composed-exclusive-byte-owners-semantic-v1`. It has two
different recognition rules:

* The leaf byte owner retains the existing completely checked allocation,
  move, borrow and destruction protocol. Its complete native AST is compared
  with compiler-owned rules. Only coordinates, opaque identities and usage
  metadata are normalized; operations, literal values, declaration bindings,
  conversions and cleanup bodies remain checked.
* The **composite is lowered from its actual Clang AST**. Field identities,
  initializer expressions, parameter routing, scalar expressions, method
  calls, local declarations, conditions, returns and constructor throws drive
  the generated code. No complete composite AST is compared to an embedded
  composite example, and no fixture name selects a prewritten algorithm.

The earlier `cpp_owned_migrate` closed 321-node protocol remains unchanged.
The new path does not infer an arbitrary resource protocol from C++ code.
Arbitrary C++ project migration, general resource classes, full language
memory safety and source-to-target refinement are not proved by this work.

## Source boundary and declaration accounting

The input must contain one complete selected leaf class, one complete
composite class, and one complete lifecycle function. Includes, preprocessing,
other top-level declarations and unknown statements reject the entire
translation before publication. Every active class/member/parameter/local
declaration is assigned a disposition. Compiler-generated declarations are
checked against the native leaf rule compilation separately; they cannot hide
an additional source implementation.

The admitted composite has 2–4 leaf-owner fields, one fallible constructor,
one explicit nonthrowing memberwise move, deleted copy/assignment operations,
and an explicitly defaulted nonthrowing destructor. There are at most 16
ordinary methods and at most 12 scalar parameters per callable. The scalar
representations are `bool`, `u8`, `u32`, `i32`, `usize` and `u64`, under the
checked native LP64 model. Clang 20 or newer is required; the observations
below were obtained with the repository's Clang 20 toolchain.

The supported method/lifecycle statements are initialized scalar locals,
sequenced Unit-returning mutating member calls, explicit compound `if`/`else`
branches, and scalar returns. A lifecycle has an outer `try` with an integer
handler and catch-all handler whose bodies return checked scalar expressions.
Owner construction and moves occur on its linear statement spine. Scalar
methods with return values must be const. Member calls bind to inventoried
Clang declaration identities, not only to names.

Integer arithmetic uses the actual promoted Clang types. Unsigned addition,
subtraction and multiplication lower to the existing wrapping builtins.
Supported integral conversions become explicit target casts. Logical
expressions retain short-circuit evaluation. Arguments of an effectful call
must themselves be side-effect-free expressions; mutations are separate
statements. Signed overflow and source out-of-bounds access remain outside
the defined-source-input equivalence domain. Hepta checks remain present.

Generated identifiers are independent of source parameter/local/member
spellings. A parameter named `receiver`, `created0` or `caughtcode` cannot
capture an inserted cleanup or receiver variable. The implementation checks
original declaration identities before assigning its own names.

## Initialization, failure and destruction

Clang supplies initializers in the actual C++ field initialization order.
The lowerer checks every target field by identity and emits nested fallible
`HeptaLeaf_new` calls in that order. Reordering the written initializer list
does not change C++ field order or the generated program.

If a field allocation fails, the target drops all **previously completed**
fields in reverse order and returns an explicit error. If the selected leaf
constructor rejects after allocating, that leaf releases its own storage
before propagating its error; the containing constructor then releases the
previous fields. A supported composite constructor-body `throw` uses a
literal integer error code in `[3, 255]` and drops all initialized fields in
reverse order. Codes 1 and 2 remain reserved for allocation failure and the
leaf's post-allocation rejection.

The generated composite destructor consumes each leaf field in reverse
order. This is explicit field destruction, rather than relying on a target
language's default aggregate drop order. Move construction consumes the
whole target owner. The checked C++ move must transfer each corresponding
field and perform no extra operation; swapped fields or custom move effects
reject. Reading the original object after a move also rejects. C++'s observable
moved-from empty state is not silently made equivalent to a usable consumed
Hepta owner.

Every accepted scalar return first computes its value, then consumes live
owners in reverse construction order. This includes early returns before a
move, early returns after a move, range-error returns and normal results.
A borrowed leaf data pointer may only appear as an immediate indexed read;
the target uses a receiver-tied read slice. Stored pointers, escaping views,
retained references, pointer arithmetic and externally supplied ownership
contracts are not part of this profile.

## Three independently executed source programs

The fixtures are authored conformance programs, not third-party production
libraries. Each includes its real leaf implementation and has a different
composite definition and actual algorithm:

| Source | Owned fields | Actual distinction | Active declarations | Complete Clang AST nodes |
| --- | ---: | --- | ---: | ---: |
| [pair.cpp](../examples/cpp/composed_migration/pair.cpp) | 2 | Left/right extents; weighted byte read, extent sum; early-after-move precedes range check | 61 | 463 |
| [triple.cpp](../examples/cpp/composed_migration/triple.cpp) | 3 | Right/left/right-plus-one extents; different fill/update constants and weighted read; range check precedes early-after-move | 63 | 500 |
| [quad.cpp](../examples/cpp/composed_migration/quad.cpp) | 4 | Fourth left-plus-two resource, fourth allocator failure point, additional byte contribution and different coefficient | 64 | 537 |

The corresponding `.hepta` files beside the sources are checked output
fixtures. The migration compiler does not read them to decide acceptance or
generate code. Qualification freshly translates each C++ source and requires
its result to equal the recorded output. Additional frontend regressions
change coefficients, initializer arithmetic, conditions, scalar locals,
handler expressions and constructor error codes. These changes produce new
Hepta bodies instead of merely alpha-renaming a fixed template.

## Native qualification and independent resource-event oracle

`tools.validate_cpp_composed` builds the original C++, Hepta/Rust and Hepta/C
implementations separately. Every implementation runs the same vectors and
checks each scalar result against a separately authored integer oracle.
There is no C++ implementation object in either Hepta build. The C program
appends an observation harness to emitted C, and the Rust program appends
its independent allocator harness to emitted Rust.

Allocation refusal occurs in the **actual allocator**: C++ `operator new[]`,
the Rust global allocator and wrapped C `calloc`/`malloc`. The refusal index
is not passed to `composed_case`; it is a separate harness state selecting
the Nth actual allocation attempt. Zero-length fields do not allocate, so
the failure index counts attempts, not simply the declared field number.

The oracle includes allocation identity, requested size and release order.
The harness assigns each successful allocation an ordinal, associates it
with its actual pointer and size, and validates releases against those
identities. Unknown/double releases abort. A per-call event digest covers
allocations, actual refusals and deallocations; the overall observation digest
also includes every result and count. All observed calls end with zero live
buffer allocations. These counts cover buffer storage, not C++ exception
runtime, startup, reporting or arbitrary foreign allocator activity.

| Program | Cases per implementation | Successful allocations = releases | Actual refusals | Observation digest |
| --- | ---: | ---: | ---: | --- |
| Pair | 437 | 401 | 196 | `79fca1db8d2f0865` |
| Triple | 613 | 796 | 307 | `857e18f53bf7b178` |
| Quad | 833 | 1,409 | 423 | `6d4d805955152153` |

There are **1,883 calls per implementation**, or **5,649 positive differential
calls across the three implementation routes**. Each route observes 2,606
successful allocations and releases, 926 allocator refusals, and zero live
buffers after every call. The pair/triple/quad programs respectively observe
76/110/122 refusals at allocation attempt 2; triple/quad observe 65/90 at
attempt 3; quad observes 64 at attempt 4. All three cover leaf-constructor
rejection, composite-constructor rejection, moves and early returns.

Two real compiled C mutations run for **each** fixture:

* Removing the actual buffer `free` call returns the expected scalar but exits
  3 with live storage: pair 2, triple 3, quad 4 allocations remain.
* Reversing resource selection in the actual composite destructor releases
  every allocation and leaves live count zero, but exits 3 because the
  destruction event order differs. This control prevents a no-leak check from
  being mistaken for correct resource lifecycle semantics.

The original reference uses Clang 20 compilation with UBSan and the selected
G++/libubsan link driver; Hepta/C uses GCC with UBSan; Hepta/Rust uses pinned
Rust 1.90. Tool identities, flags, object/executable hashes, commands, exit
codes and exact stdout/stderr bytes are retained. This gate performs no
performance timing and establishes no general speed or memory advantage.

## Current-source replay and failure evidence

`validate_report` has no weak archival bypass. With a caller-selected local
Clang, it recompiles the **current original source AST**, repeats translation,
and compares the complete migration ledger and generated source. It also
re-runs the canonical Hepta frontend with `native=False` for the retained
consumer and migrated module, compares complete resource graphs, typed
semantics, effects/interfaces and exact emitted Rust/C. A different legal
resource graph remains invalid evidence for this source even after all its
hashes and self-seals are recomputed.

The native receipt binds the current case denominator and oracle, input
closure/compiler hash, retained source and binaries, build paths, allocator
observation flags, executed artifact, and actual negative mutations. Checks
require an integer exit code, so Boolean `false` cannot stand in for exit 0.
Validation checks evidence consistency; it neither authenticates arbitrary
third-party JSON nor re-executes the native observations.

The producer installs backend/reference rows before work begins and records
each stage incrementally. A compiler exception or timeout preserves completed
translation, frontend, resource graph, source text and command output.
Timeout prefixes retain their exact bytes, including invalid UTF-8. The
test suite exercises these partial paths with explicitly mocked failures.

Independent review reproduced a publication race after the first complete
native qualification: an actual source edit in the hard-link publication hook
could leave an output while the migrator returned the old source identity.
Publication now uses the shared exact-byte/inode publisher, rechecks source
and compiler identities after publication, and independently verifies the final
published file. It withdraws only its own staged inode on failure. Regression
tests perform real source/staging writes and preserve a separate competing
writer's replacement. This is point-in-time local consistency; it does not
claim immunity to arbitrary later writes by another process with the same
filesystem permissions.

## Reproduce and integrate another backend

### Independent LLVM execution

`tools.qualify_cpp_composed_llvm` freshly migrates each original C++ file,
checks the actual generated project through the pinned Rust reference gate
and independent resource CFG, and emits a native object directly from LLVM.
It links that object with the C observation harness only. The object's actual
symbol table must export exactly `composed_case`; unresolved dependencies are
restricted to the finite allocator, memory-initialization and abort runtime.
No original C++ object or Hepta Rust/C implementation is a link input.

The separately compiled C caller declares the exact six-argument prototype
and `uint64_t` result. The linker-driver invocation rejects implicit function
declarations, implicit integer types and non-prototype declarations. A
subsequent raw-log audit found that older LLVM observations compiled the C
branch without this declaration: GCC warned and assumed an `int` result.
The original resource vectors have small scalar outputs and did not reveal
that caller defect. Those historical records remain intact; they do not
qualify the corrected caller or an unrestricted 64-bit return boundary.

`tests/test_cpp_composed_harness.py` compiles a separate C callee and executes
the actual observation harness with two independent high-bit return/argument
vectors. It also removes the C declaration from a temporary harness and
requires the actual qualification flags to reject compilation. This is a
caller ABI regression, not a new migrated resource program or a performance
sample. The 437/613/833 resource cases and every performance protocol remain
unchanged; corrected native qualification must run on its own frozen source.

The LLVM gate executes the same 437/613/833 cases as the three-route gate:
**1,883 calls, 2,606 allocations and releases, and 926 actual refusals**. The
per-variant result and resource-event digests match the table above. This is
the fourth implementation route; the LLVM gate itself does not re-execute
the three other routes or claim a timing result.

For each fixture it additionally compiles two deliberately wrong LLVM
programs directly with Clang: one removes the real buffer deallocation,
and one reverses the field selections in the actual composite destructor.
These six programs are explicitly marked as **unqualified negative-control
machine code**, never as output accepted by the source-bound compiler. The
first case observes respectively 2/3/4 unreleased buffers or zero live
buffers with incorrect order. All six return the harness's lifecycle failure
code 3. An independent oracle computes the exact expected negative event
trace, so arbitrary self-resealed failure output is insufficient.

The report validator freshly translates the complete original C++ AST,
replays the current Hepta frontend and resource graph, regenerates the exact
LLVM text, and checks retained sources, objects, executable bytes, symbol
inventories, commands, case denominators and positive/negative outputs.
It recompiles the finite layout assertions with the **caller-selected**
Clang executable; a report cannot choose a program to execute during replay.
Validation does not re-execute the retained target observations or authenticate
an arbitrary externally supplied report. The complete release gate must run
the producer against the frozen candidate source.

```
python -m tools.qualify_cpp_composed_llvm \
  --workdir artifacts/cpp-composed-llvm \
  --output artifacts/cpp-composed-llvm.json \
  --clang /usr/lib/llvm-20/bin/clang \
  --clangxx /usr/lib/llvm-20/bin/clang++ \
  --rustc /path/to/rust-1.90.0/bin/rustc
```

Both output locations must be new. Every completed native observation is
recorded before its success/failure is checked, including partial command
bytes on timeout. `tests/test_cpp_composed_llvm.py` exercises actual native
execution, both control families, 19 report mutations, source/IR and binary
tampering, exact negative-output resealing, failed link preservation and
report-controlled executable rejection.

### Migration and three-route commands

```sh
python -m hepta.cpp_composed_migrate \
  examples/cpp/composed_migration/triple.cpp \
  --output /tmp/triple-migrated.hepta --clangxx /usr/lib/llvm-20/bin/clang++

python -m tools.validate_cpp_composed \
  --workdir /tmp/composed-qualification \
  --out /tmp/composed-qualification.json \
  --clangxx /usr/lib/llvm-20/bin/clang++ --rustc /path/to/pinned/rustc --cc gcc

python -m unittest tests.test_cpp_composed_migrate -v
```

Use a new output path/work directory. Existing files and symlinks are
preserved; source/compiler changes during translation reject publication.
The regression suite includes 38 source refusal cases, 16 inconsistent
receipt mutations, internally valid but unrelated graphs, name-capture
controls and the complete three-program native qualification.

An independent native backend can consume the **fresh actual migration**
and `consumer.hepta`, whose public scalar function is
`composed_case(usize, usize, u8, usize, u32, u32) -> u64`. The qualifier exposes
`VARIANTS`, `cases(name)`, `observation_oracle(vectors)` and
`case_sources(vectors)`. The latter returns the exact C case header and Rust
vector declaration. `harness.c` can link with an independent object using the
same malloc/calloc/free wrappers. That fourth backend requires its own actual
source-bound execution; this document's three-route pass does not imply one.

## Remaining boundary

The leaf remains a closed protocol, while the composite is a real but bounded
semantic translator. General custom destructors, arbitrary allocators,
inherited/virtual classes, recursive owning types, arbitrary C++ templates,
retained/escaping pointers, cross-thread lifetimes, callbacks, class layout
ABI, whole projects and automatic inference of undocumented ownership are
still unsupported. The default destructor rules do not cover termination,
foreign undefined behavior, `longjmp`, nontermination or arbitrary external
replacements of allocation/deallocation behavior. No blanket claim of C++
source equivalence, Rust-level language soundness or low total migration cost
is made by this finite native qualification.
