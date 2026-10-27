# Actual C++ ownership across lexical scopes

`hepta.cpp_composed_migrate` now translates composite-owner construction and
move in explicit C++ compound statements and `if` branches. The previous
implementation admitted owner creation only on the top-level linear lifecycle
spine. This is implementation migration: the generated programs contain Hepta
ownership operations and do not link the original C++ object.

The extension retains the existing complete leaf protocol, two-to-four owned
fields, explicit fallible construction, deleted copy/assignment, default
destruction and scalar/noexcept method boundaries. It does not add arbitrary
classes, custom destructors, loops containing owners, stored references,
exception handlers inside the lifecycle, or general C++ ABI preservation.

## Lifetime rules

Each translated source scope remembers the declarations visible on entry.
Normal scope exit consumes only the live owners introduced in that scope, in
reverse declaration order. A moved-from owner is already consumed and is never
dropped twice. Earlier owners remain usable after inner scopes finish.

A return evaluates its scalar result before consuming every live owner from
inner to outer scope. A failed construction first releases its partially
initialized member resources, then releases already completed enclosing owners
before the original lifecycle handler is selected. Both outcomes of allocation
are handled inside the same source lifetime; a generated `Result::Ok` match arm
does not invent a new C++ scope.

At an `if` join, all paths that continue must agree about whether each enclosing
owner remains live. Both branches may move and destroy that owner. Moving it
on just one continuing branch rejects. Terminating branches do not contaminate
the continuation state. Locals from a nested block never become available to
the enclosing source environment. Lexical nesting above sixteen scopes rejects
before publication; the ordinary frontend and resource budgets still apply.

Generated names are unique. Explicit source blocks can therefore be flattened
after emitting their cleanup, without making a source-local declaration
addressable outside its original scope. Branches keep their actual conditions.
The ordinary Hepta frontend and independent resource verifier inspect the
result, including the whole generated control-flow graph.

## Native qualification

`examples/cpp/scoped_ownership_migration/scoped.cpp` is a complete, separately
labeled authored fixture. It includes an outer owner, a conditional owner, an
explicit block with a moved owner, and a further nested owner. Successful normal
execution of the first case has eight separate storage allocations whose exact
allocation identities, sizes and release order are observed. Other cases cover
zero lengths, index boundaries, early returns at all depths, partial constructor
rejection, and refusal at each of eight possible allocation attempts.

```sh
python tools/qualify_cpp_scoped_ownership.py \
  --workdir /tmp/new-scoped-ownership-qualification \
  --clangxx /usr/bin/clang++-20 --clang /usr/bin/clang-20 \
  --rustc /absolute/path/to/pinned/rustc --cc gcc

CLANGXX=/usr/bin/clang++-20 CLANG=/usr/bin/clang-20 \
RUSTC=/absolute/path/to/pinned/rustc \
python -m unittest tests.test_cpp_scoped_ownership_migration -v
```

The qualifier builds four independent execution routes:

1. Original C++, compiled with Clang and linked with its observation harness.
2. Migrated Hepta generated as Rust, with a separately instrumented allocator.
3. Migrated Hepta generated as C, with allocator wrapping and UBSan.
4. Migrated Hepta emitted directly as LLVM machine code, linked only to the C
   observation harness and permitted allocator/memory primitives.

Every route compares against an independent Python integer/resource model.
The first executed development run retained 1,121 cases per route, including
3,180 successful allocations, 3,180 frees and 398 actual allocation refusals
per route, with zero live storage at every completed call. These are finite
observations, not a theorem. The source contains 64 inventoried declarations;
none is skipped. The output contains no foreign C++ calls.

Two deliberately incorrect C implementations are compiled and executed outside
the accepted compiler path. Removing release leaves eight measured allocations
live on the first case. Reversing the composite field destruction order frees
all eight allocations but disagrees with the independent ordered event trace.
Unknown failures do not count as successful detection.

The report retains the original and generated source identities, full tool
commands, generated code, resource graphs, native stdout/stderr, case inventory
and observed failures. Direct LLVM object inspection permits only the selected
C export and known allocator/memory/abort imports. The original C++ object is
used exclusively in the reference executable. A changing compiler identity
causes final qualification to fail.

## Scope of the result

This is an additional actual C++ resource-control-flow translation profile,
not a C++ library bridge. It does not lower pointer-bearing C record views into
standalone HIA, prove arbitrary C++ equivalence, infer arbitrary ownership,
certify every backend, or establish Rust performance parity. Allocation
observations use the same explicit refusal policy across implementations;
unrestricted custom allocators and new-handler behavior remain outside scope.
Performance is reported as `not_measured`. Complete project/configuration
capture, broad third-party migration cost and whole-compiler refinement remain
separate obligations.
