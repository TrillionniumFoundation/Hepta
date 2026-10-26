# Captured C source to standalone HIA

`paired_bytes.c` and `paired_bytes.h` are an authored conformance module, not a
third-party production-library migration.  The complete module has two public
function declarations and their two definitions.  Its second allocation can
fail after the first succeeds; every normal/error/early-return path must release
the resources actually acquired.

`hepta.hia_program_source.lower_c_multi_owner` uses the existing Clang build
capture and complete declaration collector.  It recognizes each guarded
`calloc(count, 1)` structurally and translates the captured loops, calls,
arithmetic, mutations and cleanup.  It does not compare the complete source AST
with a canned fixture or substitute a handwritten target implementation.

The generated Hepta migration product is lowered to standalone typed CFG/SSA.
HIA verification, interpretation and LLVM generation do not load that source.
The target links its generated native object and the allocation observation
harness; the original C implementation is compiled only as a separate oracle.

The bounded allocation contract assumes standard byte-array allocation under a
shared explicit fault policy, unchanged `size_t` count parameters, explicit
zero-count exits, and positive counts at most `isize::MAX`.  Pointer escape,
reallocation, custom allocators and arbitrary C/C++ classes remain outside this
profile.  Unsupported source rejects the bundle; successful finite execution
does not establish semantic equivalence for all C programs.

Run the retained migration qualification with a new output directory:

```sh
python tools/qualify_hia_migration.py --workdir /tmp/hia-migration-run \
  --clang /usr/lib/llvm-20/bin/clang --clangxx /usr/lib/llvm-20/bin/clang++
```

The current case inventory contains 56 C multi-owner cases and 20 existing
C++ `ScalarState` migration cases. Each executes both the separate original
implementation and the HIA native target, for 152 native result observations;
16 observations include a real intercepted allocator refusal. The standalone
HIA interpreter is a third consumer. Reports retain commands, raw process
output, declaration inventory, hashes, link inputs and observed allocation/free
counts. These are finite correctness and cleanup observations, not performance
or engineering-cost measurements.

## Concrete generic instances

`generic_owners.hepta` exercises a real generic `Packet<T>` record and
`forward`, `dispose`, `finish<T, E>` and borrowed-return `view` helpers. The
source adapter creates concrete AST function/record instances, checks those
instances, then emits the same standalone HIA operations. It does not emit and
reparse generated Hepta or Rust. Borrowed projection helpers are inlined as
explicit checked borrow operations; a scalar projection ends its temporary
loan. Runtime code does not need templates or source text.

Specialization has a 128-instance function/record budget and a 32-level type
depth limit. Same-type recursive calls share one instance; polymorphic growth
recursion rejects. Uninstantiated templates are identified as such in
`source_report`; no claim is made about all possible future substitutions.
