# C migration qualification receipt

`qualification.json` is a real execution receipt for implementation commit
`27e7f7e1d528fdd1d6a2ffb7b94bc5dfced05c28`, using the compiler paths recorded
inside the receipt. It is not a formal equivalence or performance result.

The captured project contains three translation units and four project input
files (2,300 bytes): the frozen existing `native` example and two separately
labeled authored conformance fixtures. Its complete active project declaration
inventory has 11 entries: seven converted function definitions, two resolved
prototypes, one converted record and one resolved typedef. The receipt also
enumerates 372 system/compiler declarations. Inactive preprocessor branches and
unlisted build configurations are outside this denominator.

Actual GCC-versus-Hepta/Rust native execution passed 1,046 comparisons. Ten
additional allocator refusal/recovery calls matched original return values and
left both implementations with zero live allocations after each call. A
deliberately wrong result was detected. The generated core has 110 lines and
the separately unsafe C ABI bridge has 49 lines; three slice annotations were
provided. Captured migration elapsed time was approximately 1.43 seconds on
this machine. Human review hours, token cost and performance parity were not
measured.

`c-migration-generated/` contains the reviewed Hepta core and ABI bridge from
that run. Native libraries were temporary and are not retained. Exact build
argv in the receipt contains temporary paths that no longer exist; replay
recreates the input files and database from the retained fixtures:

```sh
python tools/qualify_c_migration.py --clang /path/to/clang \
  --rustc /path/to/rustc --output /tmp/hepta-c-qualification.json
```

See `docs/C_MIGRATION.md` for accepted/rejected source patterns, the explicit
foreign-pointer requirements, allocator model and limitations of these results.
