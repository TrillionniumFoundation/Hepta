# Complete upstream C module qualification

`qualification.json` records a real native execution at implementation commit
`27e7f7e1d528fdd1d6a2ffb7b94bc5dfced05c28`. The original modules are the complete
`compare-int.c`/`.h` and `hash-int.c`/`.h` from fragglet/c-algorithms commit
`23d453792ed89a28ed7d2c8d4311a4d9f7822edd`, retained without code changes.
All source and license bytes are checked against their recorded Git blob IDs.
The upstream project defines these source/header pairs as standalone modules;
this is not a qualification of the full C Algorithms library.

The complete active project denominator has six declarations: three resolved
prototypes and three converted definitions. Ten system/compiler declarations
are separately recorded. Two translation units and four source/header files
contain 5,621 bytes. Five caller annotations assign a one-element C `int`
interpretation to the `void *` parameters. Validity, initialization, dynamic
object type and lifetime remain unsafe caller obligations; read aliases are
allowed. No pointer contract inference or unrestricted equivalence is claimed.

Actual GCC-original versus Hepta/Rust-translated execution passed 25,302 native
return comparisons: 8,434 each for comparison, equality and hashing. These use
121 boundary-value pairs and 4,096 seeded random pairs. The count includes
8,434 same-address read-alias comparisons. Independent arithmetic expectations
and unchanged input storage are also checked. A wrong-result control was
detected. Two child-process calls using null/misaligned pointers were rejected
by the translated bridge before slice construction; the original C was not
called on those invalid inputs.

Generated output has 32 Hepta lines and 42 ABI-bridge lines. Captured migration
took approximately 0.97 seconds on this machine. Human effort, token cost and
performance parity were not measured. Generated sources and original ISC terms
are retained in `c-algorithms-generated/`. Temporary libraries and build paths
in the receipt are not retained.

Replay the entire frozen module qualification with:

```sh
python tools/qualify_c_algorithms.py --clang /path/to/clang \
  --rustc /path/to/rustc --output /tmp/hepta-c-algorithms.json
```

The original buffer, struct and allocation corpus was also replayed at the same
implementation commit; see `evidence/c_migration/qualification.json` for its
1,046 native comparisons and ten allocator refusal/recovery checks.
