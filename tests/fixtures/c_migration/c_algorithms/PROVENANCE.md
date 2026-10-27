# Complete upstream integer-key modules

These are the complete `compare-int` and `hash-int` modules from
[fragglet/c-algorithms](https://github.com/fragglet/c-algorithms) at commit
`23d453792ed89a28ed7d2c8d4311a4d9f7822edd`. Both `.c` files and their complete
`.h` files are retained without code changes or removed declarations. The
upstream README explicitly defines each source/header pair as an independently
copyable module. This fixture does not represent the whole library.

`UPSTREAM.json` records immutable source URLs and Git blob identities.
`tools/qualify_c_algorithms.py` verifies all six upstream files against a fixed
blob inventory before compiling or migrating them. The original ISC notices
remain in each source/header; the full upstream `COPYING.md` and README are
also retained. Only the README filename changed to `UPSTREAM_README.md`.

`contracts.json` is our separate caller annotation, not an upstream source edit
or inferred proof. Each `void *` must point to one initialized, aligned, live
C `int` in the captured 32-bit-int model for the duration of the call. Multiple
read pointers may alias. Concurrent foreign mutation is excluded. The translated
C ABI remains explicitly unsafe; its null/alignment checks do not prove object
type, provenance, allocation size or lifetime.

The complete module denominator is six active project declarations: three
function prototypes and three definitions. Native differential execution uses
the entire unmodified module pair as the original GCC oracle.
