# hepta_ordering 0.1.0 (experimental)

Source-only iterative range heapsort and lower/upper-bound search for borrowed
`i32` and `u64` slices. No allocation, unsafe operations, foreign calls or
recursive calls. A valid search requires sorted input; the returned `ok`
field reports only range validity.

See [API, preconditions and validation](../../docs/STDLIB_ORDERING.md) and the
[locked example](../../examples/ordering/src/main.hepta). This repository-local
package is not distributed as a Python resource and is not a stable API.
