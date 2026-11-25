# Native unsigned decimal value qualification

The actual native HIA role passed **4,024** independent checks. This qualification covers the pure immutable value component. Runtime allocation ownership, coordinator locking, publication, generation reservation, epoch advancement, and background scheduling have separate integration gates.

## Actual native execution

The source at component commit `367a273db9e4a6dfa96c530aa70567f9fe1f8362` was compiled by the qualified v95 native source compiler, SHA-256 `494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af`. The compiler's original limits of 128 functions, 1,536 blocks, 8,192 operations, and 16 block parameters were unchanged.

The resulting 34,929-byte flat image has SHA-256 `f07aca774bdf703fda1db510d99cd5dbe903058db97a17a356c3ee44c85913a8`. Its source contains 11 functions, 110 blocks, 341 operations, and at most 9 block parameters. The test runner mapped this exact image from a sealed memfd and called its six-word native entry. The independent oracle used Python arbitrary-precision integers outside the native image.

## Coverage and results

- Exact copy, increment, addition, comparison, and subtraction at boundaries through 4,096-bit operands, including 64-bit and 128-bit transitions.
- 800 deterministic random operand pairs spanning 1 through 16,384 bits, with seed 20261125.
- Carry and borrow chains with 4,097, 65,537, and 1,048,576 digits, including a 1,048,577-digit operand. The longest checks use independently constructed decimal expectations.
- Canonical decimal syntax, invalid A and B operands, subtraction underflow, private frame and reserved field validation, and exact source and output extents.
- 390 refused calls verified atomic output preservation. Every call checked immutable source bytes, unused work bytes, and unchanged output tail canaries.
- No fixed-width value saturation, wrapping, or counter reset was introduced.

The complete machine-readable case record is [HIA_UNSIGNED_DECIMAL_VALUES_QUALIFICATION.json](HIA_UNSIGNED_DECIMAL_VALUES_QUALIFICATION.json). It records each input hash and length, returned status, result hash and digit count, output capacity, and measured execution time. Oversized case payloads are reproducibly specified by the coverage above rather than checked into the source tree.

## Evidence identity

- Full case record SHA-256: `e8cffd69057919ebeb821026034191c73d6796de56f4926e5ea4e0784c6d3b3e`.
- Independent runner SHA-256: `cbc00a81e3bd85e0c287b1fd71d8a9ee777597b8db68999f5d613a63af3430fa`.
- Native input/output contract: [HIA_UNSIGNED_DECIMAL_VALUES_ABI.md](HIA_UNSIGNED_DECIMAL_VALUES_ABI.md).
