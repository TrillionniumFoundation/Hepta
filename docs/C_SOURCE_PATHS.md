# C source filenames and line directives

The independent C backend emits source filenames in C `#line` directives.
These are C string constants, not JSON strings. The filename affects native
diagnostics and debug line tables, without changing the program's operations.

## Reproduced defects

On baseline `f2b76f5741c83822be2e12cf5a50b50a8d27b96a` (draft #564), a
source file named `program-😀.hepta` passes parsing and checking but fails real
GCC compilation. JSON quoting emits two UTF-16 surrogate escapes, which are
invalid C universal character names. Some control-character filenames fail
similarly. BMP Unicode filenames alone do not expose this bug.

There is also silent corruption: with the existing `-std=c11` flags, trigraphs
inside the filename are processed before string decoding. A filename containing
`??=` or `??'` becomes `#` or `^` in the actual DWARF filename table.

The twelve regression tests were run first against the unchanged compiler.
That run failed fifteen subcases, including real file/CLI builds and a real
DWARF filename mismatch. The same tests pass after the repair. The count of
subcase failures is not a count of independent tests.

## Bounded encoding change

Only the function and statement filename emission sites change. A single helper
encodes a NUL-free Unicode string as UTF-8 bytes, then produces one ASCII C
string constant. Printable ASCII stays unchanged, with ordinary quote and
backslash escaping. Question marks and all other bytes use exactly three octal
digits. Thus there are no trigraphs, surrogate escapes, literal line separators,
greedy hexadecimal escapes, or filename-originated preprocessor directives.
Following digits cannot extend a three-digit octal escape. Ordinary existing
ASCII paths, including quotes and backslashes, retain their emitted spelling.

NUL and strings containing unencodable surrogates receive positioned
`E_C_SOURCE_PATH` diagnostics. Raw non-UTF-8 POSIX filename bytes are not a
supported extension. This does not change filesystem resolution, permissions,
source-line reset behavior, backend selection, public ABI, native operations,
resource verification or any production qualification authority.

This follows GCC's documented [line-control string
rules](https://gcc.gnu.org/onlinedocs/cpp/Line-Control.html) and
[initial processing of trigraphs and physical
lines](https://gcc.gnu.org/onlinedocs/cpp/Initial-processing.html).

## Verification

The tests exercise actual GCC, C11 with explicit trigraph processing and strict
warnings, UTF-8 `__FILE__` byte equality, and `__LINE__`. All nine trigraphs,
astral/BMP characters, Unicode line separators, quote/backslash escapes and
escape-following digits are covered. Real temporary Hepta files build through
the normal pipeline and CLI. O0/O3 executions use UBSan with recovery disabled.
GNU readelf checks filename bytes and statement line numbers in actual debug
artifacts, including different function/statement filenames and inert hostile
filename text. No GDB interaction or universal debugger guarantee is claimed.

Newline filename controls use the actual emitted Hepta program and readelf,
not an added `__FILE__` expansion: local GCC 14 itself mishandles that macro
expansion for newline filenames. The production output uses no such macro.

Run all 201 unique controls, including inherited C backend, ownership,
parser/checker and debug-source tests, with real GCC/readelf and Rust 1.90:

```sh
python -B tools/test_c_source_paths.py
```

Without Rust, the explicit local route runs 186 controls and prints the fifteen
omitted Rust-dependent identities. This is not a complete hosted pass:

```sh
python -B tools/test_c_source_paths.py --without-rust
```

The exact-head workflow requires all 201 controls on Linux x86-64 and AArch64,
zero skips/expected failures/unexpected successes, and unchanged tracked source.
Local validation passed the 186-control route; hosted and actual Rust results
must be observed separately. This remains a draft, with no merge or deployment.
