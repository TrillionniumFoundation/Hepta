# Generated C header module identities

## Reproduced problem

The previous `HEPTA_` + uppercase module name + `_H` include guard did not
preserve the source module identity:

- `module pkg::left;` emitted `#ifndef HEPTA_PKG::LEFT_H`. The colons are not
  part of a preprocessing identifier. GCC reports extra directive tokens;
  including `pkg::right` afterwards also hides that module's declarations
  because both directives test the `HEPTA_PKG` macro.
- `module App;` and `module app;` both emitted `HEPTA_APP_H`, silently hiding
  one header despite distinct case-sensitive source module names.

Both were reproduced with checked source and actual GCC C11 compilation on
unchanged source `f2b76f5741c83822be2e12cf5a50b50a8d27b96a`. The new tests
initially reported 21 failing assertions/subcases across 16 test methods;
2 Rust-dependent methods were skipped because that compiler was unavailable.
Subcases are not separate unique tests.

## Encoding and compatibility

Guards now use `HEPTA_MODULE_`, the exact UTF-8 module-name bytes encoded as
uppercase hexadecimal, and `_H`. This is a valid non-reserved preprocessing
identifier and an injective byte encoding. It does not collapse case,
namespace separators or underscores, and does not depend on a hash collision
assumption. For example, the default `main` module uses
`HEPTA_MODULE_6D61696E_H`.

Only the opening guard, its definition and the closing comment change.
Includes, public symbols, record declarations, linkage, layouts, source
checking, and native validation are unchanged. Repeated inclusion of the same
module remains suppressed even when a different copy contains different
symbols. This does not make it valid to include conflicting versions of one
module or distinct headers with duplicate public ABI symbols/types.

All generated guard spellings intentionally change. Consumers should include
the header normally rather than manually defining or inspecting the old
macros. The existing checker already reserves the entire `HEPTA_` prefix for
header macros. Historical evidence files are not rewritten.

The guard is linear in module-name length, at two hexadecimal characters per
UTF-8 byte. The parser currently admits ASCII module identifiers. Tests cover
long names in the selected GCC/G++ profiles; unlimited preprocessing-identifier
portability across every compiler is not claimed.

## Finite validation

Run the new portable/native-C tests with:

```sh
python -B -m unittest tests.test_c_header_guards -v
```

They check exact encoding, namespace/underscore/case separation, declaration
stability, the default module, deterministic guard identity, 192 distinct
valid module names, and both include orders with repeated includes. Actual
strict C11 and C++17 clients compile, link and execute separately compiled
Hepta C objects. A real CLI C-header flow is also exercised. Two additional
methods link actual Rust objects to C and C++ clients when pinned Rust is
available.

The focused hosted workflow selects exact PR HEAD on Linux x86-64 and
AArch64, with Python 3.12, GCC/G++ and Rust 1.90.0. Its runner requires exactly
206 unique new/adjacent parser, checker, C backend, importer and protocol
controls, with no skips, expected failures, unexpected successes or omitted
executions. Tool/source identities and raw logs are retained. Run it locally
with an explicit pinned compiler:

```sh
RUSTC=/absolute/path/to/rustc python -B tools/test_c_header_guards.py
```

Local Python 3.12 results before hosted execution: 16 focused methods,
14 passed and 2 Rust-unavailable skips; 206 aggregate methods, 187 passed and
19 Rust-dependent skips. Local success is not a native Rust pass. The hosted
result must be read for its exact source before calling the full finite gate
passed. This is a header-generation repair, not whole-language or production
qualification.
