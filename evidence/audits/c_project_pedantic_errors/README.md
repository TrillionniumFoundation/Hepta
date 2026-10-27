# C99 feature-query selection under `-pedantic-errors`

Base: `7c948142ba36b884ba0e1b08914b97b8b8b4d47f`, after the earlier
optimization/PIC capture correction.

## Actual remaining counterexample

The existing allowlist accepted `-pedantic-errors` but recorded it as an omitted
diagnostic flag. In Clang 20.1.8 this option also changes the builtin
`__has_extension` operator. The following source is inside the admitted scalar
C99 profile; it does not itself use a C11 extension:

```c
#if __has_extension(c_static_assert)
unsigned probe(unsigned x) { return x + 1u; }
#else
unsigned probe(unsigned x) { return x + 2u; }
#endif
```

The compilation database arguments are exactly:

```json
["clang", "-std=c99", "-pedantic-errors", "-c", "input.c", "-o", "original.o"]
```

With input `7`, real executions under the same Clang executable and the same
source/database bytes returned:

| Importer | Original native C | HIA interpreter | Standalone HIA native |
| --- | ---: | ---: | ---: |
| Before this correction | 9 | 8 | 8 |
| After this correction | 9 | 9 | 9 |

The source SHA256 is
`dcb5f142b1f3c2eb59f11c82e529ec996a364b26b618d5e7b29d60b84d589688`.
The exact recorded database SHA256 is
`14898207d9cbfc20db71d6714138c4e06d258fff039a65f240f05081afe22baa`.
`before-after.json` retains complete source/database text, captures, actual
compiler identity, translated source, program identities, compile commands,
native artifact hashes and all three observed results. The original C object
used the actual database options and was linked separately. The target library
linked only its standalone HIA object.

## Why an ordinary macro inventory missed this

For both C and C++, each of the existing allowed options `-g`, `-g0`, `-g1`,
`-g2`, `-g3`, `-Wall`, `-Wextra`, `-Werror`, `-pedantic` and `-pedantic-errors`
produced an identical `-dM -E -x LANGUAGE /dev/null` transcript to the respective
no-option baseline. All 20 calls exited successfully. The receipt records the
invocations and observed transcript identities. In particular, no ordinary
predefined-macro change was observed for the debug flags on this toolchain.

The C99 `__has_extension(c_static_assert)` probe nevertheless selected a
different body under `-pedantic-errors`. This is a builtin operator's result,
not an added or removed definition in `-dM`. The accepted combinations
`-pedantic -Werror` and `-Werror -pedantic` did not change that probe's selected
branch; `-pedantic-errors` retained its effect when combined with `-pedantic`
or with the debug flags. This evidence does not establish arbitrary compiler
option equivalence or matching diagnostic acceptance policies.

## Correction and validation

The shared C/C++ capture now retains `-pedantic-errors` in its existing semantic
option sequence, including dependency discovery, preprocessing, AST capture,
macro probes and replay. A rehashed capture which reclassifies this option as
omitted rejects. No language feature, driver, target or native gate was added
or relaxed.

Four targeted regressions passed with no skips in 8.307 seconds using the real
Clang 20 toolchain:

- Both C99 branches were compared through original native C, the HIA
  interpreter and standalone HIA native execution; ordinary macro dumps were
  required to remain equal.
- A header selected only by the strict feature-query branch was inventoried,
  and its unsupported global declaration was rejected.
- Rehashed C++ captures could not omit `-O2`, `-fpic` or `-pedantic-errors`.
- The unmodeled semantic option `-fwrapv` still rejected.

Reproduction:

```sh
CLANG=/usr/lib/llvm-20/bin/clang CLANGXX=/usr/lib/llvm-20/bin/clang++ \
PYTHONPATH=tests /usr/bin/python3 -m unittest -v \
  test_c_project_semantic_flags.CapturedSemanticFlagsTests.test_pedantic_errors_preserves_feature_selected_body_without_macro_dump_changes \
  test_c_project_semantic_flags.CapturedSemanticFlagsTests.test_feature_selected_dependencies_cannot_hide_rejected_declarations \
  test_c_project_semantic_flags.CapturedSemanticFlagsTests.test_resealed_capture_cannot_reclassify_semantic_options_as_omitted \
  test_c_project_semantic_flags.CapturedSemanticFlagsTests.test_unmodeled_semantic_flags_remain_rejected
```

The database driver spelling remains recorded metadata. Actual preprocessing,
macro/model capture and AST interpretation use the explicitly selected Clang;
this correction does not prove semantic equivalence to an original GCC driver.
The corresponding boundary is documented in `docs/C_MIGRATION.md`.
