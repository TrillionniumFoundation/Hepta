# Preserve the source operand that selects the original C/C++ program

This audit found five accepted, defined scalar counterexamples on the original
`eb722984c488a721bd6c69d2bd9a69d7c600def1` source. The capture accepted a source
argument such as `sub/input.c`, then replaced it with `Path.resolve()` in
dependency, preprocessing and AST commands. The selected Clang therefore saw
another filename spelling or another quoted-include search directory.

The original commands were executed with their original source operands and
working directories. This is independent of the documented boundary that the
database's `gcc`/`cc` spelling does not authenticate the original GCC driver.
These cases use the explicitly selected Clang 20 frontends throughout.

## Actual before and after observations

All cases call `probe(7)` through the original native library, HIA interpreter
and directly generated HIA native object. The final replay uses the same source
paths, source bytes, compilation-database bytes and working directories as the
before run. Only output artifact destinations change, so earlier observations
and native artifacts are not overwritten.

| Language and selected source behavior | Before: original / interpreter / HIA native | Final: original / interpreter / HIA native |
| --- | --- | --- |
| C `__has_include(__FILE__)` with relative main filename | 9 / 8 / 8 | 9 / 9 / 9 |
| C++ `__has_include(__FILE__)` with relative main filename | 9 / 8 / 8 | 9 / 9 / 9 |
| C main-source symlink selecting a quoted `local.h` | 9 / 8 / 8 | 9 / 9 / 9 |
| C++ main-source symlink selecting a quoted `local.h` | 9 / 8 / 8 | 9 / 9 / 9 |
| C++ concrete template argument `sizeof(__FILE__) + sizeof(__BASE_FILE__)` | 35 / 169 / 169 | 35 / 35 / 35 |

For the symlink cases, `alias/input.c(pp)` points to `sub/input.c(pp)`. The alias
directory's `local.h` defines `OFFSET` as `2u`; the canonical source directory's
header defines it as `1u`. The main source returns `x + OFFSET`. Replacing the
source operand changes ordinary quoted-header lookup, even without filename
builtins in the function. For the relative-name cases, Clang's
`__has_include(__FILE__)` chooses `x + 2u` with the original relative operand and
`x + 1u` after substitution of the absolute path.

[before.json](before.json) retains the original source text, exact database
entries, source/database hashes, selected compiler identity and observations.
[after.json](after.json) is the final same-input replay, binds the original
report hash and records the exact patched implementation/test file hashes.
[after-initial.json](after-initial.json) preserves the first successful
five-case replay before correcting the separate qualification-tool cwd issue.
These are finite empirical observations, not a proof of arbitrary C/C++ source
equivalence, full-language safety, performance or project-wide migration cost.

## Fix and admission boundaries

One shared command parser returns the original source operand along with the
existing reviewed flags and omission metadata. The canonical path remains the
file/dependency identity. Replay derives the operand from the already-bound
`original_arguments`, compares the derived flag/omission data, and checks the
database, source identity, dependency graph and preprocessed bytes as before.
No manifest schema, driver allowlist, semantic flag list or AST language profile
is expanded.

Dependency discovery, preprocessing, C AST lowering, C++ AST lowering and the
three original-native comparison tools now pass that operand in the captured
working directory. The comparison helper has an explicit optional `cwd`; its
default remains `None`, its actual working directory is recorded, and logs
continue to use their original evidence directory.

All leading `@` argv tokens reject before forwarding, including an `@` operand
following `-o`. This prevents response-file expansion when a formerly
canonicalized filename is replayed verbatim. Bare `-` stdin and option-like
source operands remain outside the profile. No shell command is constructed.
Resealing a capture after substituting an absolute operand or old absolute-path
preprocessing digest cannot authorize the different source selection.

## Validation, including the failed intermediate attempt

The first targeted run executed 27 tests in **198.933 seconds** with no skips:
**24 passed and 3 failed**. The new source-spelling, symlink/dependency,
`__LINE__`/`sizeof` template, response-file and resealing checks passed, as did
the earlier semantic-flag and selected capture-identity tests. The three failed
native comparison tests exposed that their shared `_process` argument named
`directory` had only selected the log directory; it did not set `run_bounded`'s
working directory. The original failure is retained in
[targeted-validation.json](targeted-validation.json) and
[targeted-validation.log](targeted-validation.log).

After explicitly forwarding `cwd` to the actual execution helper, the three
affected native comparison tests passed in **87.383 seconds**, with no skips
and stable recorded source identities. See
[qualifier-cwd-replay.json](qualifier-cwd-replay.json) and
[qualifier-cwd-replay.log](qualifier-cwd-replay.log). This is a three-test replay;
the earlier 27-test attempt is not relabeled as a complete pass.

After that correction, the five original counterexamples were replayed again
and all three observations agreed in every case. The final entry-control method
also rejected four cases: `@input.c`, `-input.c`, bare `-`, and an `@` response
operand following `-o`. The final run receipts and original logs are retained in
[final-recheck.json](final-recheck.json),
[final-five-counterexamples.log](final-five-counterexamples.log), and
[final-entry-negative-controls.log](final-entry-negative-controls.log).

The added regression module is `tests/test_c_project_source_arguments.py`.
It includes relative/absolute and dot-relative spelling controls, a database
`file` spelling distinct from its actual argv operand, selected-header mutation,
old-preprocessing resealing and actual original/interpreter/native comparisons.
It can be run with the explicitly selected toolchain:

```sh
CLANG=/usr/lib/llvm-20/bin/clang \
CLANGXX=/usr/lib/llvm-20/bin/clang++ \
/usr/bin/python3 -m unittest discover -s tests \
  -p test_c_project_source_arguments.py -v
```

Raw ad hoc original/HIA objects, shared libraries, capture data, generated source
and audit drivers remain under `/tmp/hepta-p3-path-semantics-audit`, with the
`before`, `after` and `after-cwd` attempts separate. Ordinary unittest temporary
directories follow their existing cleanup behavior; their actual failure and
success logs are retained here. No full suite, model study or performance run
was performed for this patch, and prior frozen execution evidence is unchanged.
