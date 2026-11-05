# Selecting the native C archiver

The independent C backend uses `CC` (or `--cc`) to choose its native C compiler.
For `--crate-type staticlib`, it also needs an `ar`-compatible archive tool.
Set `AR` to an executable path or a name resolved through `PATH`:

```sh
AR=/path/to/ar python -m hepta build library.hepta --backend c --crate-type staticlib
```

When `AR` is unset, the existing `ar` lookup on `PATH` is unchanged. When it is
set, that exact selection is required. An unavailable or empty selection raises
`E_C_TOOLCHAIN`; it does not fall back to a different archiver. A path containing
spaces is passed as one executable. `AR` is not a shell command and must not
contain command-line options. The selected tool receives `rcs`, the temporary
archive path, and the compiled object path as three arguments.

Object-only and check-only operations do not need an archiver. An archiver's
nonzero exit still fails the build before the output archive is published.
This selection does not add cross-compilation support or qualify arbitrary
archive formats, targets, or C backends. Existing compiler and artifact checks
remain in place; archive-tool identity is not added to build receipts here.

## Focused regression checks

```sh
python -B -m unittest discover -s tests -p 'test_c_archiver_selection.py' -v
```

The eight checks require a POSIX host with GCC, GNU-compatible `ar`, `as`, and
`ld`. They compile a small, fixed C function, create real archives, inspect their
members, and link and execute a C caller. Tool wrappers only record or reject
archive invocations; successful archives are produced by the actual host `ar`.
The tests also cover unavailable/empty selections, a nonzero tool exit, names
and paths with spaces, the default lookup, and operations that need no archive.
They do not run Hepta lowering, language semantic tests, research workloads,
formal verification, benchmarks, or full release qualification.
