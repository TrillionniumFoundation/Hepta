# Working with the Hepta 0.2 checkout

This guide covers the compiler source on `main` at
[`125d11c`](https://github.com/TrillionniumFoundation/Hepta/commit/125d11c5454835a7df1dc51915fc49901fbede5b).
Open research pull requests may add different commands or supported features;
their results do not qualify this source. The implemented language contract is
[SPEC.md](SPEC.md), and the prototype's compatibility limits are in
[COMPATIBILITY.md](COMPATIBILITY.md).

## Start from the repository root

The checkout requires Python 3.11 or newer. The compiler package has no declared
Python runtime dependencies. The commands below run the checked-out `hepta`
package directly, so no package installation is required for these checks.
Run them from the directory containing `pyproject.toml` and `hepta/`:

```sh
python --version
python -m hepta --version
python -m hepta --help
python -m hepta check --help
```

Use a Python 3.11+ executable if `python` selects a different version on your
system. This source reports `hepta 0.2.0`; that version alone does not identify a
later development branch or establish a stable language/ABI guarantee.

## Check the frontend without a native toolchain

```sh
python -m hepta check examples/parser.hepta --frontend-only
```

For this example the command returns exit code 0 with `ok: true`,
`status: "frontend_only"`, and `checks.rust_borrows_types: "not_run"`.
The syntax and supported type/effect/resource checks ran. Native checking and
program execution did not run. Always read `status` and `checks` alongside
`ok`; frontend acceptance is not a complete native check.

## Use the default Rust path

```sh
python -m hepta doctor
python -m hepta check examples/parser.hepta
```

The default backend requires actual **rustc 1.90.0**, as specified in
[SPEC.md](SPEC.md) and [toolchain-lock.json](../toolchain-lock.json).
`doctor` inspects the selected Rust compiler; it does not install a compiler
or diagnose the C backend. Rust selection can be supplied with `--rustc` or
`RUSTC`. An explicitly selected invalid toolchain is not silently replaced.

When Rust is absent, both commands above return exit code 1 with `E_TOOLCHAIN`.
That environment failure is not a compiler pass. A successful Rust `check`
performs the native type/borrow-validation stage, but does not run the program
or guarantee that a later final link will succeed.

## Check and execute the independent C subset

```sh
python -m hepta check examples/parser.hepta --backend c
python -m hepta run examples/parser.hepta --backend c --json
```

This path uses a GCC-compatible compiler selected by `--cc`, `CC`, or the
default `gcc`. It does not need rustc. Its supported subset and 64-bit host
data-model requirements are defined in SPEC.md, section 12.

For the parser example, the first command reports `status: "checked"` and
`checks.c_types_codegen: "gcc_checked"`; `checks.rust_borrows_types` remains
`"not_run"`. The second command builds and executes the program. A successful
run reports `returncode: 0`, `stdout: ""`, and `stderr: ""`: the example checks
its results with assertions rather than printing them. The CLI also exits 0.

A C success covers this example and backend. Unsupported C constructs reject;
there is no automatic fallback to Rust and no claim of full backend parity.

## Locate the full validation entry points

The root [Makefile](../Makefile) defines the developer checks. To inspect the
unit/integration-test command without executing it:

```sh
make -n check
```

It prints `python -m unittest discover -s tests -v`. The `check` target is the
full discovered suite, not a Python-only smoke test: it includes native tests.
Some native tests skip when tools are missing, while others require native
success. Read failures and skips explicitly rather than assuming every missing
tool becomes a skip.

The same Makefile links the `native`, `examples`, `groups`, `formal`, `cross`,
`bench`, and `release` targets to their scripts. Read the relevant script and
prerequisites before running a broader target. The successful smoke commands
above do not establish full-suite, formal, cross-platform, benchmark, or release
qualification. See [BLOCKERS.md](BLOCKERS.md) for the remaining project goals and
[INTERFACES.md](../INTERFACES.md) for compiler pass boundaries.

## Scope of the command verification

The commands in this guide were checked on the source commit above using
Python 3.12.14 and GCC 14.2.0 on Linux x86-64, with no rustc available:

- The version and help commands succeeded.
- The frontend-only parser check succeeded with native checks marked not run.
- `doctor` and the default Rust check produced the missing-toolchain rejection
  described above. Successful Rust validation was not exercised on this host.
- The C parser check and actual program execution succeeded with empty program
  output and exit code 0.
- The Makefile test entry point was verified by dry run only. The full suite
  and broader validation targets were not run as part of this documentation
  check.

These are source- and environment-specific observations, not release evidence
for another commit, platform, or backend.
