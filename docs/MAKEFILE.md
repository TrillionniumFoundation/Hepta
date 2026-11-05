# Selecting Python for Make targets

The root [Makefile](../Makefile) defaults to `python` for compatibility with the
existing commands. Hepta requires Python 3.11 or newer. To select a particular
interpreter for every target, pass the `PYTHON` make variable:

```sh
make PYTHON=python3.11 check
```

An exported `PYTHON` environment variable also works. An explicit command-line
assignment takes precedence over the environment. Interpreter options can be
included, for example `make PYTHON='python3.11 -B' check`.

To inspect the selected commands without executing them:

```sh
make -n PYTHON=python3.11 check native bench release examples groups formal cross
```

Changing the interpreter does not install it, install native toolchains, change
validation scope or relax any test or release gate. The `check` target still
runs the complete discovered suite, including native tests. The default target
remains `check`. Native, formal, cross-target, benchmark and release commands
retain their existing prerequisites and arguments.

## Isolated routing regression

```sh
python3.11 -B tools/test_makefile.py
```

This standard-library test needs GNU make. It copies only the Makefile to a
temporary directory and runs `make -n`; it does not import Hepta or its tests,
run project test bodies, launch native compilers, execute evaluators, or write
qualification evidence. Its independent inventory covers all eight targets and
14 commands, the unchanged default, command-line and environment selection,
command-line precedence and interpreter options. The nonexistent interpreter
paths used in routing cases are intentional: the commands must only be printed.

The separate CI workflow checks the exact PR head on Python 3.11 and 3.13. Passing
these routing checks is not full project, native, formal, performance or release
qualification. See [BLOCKERS.md](BLOCKERS.md) for the broader open goals.
