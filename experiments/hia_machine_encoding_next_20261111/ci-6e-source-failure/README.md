# Exact 6e GitHub failure and retained-source guard repair

Run [43038321007](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43038321007)
executed commit `6e048234e19e4dbf02d1cf5040831fba07748f02`, tree
`440f3fcb9014b2af6c788f78b993af6b25730d46`, on CPython 3.14.10. Its terminal
workflow status is **FAILURE**. The two complete job logs and API snapshots
in this directory are original observations. No rerun of that source was
requested to replace this result.

The source job regenerated all 51 HIA generators without drift. Its source
suite ran 350 tests in 288.562 seconds: 349 passed and one failed. The failure
was `MachineEncodingSourceTests.test_retained_reference_methods_are_unchanged`.
The test had compared a CPython 3.12 `ast.dump` serialization hash with the
CPython 3.14 serialization. The official CPython implementations differ in
their default representation of empty fields. The original encoder method
source had not changed.

The native job completed the cold wrapper with status
`COLD_SELFHOST_REPLAY_PASS` in 132.140118786 seconds at the original 180-second
limit. This is the original wrapper observation, not a qualification of a
later source. A separate archive audit is required for full nested custody.
All native workflow steps preceding the instruction-byte qualifier passed.
The original 44 machine-plan callers passed in 15.649 seconds. The instruction
qualifier then ran its complete nine-method component group in 3.706 seconds:
the same AST guard failed, while the other eight methods passed, including
the actual installed-wheel execution. The qualifier correctly stopped with
FAIL, before the 51 original caller group. The later complete 89-callers wire
step was skipped. Neither unexecuted group is recorded as passing.

The original artifact ID is `13865519334`, 122,628,168 bytes, with SHA-256
`7ff3905907ac8a02e0b5366ce4bbc3c24e5794c9dde94a0f87149c9ed9cc5137`.
It contains 6,176 members with 578,435,037 decoded bytes. It retains the cold
and native fixtures, including the component unittest failure and selected
caller report. Downloaded bytes were checked against the Actions artifact
digest before any inspection. The artifact's seven-day service retention is
not permanent source custody; the complete preservation is tracked separately.

## Repair without dropping the original assertion

Pre-execution repair commit `38dbc37edd1ad6467d519804c70d10a483d9da95`
adds `tests/fixtures/hia_machine_x64_e09.py.txt`, the exact original module from
`e09c6faf5507fc4e38d8b7c36ba2650a1c0a10d6`. Its Git blob is
`8e87bd317c5f61e00993bb0bf8d803c5385d6556`; its 11,057 original bytes have SHA-256
`8795fb4e5034673401f5f6a5a60e57872c48a3982dbdcb4d3b8198ee7b3f41a9`.
The fixture is part of the declared source closure.

The same test ID now verifies those exact frozen bytes, parses both classes
with the executing interpreter, requires exactly one newly added `__new__`,
removes only that one node, and compares the entire remaining class AST. This
retains all original methods and class metadata while avoiding a serialization
comparison across interpreter versions. No HIA kernel, image or production
adapter changed in this repair.

The adjacent `ast-reference-controls-r1` records the actual four source tests
on CPython 3.12.14: four passed, all five unittest anomaly counts zero, unchanged
source before and after, 1.6819196899996314 seconds. That scoped result is not a
CPython 3.14 result, a new cold run, or complete product acceptance.
