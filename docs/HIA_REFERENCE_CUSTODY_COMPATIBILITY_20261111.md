# Retained reference custody across supported Python versions

## Original published failure

The first source job for published commit
`3875e6bcd037d9d649e07ae5c4fcf7ce426f8210` (tree
`01ff475b929f0c21d7111cc793dde181dd690b2c`) ran 470 tests in
676.052 seconds on Python 3.14 and reported seven failures. The original job is
`130568440847` in [run 43034132760](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43034132760).
The complete decoded log is retained separately with SHA256
`899e9ef53600c3f53071a5461df7fccfee221d6e3c3ce7bbee5ad066e1d825bc`
(154,222 UTF-8 bytes). This failure remains an original failed observation.

Six selected test methods reproduce all seven failures on the identical local
tree using Python 3.13.5. That reproduction took 0.385277643 seconds and had no
errors or skipped tests. It is not a second complete source-suite execution.

## Precisely identified causes

Four test methods, including the two independent function subtests, used
`ast.dump` defaults to compare complete retained-reference AST hashes. Python
3.13 introduced `show_empty=False`; empty list fields disappeared from the dump
although the parsed implementation had not changed. The new test-only
`tests/hia_reference_ast.py` requests `show_empty=True` when supported. On Python
3.12 it retains the original full dump. It does not rewrite AST nodes, omit
fields, accept additional hashes or change the original expected digests.

The constructor custody check still expected the main branch's complete former
initializer. The integration had intentionally moved exactly its final four
lines of native function-session selection to the common constructor, after
the selected constructor route and the function-owner conflict check. The
retained nominal-admission initializer is the exact original `b99ff213` body,
SHA256 `f50b6efca4ed47d4f63abc94e9dfa4d8d7cbdd25b62bda0affe1aede4a7720b5`
after restoring its old method name. The check now verifies that exact body,
the exact four lines at the end of the common constructor, and reconstruction
of the unchanged original `5831f52f` initializer hash
`1b94c6d4246baf5e8be8d0e23924181b94a3746807215d4e4cb017e1918f5842`.
The original independent route, conflict, allocation and cleanup controls
remain responsible for execution order and session lifetime.

The workflow custody check expected the main branch's fifteen-module bundle,
while the unified workflow correctly executes that bundle plus fourteen
retained nominal controller and operation modules. The check now pins all
twenty-nine unique workflow modules, continues to pin the fifteen-module
bundle's own contract, and checks every integrated native cold selector. The
original failed/skipped/expected-failure rejection controls remain intact.

## Targeted correction observations

The same six methods pass with zero failures, errors, skips, expected failures
or unexpected successes on Python 3.12.14 (0.568630824 seconds) and Python
3.13.5 (0.597387579 seconds). The correction changes only test custody and its
source registration; no production Python or HIA implementation changed.

Python 3.14 validation and complete combined-source qualification remain
pending at this checkpoint. These targeted results do not transfer the old
local cold result or qualify the failed published commit. Whole-native
delivery, production default cutover and old-owner removal remain false.
