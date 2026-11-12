# Retained retirement owner integration observations

The bounded HIA retirement owner is imported from
`5d5424a31caa33283a562defba9cb6b187deb99c` onto `ec484121`. Its HIA source bytes,
state protocol, fixed syscall primitive and two runtime policy entry points
are retained. Current paths use `.hepta`; public generator/builder scripts gain
only their standalone import guards. Package data and current source/CI gates
include this owner. [RECORD.json](RECORD.json) records exact inputs and raw logs.

The first actual 31-test development run had 30 passes and one failure: its
installed-wheel fixture omitted the current source-builder resources required
by `setup.py`. The original [result](initial-development.json) and
[log](initial-development.log) remain unchanged. The fixture now copies all
`SOURCE_BUILD_FILES`; policy assertions, native bytes and resource budgets are
unchanged. The corrected same 31 tests all passed, without skipped or expected
failures. Fourteen package-resource, direct-entry and CI source controls passed.

The nested retained runtime suite was then strengthened to require an exact,
nonempty test count and zero anomalies. That exact suite ran again: 69 of 69
original retirement, publication-interruption, multiversion and scalar-state
controls passed while the old policy constructors/functions were forbidden.
The [nested receipt](retained-suite.json) and [raw log](retained-suite.log) are
actual executions, including the original native children and resource faults.

Development deliberately reuses the retained `ec484121` B3 compiler. These
observations do not satisfy cold qualification for changed integrated sources.
Every run records its own complete source map; no prior result is relabelled as
matching a later merge. Native binaries, temporary installed trees and large
reproducible build directories are excluded from this committed record.

The owner controls in-process pin admission, effect claims and retirement state.
The adapter retains real foreign loader objects and descriptors. Multiversion
capacity, persistent Agent state, global release consumers and installed-release
garbage collection remain separate obligations. Whole native delivery and
production activation remain false.
