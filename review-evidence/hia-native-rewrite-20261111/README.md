# HIA native rewrite evidence

Baseline: `c2d937e5eec734af5c1d5d0519afc7e3a91df58a`.
These development observations retain their original identities, including
failures while the shared source contract was still changing. They are not
retroactively promoted into cold or whole-product qualification. The final
qualification record, when present, identifies the tested source manifest.

`core-admission-differential.json` contains four previously accepted conflicting
returned-loan witnesses, three valid controls and 12,030 fixed-seed differential
checks. The original driver is retained without rewriting its absolute paths;
its `ROOT`, `OUT` and compiler argument must be deliberately set to a new local
checkout/output for replay. The regression log preserves its original strict
source-contract refusal before the joint contract was regenerated.

The static source ledger and domain-by-domain migration status are in
`docs/HIA_NATIVE_REWRITE_INVENTORY.json` and
`docs/HIA_NATIVE_REWRITE_STATUS_20261111.md`. Neither authorizes deletion of an
implementation or a live worker migration.

## Exact published v58 qualification

The first published tree (`f174f9b`, run `42933658467`) passed the full 11-check
cold wrapper but retained a stale language inventory. Its failed source/native
job logs, exact cold and nested records, and independently checked archive/source
custody are retained as `first-ci-*`. The subsequent `ecf6886` source/native run
`42934701069` passed: 222 source tests, 424 native component test invocations,
1,242 language checks, 10 language assertions and 11 cold checks. The two actual
job logs are `v58-ecf-*-ci.log`. These results apply to v58, not the v59 edits.

## Raw ordinary Agent patch-result development

`agent-patch-result-review.json` records the independent 540-case byte/refusal
differential, 11 Agent/SQLite controls and 10 real HIA-packed CLI controls.
`agent-candidate-final-development-tests.log` contains the focused nine-test
ordinary Agent suite, including isolated installed-wheel use and four real
SIGKILL cut points. The earlier 21-test log also includes 13 existing kernel
regressions discovered through an accidental TestCase import; that import was
corrected without dropping the kernel's own CI suite.

`core-patch-result-cli-development.log` retains the original misspelled fixture
and ptrace EPERM failures. The former has a separate successful focused recheck;
the latter remains unpassed locally. `agent-patch-journal-original-cache-observation.log`
retains the initially incorrect expectation that removing an image file would
invalidate an already pinned RX image. Its corrected manifest-refusal control
did not change the production cache lifetime.

The original external qualification runner mistakenly requested a long suite
from the cold owner's fixed 180-second API. The first local source-driver
refusal occurred before running tests and is preserved. The corrected external
workflow supervisor records only POSIX process-group custody and makes no
full-tree/ECHILD claim. The product cold owner's deadline and cleanup gate are
unchanged. The final full-runner revision also binds the entire clean Git tree,
separately from the smaller cold source contract, and distinguishes component
success from complete retained-regression success.
