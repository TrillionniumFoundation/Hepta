# v69 execution integration qualification

This new runner retains the unmodified v5 runner and every existing test group.
It adds the current native Core execution family, its independent scalar and
complete VM controls, and an actual sdist/wheel/installed-worker check. The
installed process refuses authoring imports and cannot use the original VM.
All 38 component families receive the same current-source cold report.

Cold admission still has a 180-second qualification limit and 3-second cleanup
limit. The outer cold step retains 240 seconds, component groups retain 1800
seconds, and the unrestricted complete suite retains 5400 seconds. No skip,
expected failure, deadline change or prior-run proof substitution is admitted.
The unchanged process owner retains SHA256
`f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80`.

This is a pending integration gate, not a qualification result. The retained
reference implementations remain available for independent comparison.
Public normalization, complete slot-object behavior, static resource owners
and constant-folding remain separate closure work. Whole-native delivery,
default migration and removal of old owners remain false.
