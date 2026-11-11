# Original Core PR attempt 2 evidence

This directory retains the second and final observed diagnostic attempt of Hepta Core run 43015503275, native job 130524053433, without replacing attempt 1. Candidate source is frozen at 7c20b6cfc792f0147b5418968f94734b8890fcca; actual PR merge checkout is 71520ff1114b0dd95b78ccc4563864713baccc67 with the identical tree d76c851edfb51fd649aca26a799ed4874af54489.

Read DIAGNOSIS.md for the finding and workflow comparison, PHASE-COMPARISON.md for existing wall observations, full-archive-readback.json for independent ZIP/source verification and phase-readback.json for completed report/archive hash checks. The complete original artifact is artifact-13854688251.original.zip. Small original reports are also extracted verbatim into hia-cold.json and hia-cold.cold/. Full original stage archives and unfinished inputs remain inside the original ZIP; no later successful record is substituted.

attempt2-log-readback.json is the earlier log/Range-stage snapshot, retained unchanged. Its pending full-download wording is superseded by full-archive-readback.json and desktop-original-archive-verification.json. range-readback.original.json explicitly identifies its original partial observation. Both the original desktop transfer and the independent cloud verification copy reached the same complete ZIP SHA-256 and all 4,441 outer-member CRCs. Slow partial transfers are recorded separately in artifact-transport-observations.json and are not test executions.

Runtime 7924 comparisons derive from already-retained original push/PR archives and literal job-log excerpts. Later Runtime candidates are outside that comparison. No candidate code, qualification budget, test inventory or worker count changed for this evidence.
