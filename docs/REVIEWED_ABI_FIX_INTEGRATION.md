# Reviewed ABI fixes on the next-stage candidate

## Frozen ancestry and scope

This child is based directly on PR #14, commit
`82f479d21de50626914468f81d8c032df62327da` (tree
`007e74a75945914f9d9c4bbe053bbdcb4abfb08f`). It treats that snapshot as a candidate
integration base, not a declaration of the project's canonical architecture.
It does not merge or modify PR #14.

Only the independently reviewed source fixes and unchanged regression tests
from these donors are transplanted:

- PR #12, `f47508f5700c7595ff167c6c7ddf5458bc445a41`: reject unlowered C
  function-type calling-convention decorations instead of silently exporting a
  different ABI.
- PR #13, `84ae11e2fb6611bcdb97e7319bbaca3a3e0d1a2e`: resolve the scalar
  pilot's four supported typedef names through actual Clang canonical types,
  including return-only aliases, rather than guessing signedness/width by name.
- PR #16, `244ba9aea3daa301b82c71ed6e9eadc07f7e5392`: reject declarations
  hidden by an externally defined or same-header pre-defined include guard.

No checker, ownership, resource/flow/HMIR implementation, benchmark, fixture,
workflow, C++ bridge or project migration source is changed. The only source
files changed are `hepta/c_migrate.py` and `hepta/c_import.py`.

## Semantic intersections retained

PR #14 already contains main-file declaration accounting and atomic publication
in the scalar pilot, a separate `migrate_c_project` entry point, and extra
C-import alias compatibility assertions before prototype assertions. All are
preserved. The guard gate precedes the native header include and both assertion
families. The canonical typedef context remains local to scalar C migration;
its shared helper's C++ bridge behavior is unchanged. New project translation
uses a separate type mapper and is not silently redirected through this fix.

PR #14's existing alias assertion already rejects the donor's hidden-alias
case. That strengthening is retained, not replaced or counted as a newly
reproduced defect. Record-only and same-header guard cases still failed on the
frozen base.

## Unresolved PR #15 intersection

PR #15 (`2f571334e431e5c50e299651b257ea576130a5cf`) is separately based on PR #4
(`0ee943a4c79ec5a414e8e75b88c4dd38da960a48`). It rejects preprocessing input
except a literal stdint include, aiming to close missing-offset/macro declaration
inventory gaps. It has not been imported here. Its strict header boundary would
reject the included-header positive regressions intentionally retained by the
canonical-type donor. The inventory/provenance policy must be reconciled
explicitly; this child does not claim that gap closed or choose a policy by
mechanically combining the branches. It also does not repair residual C++
alias semantics or extend preprocessor support.

## Source-specific local evidence

Before changing the frozen PR #14 sources, the unchanged donor suites produced:

- Calling conventions: four expected failing assertions across three tests.
- Typedef semantics: five expected failing assertions across four tests, including
  the two complete native programs returning 1 versus 0 for a defined negative
  input. Each caller sees its actual prototype; no incompatible ABI call occurs.
- Active guards: two expected failing assertions across five tests. The alias
  case already rejected under the base's stronger native alias probe.

After integration, all 77 C/import/project focused tests passed. The original
failed runs are retained separately, not overwritten with green output.

This is bounded correctness evidence, not arbitrary C/C++ translation
soundness, universal ABI equivalence, whole-language proof, or release-wide
qualification. The donor release receipts and PR #14's historical 19-gate report
remain source-bound historical evidence and are not inherited as new-head
results. No remote CI is queried, no branch is merged, and no deployment occurs.

Final local unit/integration run: **661 tests passed, zero skips**, 119.421
seconds, with Python 3.12.14, Clang 19.1.7, GCC 14.2 and pinned Rust 1.90.0.
The run used a 420-second timeout and single-job/thread build environment.
Independent integration review found no blocker, verified all three donor test
files unchanged, checked the retained interfaces and assertions, and reran nine
canonical-type/active-guard tests successfully. `git diff --check` passed. This
run is the current full unit/integration suite, not a rerun of all 19 release
gates, performance experiments or real AI evaluations.
