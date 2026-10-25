# P5 dual LLVM SSA artifact publication guards — exact source integration

This isolated branch combines the two independent fixes previously submitted
as PR #41 (target object) and PR #42 (host shared library) onto the exact PR
#37 base commit `af3f406f4d980ae2e8c5fca23b4ed12bee5195af`.

No new compiler semantics or LLVM optimization is claimed. All four code/test
files are copied as exact original Git blobs, rather than manually reapplying
textual patches:

| Integrated file | Original revision |
|---|---|
| hepta/llvm_ssa_target.py | 82432b49b27178ed6ed56a0b9a379989a59f859d |
| tests/test_llvm_ssa_target.py | 0cfe108ae04a8bdb1fb86266416f596dc0600d42 |
| hepta/llvm_ssa_backend.py | ae14e5d78b881142f9bd81818eb6b686e84cee75 |
| tests/test_llvm_ssa_backend.py | 321fa9f54b9f4424f8f6c48f9d136fefd3997207 |

The parent modifications affect different backend files. The target-object
path uses a lexical absolute destination without dereferencing its leaf;
it rejects existing/live/dangling output symlinks and retains no-overwrite
hardlink publication. The host-library path similarly rejects destination
symlinks before and after native compilation. Actual negative controls in
the corresponding test files explicitly create dangling symlinks and require
the unintended target to remain absent.

These checks cover **the leaf output symlink redirection class** described
in the prior PRs; they do not establish hermetic builds, arbitrary filesystem
race freedom, full path security against a hostile noncooperating parent
directory, or universal LLVM backend equivalence.

## Verification

The four integrated blobs were refetched from this new branch and match the
original PR #41/#42 blob SHA values byte-for-byte. PR #41 and #42 describe
separately executed local Clang positive/negative tests on their individual
heads. Those historical tests are not reused as a fresh combined-head
qualification.

This integration turn did **not** run the combined real Hepta Clang suites
or remote CI. The original two test files remain in place and should run
on the final combined source with matching compiler/toolchain identities.
No status from CI was consulted.

## Remaining blockers

P5 still lacks comprehensive CFG/SSA/LLVM ownership, effects, pointer
provenance, verified native lowering, real multi-target execution and
application performance acceptance. P0–P7 and P01–P12 system blockers
remain open; `whole_project_blockers_closed=false`.
