# One HIA-only main line

Owner decision 3905 consolidates the Hepta repository into one active remote
branch, main. Subsequent work uses main and detached immutable qualification
checkouts, not another family of published feature branches.

## Current product and conflict policy

The product combines the latest full native workspace JSON linker, explicit
native workspace facts and semantic ELF materialization, native capability
renaming, private compiler-state optimization, Agent identity and SSA/CFG
slicing, and the repository/Runtime-audit cleanup.

Facts transport and linked Core JSON have distinct filenames and protocol
identities. Framing success never grants semantic admission. Original Core
type, resource and borrow checks, native compiler limits, all retained control
families and original/modified-source bootstrap requirements remain in force.

Every captured branch tip remains reachable in Git history. The selected
current product tree is an explicit content reconciliation, not a union that
reactivates retired high-level implementations or intentional red experiments.
The per-reference history disposition is recorded under
review-evidence/hia-main-consolidation-20261110. Historical failures do not
become qualification passes because their histories have been consolidated.

## Qualification and publication

The review summary binds the exact implementation commit and terminal local
receipts. Before updating remote references, require unchanged qualified source
paths, complete full regression with no skipped/expected-failure promotion,
all original tips ancestral, and unchanged remote reference leases. Main moves
forward; old references are removed only while their full histories remain
reachable through main. Check the live remote refs for the publication result.

The commit/tree metadata archive is complete but blob-filtered: it is not an
offline backup of every historical file. The failed full-content download and
its partial pack remain external failure evidence.

This branch consolidation is not complete HIA-native product qualification:
136 Python package modules remain. No live Runtime, Mac or X230 service,
configuration, state, package pin, task replay or deployment is changed.

## Post-publication CI provisioning correction

Main `3641637b54edb4d055280024d17d2fcca2c5fe2c` was published as a fast-forward; all 1,036 old remote branches were then removed with per-ref leases after ancestor verification. Git and the GitHub branch API confirmed only `main`. The 44 remaining obsolete PR heads were also verified as ancestors before their PRs were closed; their descriptions and histories were not rewritten.

Its HIA Core-only run `42851392168` passed source controls, cold bootstrap and language regression, but two loaded-mapping controls failed because the native job installed the distribution's default Clang rather than their required Clang 20+. That failed run remains a failure. The follow-up changes only CI provisioning: verify the existing LLVM signing fingerprint, install Clang 20 and its runtime, and bind both driver environment variables explicitly. No product source, checks, skip policy or native admission guard is changed. The actual loaded-mapping and workflow-boundary suites passed locally (7 tests, no skips). The 3,699-test and 5,049-cold-check evidence above remains scoped to its original exact implementation source, not retroactively relabelled as qualification of this CI correction. Remote follow-up status must be read from the new commit's run.
