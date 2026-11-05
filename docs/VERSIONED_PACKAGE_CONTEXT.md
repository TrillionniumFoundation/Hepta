# Versioned package selection and module context

This is a bounded P12 correctness composition, not a release or whole-project
qualification. It combines the existing package-context correction with the
existing offline resolver and lock review. P01/P11/P12 remain PARTIAL.

## Exact sources and narrow change

- Parent #698: `999850195334cc8439cfbb95de09e6e49faeee2c`, tree
  `9b0ed5e947fbb42920d6cb303d6f5346fbe79da6`.
- Guard and historical tests/documentation from #665:
  `017e8c469f3b55f6b4ac6ae0391527442d1432b7`.
- The three-line production insertion is the original completed-module-cache
  check that requires equal canonical package roots. Its position after escape
  and active-stack checks is unchanged. No resolver, lock, checker, backend,
  package schema or compiler-signature behavior is changed.
- Of the parent's 166 files, 165 remain byte-identical. Removing exactly that
  guard recovers the original `hepta/modules.py` Git blob. The original #665
  test file and context document retain their original Git blobs. The source
  manifest and preflight check all these identities on every scoped run.
- All three parent workflows, 65-method runner, three oracles, component pins,
  tests and inventories remain byte-identical. No new workflow or manual
  dispatch is added. The original context document describes historical #665
  evidence, not a new full #665 pass on this composition.

#666/#667 qualify module scope with this guard, but not version resolution.
#709/#719 qualify versioned library consumers without the guard. This change is
stacked only on #698, not those larger compiler/library compositions. It does
not claim that their source trees, module-scope corrections or unrelated package
schema repairs have been integrated here.

## Reproduced wrong result

A package can select a local version candidate inside its own source tree.
The candidate's library imports `helper`; the candidate's helper returns 42,
while the application's helper returns 7. On exact #698, importing the selected
library normally returns 42. Adding an unused application-relative import of
that same library first silently changes the result to 7. Reversing the imports
returns 42 again. A transitive constraint that selects the lower version has
the same defect, with 24 changing to 7 in the independent oracle.

These use ordinary regular files, acyclic graphs, refreshed content locks and
actual GCC O0/O3 with UBSan. The lock correctly records selected candidate
nodes and edges; a valid content lock does not remove the ambiguity in the
module cache's package context. There is no stale-lock or collision claim.

The independent baseline accepted all 48 conflicting loads across two selected
versions, candidate ordering, import ordering, locked/unlocked loads and three
entry forms. Eight native executions demonstrate the incorrect 42/24 versus 7
results. The corrected source rejects all 48 with full
`E_MODULE_PACKAGE_CONTEXT` diagnostics at the second import's exact span.

## Compatibility and migration contract

- Conflicting reuse rejects regardless of import order, locked mode or the
  selected candidate's version. A module error does not trigger resolver
  backtracking to a semantically different older candidate.
- Multiple dependency names, fixed plus versioned paths and dependency diamonds
  still reuse one module when their canonical package root agrees.
- A distinct unselected candidate file may still be imported in the application's
  own context. Distinct physical files and different versions with the same
  package name do not themselves conflict.
- Candidate updates still stale old locks. Explicit refresh selects the new
  graph; lock review reports every changed dependency edge and continues to say
  `compatibility: not_assessed`. A fresh lock may describe a graph whose imports
  are rejected by the module check.
- Root package source inventories include nested source files even when the
  nested package is not selected. Selection assertions concern package nodes
  and edges, not an invented promise to omit every unselected nested file.
- Source overlays and relocation retain their existing rules. The correction
  neither assigns ownership to the nearest manifest nor bans nested packages.

## Reproduction and exact scope

Run from this source with Python assertions enabled and actual GCC:

```sh
PYTHONDONTWRITEBYTECODE=1 python -B tools/qualify_versioned_package_context.py
```

The frozen local inventory has **83 methods**: 60 selected original #698
methods, 11 selected original #665 methods and 12 new versioned intersections.
It requires planned = started = finished = passed, zero skips/failures/errors/
expected failures/unexpected successes, and unchanged source bytes. New tests
cover selected high/low versions, transitive backtracking, both import orders,
all entry forms, backend-independent rejection, lock staleness/refresh/review,
same-root reuse, distinct versions, overlays, CLI execution and relocation.
Only fixture helpers are reused from #665; new tests do not inherit its tests.

The unchanged acyclic #698 oracle checks 326 graph states, including 250
satisfiable and 76 unsatisfiable states, 249 transition pairs and 748 complete
lock comparisons. The independent context oracle separately checks 48 exact
rejections, 16 valid C/Rust frontend cases, eight native O0/O3 UBSan executions,
and a version upgrade that retargets three shared dependency edges. Rust
frontend emission is not native Rust execution.

The original full 65-method #698 gate is **not run by this scoped command**.
Five cycle-specific #698 methods, the original #665 active-cycle method and its
native Rust parity method are recorded as unexecuted in the source manifest.
The other two original package graph oracles are also outside this scoped run.
They are retained, not weakened, replaced with skips, or reclassified as passes.
This is not a full 124-method #665 qualification either. Original parent greens
cannot qualify the new source. Required hosted gates remain separate exact-head
evidence, and this new scoped check has no dedicated hosted workflow.

## Remaining limits

Native Rust, ARM and Python 3.11 are unexecuted locally. There is no recursive
program execution, literal-admission validation, function-signature audit,
C-import publication or output-alias work. No registry, universal solver,
compatibility proof, automatic migration, semantic equivalence, security
isolation, formal soundness, resource bound, performance or production claim
is added. Draft only; no merge, release, deployment or activation.
