# Executable-fixture repair composition

This correction retains original #715 `2a7724860824fa6b612d3ea701af4c7aed046804`
and composes the corrected #713 draft, whose inherited repair source is exact
#710 `a5cbdfda69cd9ba4c29bc9328e87845f88bd6270`. All 26 upstream repair files
remain byte-identical, including the three explicit Rust binary callers and
three Rust-independent contract regressions. All compiler, source-library,
packaging configuration and eleven workflow bytes remain unchanged. No new
workflow, dispatch, chmod, native Rust substitution or broad test run is added.

The original 286-file #713 provenance manifest and all three #677 supplier
identities remain unchanged. The artifact-only checker pins all 26 repaired
files, recovers the 21 historical originals through exact inverse edits, and
checks those projections against the original manifest. It never imports or
executes a project, test or qualification module to do so. The other 265 original
parent files are checked directly. Five new upstream repair files are required
as actual archive inputs, bringing the complete supplied source inventory to
298 and selected source inputs to 274, plus seven generated metadata members.

Projection is used only for historical identity checks. All fresh builds,
archive member comparisons, unpacked input checks and tests use actual repaired
bytes. Missing or changed repair files and changed inverse records must refuse
before any build command. No old failure or queued hosted job becomes a pass. An initial local adapter
attempt refused before any build because the two immutable inverse manifests
use different identity field shapes. Both original schemas are now handled
explicitly; that failed attempt remains separately recorded.
The unchanged installed/native qualifier remains a separate gate. The complete
410/418-method aggregate, native Rust, ARM and Python 3.11 are not local claims.

The original #715 parallel GCC `cc1`-killed result and original #710 hosted store
failure ([run 42025621232](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42025621232))
remain separate failures with their original source identities. All earlier
upstream failure records remain intact. The following original-head report is
retained as history, not qualification of this corrected source. P01/P11/P12
remain PARTIAL. Draft only; no PR/main merge, release, deployment or activation.

## Retained original-head contract

# Development source-distribution composition

This bounded P11/P12 increment combines the artifact contract from #677
(`5b7d69304f69423c8c4b4aeaeb156fed7fcf9b75`) with the installed compiler source
from #713 (`dca2b7131bb2774eef7f45cac24a844eb9feb1bc`). All 286 #713 files,
including compiler, tests, libraries, packaging metadata and workflows, remain
unchanged. The original #677 checker and packaging document remain unchanged;
its original manifest is retained under `tools/packaging_origin_677/`.
The old checker documents its historical scope and is not the current gate.
The old workflow is not copied and no hosted matrix is added.

The extended manifest includes current non-test helper Python files, tool JSON
inventories, source libraries and their manifests, and the documentation and
workflow bytes required by existing source-provenance checks. Workflow YAML is
inert archive content, not a newly enabled CI job. Historical generated evidence,
unrelated experiments, binary products, toolchains and bytecode stay excluded.
The compiler wheel still contains only the same 16 runtime Python files and five
metadata members. Libraries remain separate source packages, not wheel resources.

## Artifact-only gate

Run from a complete source checkout/export with preinstalled setuptools >=68:

    python -I -B tools/qualify_development_sdist.py > /tmp/development-sdist.json

The checker uses only Python standard-library code plus the preinstalled build
backend in isolated subprocesses. It does not import Hepta, test modules or other
repository helpers, discover or execute tests, invoke native compilers, install
packages, download dependencies, run evaluators/models/studies or upload archives.
Every build receives a fresh full source copy, including excluded tracked files
and exclusion sentinels. Expected archive membership comes from the independently
pinned source inventory, not from MANIFEST.in or the archive being checked.

The gate verifies:

- All original parent and retained supplier bytes and the unchanged manifest
  prefix, with both Git blob identity and SHA-256.
- Exact sdist source membership and bytes, plus seven named generated metadata
  files. The frozen evaluator's original review-input manifest still agrees.
- All wheel member bytes across clean direct, sdist-rebuilt and no-manifest
  routes, including entrypoint metadata and every RECORD digest and length.
- Original-manifest and no-manifest source archives retain their actual missing
  input lists, rather than being relabeled complete.
- Real build controls omit a non-test helper, a tool inventory, a source library,
  provenance documentation, benchmark sources and the evaluator C fixture.
  Additional controls include excluded synthetic evidence, an actual tracked
  historical result, and an unregistered documentation file. Each must reject
  for its named missing or unexpected member.
- An explicit `--check-inputs-only` invocation in the unpacked archive checks the
  complete selected input contract using that archive's own copied checker and
  inventories. It does not import or run its tests.
- Every supplied source byte remains unchanged after qualification.

The unchanged #713 installed/native consumer qualifier is a separate gate:

    python -B tools/qualify_installed_compiler.py > /tmp/installed-c.json

Artifact completeness does not establish that all test bodies execute, or that
every legacy gate supports running outside Git. No broad project test discovery,
signature audit, recursion execution, literal admission or output/alias behavior
is changed or qualified. The parent provenance manifests are preserved, not
rewritten to hide missing inputs. Every gate retains its original scope and
environment requirements. Linux C installation checks cannot qualify Rust, ARM,
Windows, Python 3.11, whole-language soundness or performance.

All wheels/sdists are disposable local validation products. There is no new
license or distribution permission, registry publication, release signing,
production standard-library qualification, merge or deployment. P11/P12 remain
PARTIAL and `whole_project_blockers_closed` remains false.
