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
