# v67 complete-source qualification runner, revision 4

This runner extends the existing v3 qualification harness to the integrated
native owners. It is a new file. The historical v3 runner and its results are
unchanged. The adjacent `workflow_process.py` is an exact copy of the original
supervisor, with SHA256
`f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80`.

The original v3 source used for this revision has SHA256
`32f01fffcea0c4e19075738791cb0718ea81866d679b234adfde0bc7662253f2`.
Reading or validating this harness is not an execution or qualification of
the candidate repository.

## Invocation and custody

Run the harness against a clean, complete Git checkout. The output directory
must not exist and must be outside the candidate source tree:

```sh
python3 -B review-evidence/hia-native-rewrite-20261111/v67/qualification/run_hia_qualification_v4.py \
  --source /absolute/path/to/Hepta \
  --output /absolute/path/outside/Hepta/new-qualification \
  --full
```

The runner retains the original raw Git HEAD/tree/blob/mode identity before
and after execution. It reproduces all workflow-declared source generators
and the language inventory in a separate detached checkout and requires the
same complete source identity afterward. The cold source manifest must agree
with the complete pinned Git source. Runner and adjacent supervisor hashes
are checked before and after execution as separate harness identities.

No historical pass is transferred to a changed checkout, changed harness or
reconstructed source. `whole_native_delivery_qualified` remains `false`;
a passing retained regression is not a claim that the whole project has been
rewritten or that retained reference implementations may be deleted.

## Unchanged limits and result classification

| Boundary | Retained limit |
| --- | ---: |
| Product cold qualification owner | 180 seconds |
| Product cold owner cleanup | 3 seconds |
| External cold workflow step | 240 seconds |
| Ordinary workflow step and named suite | 1800 seconds |
| Complete `unittest` discovery suite | 5400 seconds |
| Supervisor accepted step ceiling | 7200 seconds |
| Supervisor TERM / KILL cleanup waits | 1 / 2 seconds |

The product cold command is unchanged and receives no deadline override.
The external supervisor still owns only its POSIX process group; it does not
replace the product owner's subreaper/ECHILD cleanup proof. The original
supervisor's additional leader reap wait is unchanged.

All original v3 component groups remain. `--full` still performs unrestricted
`loader.discover('tests', top_level_dir='.')`. No module or test is filtered out.
A suite needs a positive test count, success, and zero errors, failures,
skips, expected failures and unexpected successes. Missing component modules
fail normally; they are not silently omitted.

`FULL_RETAINED_PASS` requires the requested complete discovery suite, all
other steps, valid matching-source cold evidence, source custody and harness
custody. `COMPONENTS_PASS` is available only without `--full`. Every other
completed qualification remains `HOLD`. Original step logs, owner receipts,
cold failure records, suite JSON and before/after identities are retained.

## Fresh cold report selection

The v3 component list omitted several owners added by the parallel rewrite.
V4 explicitly provides the newly produced report to all 35 implemented or
scheduled cold-report families, including:

- Existing Core, publication, patch and workspace families.
- Composite types, task helpers, all enum/record/task operation owners, both
  nominal controller families, call/primitive lowering and task-helper cache.
- Execution budget, request journal, retirement state and worker requests.
- Release installation, release selection and artifact namespace.

`ARTIFACT_NAMESPACE` is included explicitly for the pending integrated owner.
Its named suite is `tests.test_hia_artifact_namespace_native`. The namespace
fixture uses `HEPTA_HIA_ARTIFACT_NAMESPACE_COLD_REPORT`; it is not substituted
with a development compiler when the component is missing.

At startup, every cold-report selector declared by the current workflow must
belong to this explicit roster. Missing coverage is recorded in
`workflow-cold-report-coverage.json` and refuses the run. Each component
fixture is still responsible for validating and consuming its matching-source
cold report. Merely supplying an environment variable is not evidence that a
fixture used a qualified compiler.

Before importing candidate modules or starting children, the runner removes
inherited `HEPTA_HIA_*` selections that:

- end in `_MANIFEST`;
- contain `_DEVELOPMENT_` or end in `_DEVELOPMENT`; or
- end in `_COLD_REPORT`.

This includes development compiler overrides and future production manifest
selectors, not only the historically named nominal manifests. Only the
explicit cold-family roster is then set to this run's new `cold.json`.
Apart from the original Python no-bytecode/unbuffered flags, unrelated
environment values are retained. Tests remain free to install
their own deliberate positive or negative selectors inside their processes.

`environment-selection.json` records each removed name, category, exact
encoded-value SHA256, byte count and empty/nonempty status, along with the
effective cold selectors. It explicitly records that the inherited selection
environment changed. Original selector values are not falsely described as
the environment tested by qualification. The existing discarded-selector
fields remain in the final report, with a separate discarded-cold-report list.

## Added component groups and evidence

The new groups cover nominal operations and controller orchestration,
durable budgets and request journals, retirement state, worker requests,
release installation and selection, and artifact namespaces. Existing
composition, alternate-owner routing, resource and loan controls remain in
those suites and complete discovery.

Each step retains its own stdout, stderr and supervisor receipt. Component
evidence variables for budget, journal, retirement, releases and artifact
namespace are directed to distinct paths under that step's output prefix,
alongside the existing module-graph and composite-fixture evidence paths.
A new group does not gain a larger per-suite deadline.

The v4 harness can be checked without executing qualification by parsing its
source and independently exercising its environment-selection helper.
Those checks are harness controls only; actual cold, native component and
complete retained runs need separate raw reports from the pinned candidate.

