# Complete HIA verified-increment audit harness

This is a standalone, minimal Git tree for one explicit product target. It is
not a product branch and contains no other product workflows. It does not alter
product source, the Selfhost-Core 180-second qualification deadline, any test
selector, skip rule, expected-failure rule, or product budget.

## Freeze and publish

`target.json` is the sole source of the product repository, full commit SHA and
full tree SHA. Its values name the final frozen product HEAD and its
`HEAD^{tree}`. For a later audit, the owner must freeze a new product target and
replace **both** values before publishing a new harness commit. Do not resolve
a moving branch at audit runtime.

Publish these five files as a new Git tree **without a product base tree**:

- `.github/workflows/audit.yml`
- `prepare-dependencies.sh`
- `run-gate.py`
- `target.json`
- `README.md`

Only after the product target and this tree are final, create a new branch named
`audit/hia-verified-increment-<unique-suffix>` pointing at the harness commit.
That matching branch push starts the audit. The workflow does not depend on a
first-time `workflow_dispatch` in a branch absent from the default branch.
The harness checkout explicitly uses `github.sha`; the separate `source/`
checkout uses the full commit from `target.json`. No Core-only push workflow is
present in this minimal tree.

Retain the immutable harness commit, the product commit/tree, the GitHub run URL,
and the complete uploaded artifact. Remove the temporary harness branch only
after the original run and artifact are retained. This directory itself has not
been published or run.

## Actual execution

The job uses Ubuntu 24.04 x86_64 and Python 3.14. It installs the original Clang
20 packages after verifying the same LLVM signing-key fingerprint, and installs
`setuptools==78.1.1`, `wheel==0.46.3`, `z3-solver==4.15.4.0`, and
`jsonschema==4.26.0`. Rust 1.95.0 is explicit for the audit's default Cargo/Rust
commands. The original locked `rust/hia-core-shadow/Cargo.lock` fetch and its
before/after input checks run before the native NDU builds. Unversioned `clang`
also resolves through `/usr/lib/llvm-20/bin`.

Before preparation and before the Gate, the harness loads the existing product
source checker from the **fixed raw Git blob** and runs its full `_source_state`
admission. That checks every tracked file against its raw HEAD blob and
executable mode, independently of index hints, filters and `core.fileMode`.
The complete per-file SHA-256 inventory, exact commit/tree, and checker-byte hash
are retained. The same check runs after preparation and after Gate completion.

The public original NDU repository is fetched anonymously using exact shallow
commits and a blob filter. Sparse checkout retains only the three original
crate directories, their original parent Cargo manifest, and the original
adapter directory where required. Full crate directories retain embedded
fixtures. No original upstream checkout or adapter is edited.

| Profile | Exact original source commit | Builder | Rust |
| --- | --- | --- | --- |
| Ranking | `d3c2d760eca5065fc966820379c35c6e8d56e855` | `build_hia_ndu_bridge.py` | 1.90.0 |
| Recursive | `2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b` | `build_hia_recursive_ndu_bridge.py` | 1.90.0 |
| Finite | `4b6391e116949af0c7e59776baead67271856bdb` | `build_hia_recursive_ndu_bridge.py` | 1.95.0 |
| Current stream, `zero-abstain-v1` | `8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d` | `build_hia_recursive_ndu_bridge.py` | 1.95.0 |

Ranking uses the existing builder's isolated production manifests and unchanged
original non-manifest source bytes. The other three profiles use their original
adapter and tracked lockfiles. Actual binary paths come from actual receipts.
The product's identity admission runs on those outputs; the current stream also
performs a real `for_stream_profile(..., profile="zero-abstain-v1")` handshake
and close. This explicit profile binding is necessary because the existing
general stream tests do not themselves force the corrected source pin.

The seven required native variables are `HEPTA_NDU_BUILD`, `HEPTA_NDU_BRIDGE`,
`HEPTA_RECURSIVE_NDU_IDENTITY`, `HEPTA_RECURSIVE_NDU_BRIDGE`,
`HEPTA_FINITE_NDU_IDENTITY`, `HEPTA_FINITE_NDU_BRIDGE`, and
`HEPTA_NDU_STREAM_IDENTITY`. They are configured before first test import.

Fresh Python 3.14 discovery loads the product's entire declared `MODULES` tuple
through its existing `load_declared_suite`. This Gate declares 127 selectors;
the earlier local Python 3.12 discovery counted 1098 unique test IDs. Separate
new linked-observer tests are not silently appended to this declared Gate.
Those local observations are not a CI result. This run retains its actual
complete selector and ordered-ID lists. A missing prerequisite that still
declares a skip stops preparation for execution, leaving discovery evidence;
no tests are filtered to manufacture a pass.

The unchanged command is then run:

```bash
python -B tools/qualify_hia_verified_increment.py --output <new-external-directory>
```

It is owned by the product's existing
`review-evidence/hia-native-rewrite-20261111/workflow_process.py` with
`seconds=5400`. The owner observes **only the started POSIX process group**;
`full_process_tree_claimed` remains false. Its existing cleanup grace and
failure semantics are unchanged. The 180-minute GitHub job ceiling reserves
time for dependency acquisition and evidence upload; it does not extend the
Gate's 5400-second budget or any nested product budget.

The Gate's own failure, error, skip, expected-failure, unexpected-success,
complete-test-identity, and source-identity checks remain authoritative. An
outer timeout or missing final result is a failure, with original partial logs
retained. A successful finite implementation regression Gate is not a claim of
whole-language, performance, productivity, or whole-native-product completion.

## Retained evidence

The always-run collection and upload steps preserve original success **and**
failure output using a fixed allowlist:

- Setup stdout/stderr, locked caller-input checks, and outer preparation/Gate
  stderr, including failure before an inner receipt exists.
- NDU fetch/build command logs, ranking `command-evidence/cargo.*`, recursive
  builders' `commands/*`, identity/build/failure receipts, preparation and
  source-admission records, and the exact native environment mapping.
- Complete Gate output: discovery, all planned IDs, plan, original tests log,
  stdout/stderr, owner receipt, result if one exists, and harness outcome.
- All five original harness files. The workflow is copied to non-hidden
  `harness/audit.yml` inside the artifact so upload-artifact cannot silently
  omit `.github`.
- An artifact inventory with observed file sizes and SHA-256 values, and an
  explicit allowlist of GitHub run metadata fields.

The collector does not copy Git checkouts, `.git`, NDU source directories,
native build targets/binaries, Cargo caches, credentials, or the complete
process environment. It does not replace original failure files with generated
success records. Missing not-yet-reached files are identified in the inventory.

## Manual invocation on an already provisioned runner

```bash
python -B harness/run-gate.py preflight --target harness/target.json \
  --source source --output "$RUNNER_TEMP/source-before.json"
HIA_GATE_PYTHON=python bash harness/prepare-dependencies.sh \
  "$PWD/source" "$RUNNER_TEMP/native-prerequisites" "$PWD/harness/target.json"
python -B harness/run-gate.py run --target harness/target.json --source source \
  --environment "$RUNNER_TEMP/native-prerequisites/environment.json" \
  --output "$RUNNER_TEMP/verified-increment"
```

All output locations must be outside the product checkout, with new dependency
and Gate output directories for every attempt. These commands do not install
the system/Python prerequisites shown in the workflow.
