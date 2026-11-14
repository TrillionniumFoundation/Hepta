# Complete retained HIA qualification harness

This minimal Git tree runs the product's original
`review-evidence/hia-native-rewrite-20261111/run_hia_qualification_v4.py --full`
on one immutable product commit. It provisions the prerequisites required by
complete `unittest` discovery, preserves original success and failure output,
and independently checks the ordered method identities visible in the original
verbose test log. Product source, test bodies, skip rules and all inner budgets
remain unchanged. A separate supplemental step runs missing original caller
qualifiers and binds the production SHA stream image to the same cold
compilation and the native observations already made by full discovery. The
new full-cost, patch-impact, static-budget, Store-lifecycle and CLI-discovery
owners use that same cold result. The original CLI-discovery qualifier also
enforces its separate group deadlines and installed-resource checks.

## Freeze and publish

`target.json` is the sole product-target declaration: repository, full commit
SHA and full tree SHA. Its values name the frozen product selected for this
run. A later audit requires replacing both SHAs with that audit's separately
frozen product commit and tree. Nothing resolves a moving product branch at runtime.
The strict target parser accepts only full immutable commit and tree hashes.
It has no draft execution or target fallback.

Publish exactly these five files as a fresh Git tree without a product base:

- `.github/workflows/audit.yml`
- `prepare-dependencies.sh`
- `run-gate.py`
- `target.json`
- `README.md`

Create a new branch `audit/hia-full-retained-<unique-suffix>` pointing at the
final harness commit. Its push starts this workflow. The harness checkout uses
`github.sha`; the separate `source/` checkout uses the explicit full commit from
`target.json`. The tree contains no product Core-only push workflow. Keep the
harness commit, product commit/tree, run URL and original artifact before
removing the temporary harness branch. Preparing these files is not a test run.

## Environment and original dependencies

The job uses Ubuntu 24.04 x86_64 and Python 3.14. It installs Clang/LLVM/lld 20
through the original LLVM signing-key fingerprint
`6084F3CF814B57C1CF12EFD515CF4D18AF4F7421`. Unversioned `clang` resolves through
`/usr/lib/llvm-20/bin`. The original pinned Python dependencies are
`setuptools==78.1.1`, `wheel==0.46.3`, `z3-solver==4.15.4.0`, and
`jsonschema==4.26.0`; the existing verification-toolchain action also supplies
`zstandard==0.25.0` and `PyYAML==6.0.2`. The original locked
`rust/hia-core-shadow/Cargo.lock` fetch runs with before/after input hashes.
Rust 1.95.0 is the default for the full suite.

The existing `tools/bootstrap_verification.py` installs both components from
its committed locks: Lean 4.19.0 and the pinned AArch64 QEMU binary. Its original
archive/package and executable-hash admission remains intact. The full suite
also uses the explicitly selected `ld.lld-20` and Ubuntu's `qemu-x86_64` for the
actual masked-CPU target-profile controls. Tool versions, executable hashes and
modes are recorded. `LEAN`, `HEPTA_LLD`, `HEPTA_QEMU_AARCH64`,
`HEPTA_QEMU_X86_64`, and `HIA_TEST_CLANG20` are configured before first test
import; the existing `HEPTA_RUN_ARTIFACT_SESSION=1` switch enables its real native
session tests.

The public NDU repository is fetched anonymously at exact shallow commits with
a blob filter. Sparse checkouts retain only the three required original crate
directories, their parent Cargo manifest and the original adapter where used.
Full crate directories retain embedded fixtures. All original upstream
checkouts and committed adapters remain unchanged.

| Profile | Exact source commit | Existing product builder | Rust |
| --- | --- | --- | --- |
| Ranking | `d3c2d760eca5065fc966820379c35c6e8d56e855` | `build_hia_ndu_bridge.py` | 1.90.0 |
| Recursive | `2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b` | `build_hia_recursive_ndu_bridge.py` | 1.90.0 |
| Finite | `4b6391e116949af0c7e59776baead67271856bdb` | `build_hia_recursive_ndu_bridge.py` | 1.95.0 |
| Stream, `zero-abstain-v1` | `8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d` | `build_hia_recursive_ndu_bridge.py` | 1.95.0 |
| Raw model | `8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d` | `build_hia_raw_model_bridge.py` | 1.95.0 |
| Dynamic policy | `8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d` | `build_hia_ndu_dynamic_bridge.py` | 1.95.0 |

The last two use the existing builders' release profile and share the unchanged
stream-source checkout. Ranking, raw model and dynamic policy use the product's
existing isolated production manifests. Build receipts determine actual binary
paths. Product identity admission runs on every profile; stream, raw model and
dynamic policy also perform actual protocol handshakes and closes. These are
prerequisite observations, not substituted test results.

The raw-model environment binds `HEPTA_RAW_MODEL_BUILD` to the actual
`build-receipt.json` **file**. Ranking's `HEPTA_NDU_BUILD` remains the build
**directory** and `HEPTA_NDU_UPSTREAM` retains its original pinned checkout for
provenance controls. The original four NDU profiles and their checked build
workspaces remain available until the complete suite finishes.

## Raw source identity and complete discovery

Before preparation, after preparation, before discovery and after execution,
the harness loads the product's source checker from its immutable raw Git blob.
Its existing `_source_state` checks all tracked raw HEAD bytes and executable
modes, including regular-file and parent-directory admission, independently of
index hints or filters. Each observed complete per-file inventory and exact
commit/tree is retained.

A separate fresh Python interpreter performs the original complete discovery:

```python
unittest.TestLoader().discover('tests', top_level_dir='.')
```

It records every ordered method ID, count, description, loader error, declared
skip and expected failure, without executing any test body. The separate
interpreter prevents discovery imports from changing the environment of the
actual v4 process. The audit uses the actual Python 3.14 discovery of its final
target and includes every newly added test. Earlier discovery counts and prior
run results are never credited to this target.
It imposes no fixed count or selector subset. Missing declared prerequisites
leave full discovery evidence and prevent an attempted passing run.

The pre-discovery environment mirrors v4's existing static selector removals
and its original cold-report bindings, read from the admitted v4 source.
Twenty-six newer cold selectors, including `NATIVE_MAPPING`, additionally point
to **this same run's future `qualification/cold.json`**. The real unchanged v4
still performs its own original assignments. All native consumers retain their
existing matching-source cold admission. The two `WRONG_COLD_REPORT` negative
control variables are never populated.

The additions include `BOUNDED_MEMORY`, `SCALAR_PROFILE`,
`GENERATION_RETENTION`, `PUBLICATION_MEASUREMENT`, the actual
`SHA256_STREAM_DIFFERENTIAL` selector, and the new `FULL_COST`, `PATCH_IMPACT`,
`STATIC_BUDGET`, `STORE_LIFECYCLE` and `CLI_DISCOVERY_JSON` selectors. Full discovery
retains the original mapping, scalar, measurement, generation and stream
differential component evidence under `qualification/full-discovery-components/`.
Before execution the
harness checks the same source/native tuples that v4 extracts, together with
its original component groups. These retained native classes must first run
in full discovery, so their evidence directories are not reused by an earlier
stage. Their source-only classes stay in the existing source test tuple.
Inherited production manifests and development compiler alternatives for these
components are removed before the same-run cold bindings are applied.

Full-cost, patch-impact, static-budget and Store-lifecycle native classes retain
their actual same-cold builds, compiler readback records and installed-wheel/bundle
observations in separate evidence directories. CLI discovery's explicit
cold-report setup calls the
original strict fixture builder after the unchanged v4 has produced its cold
report. The original JSON class and selected CLI class each own a separate
fixture directory. The latter also builds and admits the original CLI control
and format images against that same compiler. No pre-existing cold fixture,
development manifest or inherited CLI companion is used. All six new native
classes must first execute in complete discovery and must have complete
ordered successful method observations before supplemental acceptance.

## Original full execution and bounds

The external wrapper invokes the original source-owned script directly:

```bash
python -B source/review-evidence/hia-native-rewrite-20261111/run_hia_qualification_v4.py \
  --source source --output <new-external-directory>/qualification --full
```

The original v4 reproduces all source generators and the language inventory,
checks source contracts and scope, runs the current source workflow selectors,
and executes the original cold replay. If cold succeeds, it runs the language
qualification, current native workflow selectors, all original 27 component
stages, and finally the complete retained `unittest` discovery. Its original
35-stage orchestration, success conditions and per-step receipts are retained.
New tests are reached by full discovery; the v4 component list is not edited.

| Existing bound | Seconds |
| --- | ---: |
| Ordinary source, native and component step | 1800 |
| Outer cold workflow step | 240 |
| Cold qualification owner | 180 |
| Cold cleanup owner | 3 |
| Final complete discovery step | 5400 |

No 5400-second cap is incorrectly placed around the entire multi-stage
orchestrator. The GitHub job ceiling is 360 minutes to include provisioning,
all original stages and evidence upload; it does not change any inner bound.
The ordinary retained supervisors own their started POSIX process groups. The
cold replay retains its separate original subreaper/ECHILD cleanup proof.
The external harness makes no complete-process-tree ownership claim.

A terminal pass requires the original `FULL_RETAINED_PASS`, exact full counts,
zero failures/errors/skips/expected failures/unexpected successes, preserved
complete product source and original harness, and the independent ordered-ID
check described below. Original partial output and failing receipts remain
visible when a prerequisite, component or final suite fails.
`whole_native_delivery_qualified` remains false even after a passing retained
regression; the original v4 does not grant whole-native product qualification.

## Supplemental callers and original CLI group limits

The workflow's separate supplemental step does not insert a stage into v4 or
change its `steps.json`. It requires all 35 original stages to have been reached,
then checks actual ordered full-suite method observations for the retained
component classes. It does not infer native execution from an environment
variable or from a generated source file.

The component modules already run through complete discovery. The independent
qualifier commands in the product workflow are not part of the two tuples that
v4 extracts. The supplemental step runs the missing original
scalar-profile, bounded-memory and generation-retention caller qualifiers,
each with the same `qualification/cold.json`. Generation uses the original
`--require-companion-policies` gate with mapping, scalar and measurement
manifests produced by that full discovery. Their build scopes, cold-report
hashes, complete source manifests, compiler identities and actual image bytes
must match before they can be reused. No development image substitutes for a
missing candidate, and no companion owner is optional in that gate.

For SHA, the existing `tests.test_hia_sha256_stream_transition_equivalence`
native class has already invoked both original and candidate images against
its independent VM observations. Its retained report must show `actualCold`,
the same cold/nested reports and complete source manifest, unchanged compiler
and source, and real public-buffer and alias observations. The supplemental
step invokes the existing `tools/build_hia_sha256.py --candidate sha256_stream`
with that cold compiler. The produced manifest must name exactly the candidate
image hash that the original differential class actually executed. The older
`test_hia_sha256_stream_native` development fixture is not relabelled as cold.

The three additional full-cost, patch-impact and static-budget caller qualifiers
build their images from this same cold compiler and run every declared original
caller module with the retained Python decision bodies forbidden. Reports must retain
identical planned/started/stopped IDs, positive actual native call counts, the
exact image identity and unchanged complete source and bundle inputs.
Static-budget acceptance requires actual calls to all five native owners:
topological order, function bounds, frame rows, resource profile and policy
selection. Its retained Python resource bodies must remain forbidden throughout
the complete original caller modules.

The Store-lifecycle caller qualifier independently admits its frozen four-module,
50-method original inventory and source hashes. It runs all 50 methods under
their existing budgets, binds its actual image to this same cold compiler, and
requires positive native initialization and close observations with no retained
reference calls. The report preserves the precise instrumentation scope: Python
reference bodies are poisoned in the test process; subprocesses inherit the
selected image and retain their original controls. Full discovery separately
retains the complete Store native class, including installed-resource and pinned
worker-bundle observations, before this caller gate can qualify.

Two further commands run the unchanged four-group CLI-discovery qualifier and
the complete ordinary CLI-discovery caller qualifier. Complete discovery alone
does not establish their original per-group deadlines. The four original groups
therefore execute again under their existing 180-second qualification and
three-second cleanup owners, retaining all 61 native frames, six independent
full-buffer VM controls, public byte-API checks and the actual installed wheel.
The selected caller qualifier retains all three methods and twenty native JSON
calls through both ordinary CLI routes. Its real CLI control/format compilation,
JSON fixture, source identities and original process-owner results are checked
again against this run's exact cold report. These are additional observations,
not extra credit in the full-discovery denominator.

All ten supplemental commands use the unmodified product workflow supervisor
with its ordinary 1800-second budget. The original inner limits, including the
CLI compilation and installed subprocess limits of twenty seconds, remain in
force. Reports require complete planned/started/stopped IDs, nonzero exact
counts, zero skips, and preserved captured inputs.
The supplemental result is separate from the original full result; a successful
GitHub job requires both. An original full failure remains a failure even if
these added caller gates pass. The five previously retained component suites
are not repeated by the supplement; the added CLI group and caller executions
are explicitly recorded with their separate original bounds.

The retained v4 plus this supplement does not reproduce every independent step
of the current `hia-core.yml`: the selected mapping and publication-measurement
caller gates remain required in the standard workflow on the same final product
head, and are not duplicated here.

## Independent method-identity observation

The original v4 records complete suite counts but does not instrument unittest
start/stop callbacks. This wrapper does not monkeypatch that runner. Instead,
it freezes each discovered test's actual `str(case)` and first docstring line,
then reads the original full-suite verbose stderr byte stream after execution.

Every recognized method description and its terminal status must occur exactly
once, in the same order as complete pre-discovery. The parser accepts normal
single-line and docstring descriptions and intervening diagnostic lines. It
rejects unknown, duplicate, reordered, truncated or ambiguous descriptions or
status markers. An unparseable log yields an explicit identity-audit failure;
a green original count is never presented as proof of ordered-ID equivalence.
The artifact retains the original stderr, its hash, complete planned IDs,
observed starts/completions, offsets, status candidates and parser errors.
These are log observations, not newly claimed in-process callback receipts.

## Retained original evidence and modes

The always-run collection and upload steps retain evidence even after an early
failure or interrupted execution:

- Original setup, bootstrap, dependency fetch/build and wrapper stdout/stderr.
- All six NDU identity/build/failure receipts and original command evidence,
  the six receipt-selected native images when present, fixed-tool identities,
  readiness logs, preparation records and explicit native environment mapping.
- Full discovery and description lists; every reached original v4 log, step,
  process-owner receipt, cold artifact and component evidence file; original
  qualification and full-suite results if produced; raw source inventories and
  the independent method-identity observation.
- All five executed harness files and selected GitHub run metadata.
- Same-run full-discovery component builds and observations, all supplemental
  commands and process-owner receipts, and their independent result record.
- File sizes, SHA-256 values, original file and directory modes/timestamps,
  missing not-yet-produced paths, and explicit excluded-directory records.

Complete source-reproduction and cold source-export copies are excluded; their
original source manifests and reproduction reports remain. Git metadata,
bytecode caches, upstream checkouts, Cargo caches/target directories, credentials
and a complete environment dump are not collected. Only the six specifically
identified final NDU images are selected from build targets.

The collector retains empty evidence directories and applies original directory
metadata after copying their children. It stores the retained tree in
`original-evidence.tar.gz` using original modes and precise timestamp headers,
then reads back every member and verifies type, size, hash, mode and timestamp.
Only after that verification does it remove its disposable staging copy. All
original audit output remains untouched. The tar preserves executable bits
that GitHub's outer artifact ZIP otherwise normalizes. Download the artifact,
verify its collection receipt, then extract the tar to restore retained modes.
If collection fails before that point, the always-upload step also sees the
existing raw staging evidence and the error appears in the original job log.

## Manual invocation on a provisioned runner

```bash
python -B harness/run-gate.py preflight --target harness/target.json \
  --source source --output "$RUNNER_TEMP/source-before.json"
HIA_GATE_PYTHON=python bash harness/prepare-dependencies.sh \
  "$PWD/source" "$RUNNER_TEMP/native-prerequisites" "$PWD/harness/target.json"
python -B harness/run-gate.py run --target harness/target.json --source source \
  --environment "$RUNNER_TEMP/native-prerequisites/environment.json" \
  --output "$RUNNER_TEMP/full-retained"
python -B harness/run-gate.py supplemental --target harness/target.json --source source \
  --environment "$RUNNER_TEMP/native-prerequisites/environment.json" \
  --full-run "$RUNNER_TEMP/full-retained"
```

Every preparation and qualification output directory must be new and outside
the product checkout. The workflow installs the system/Python prerequisites
before these commands. Keep the original attempt and failures; a later target
or repaired harness is a separately identified run.
