# Real fleet scoped tests and Clippy — completed

The exact published fixture fix at **`dc984bb3b3cb21259f838a31f67a7c2983ea9510`**, tree **`cd388fb79077d62f041c9b0c63b46be24c949d70`**, passed both original repository commands on Linux x86_64:

| Command | Actual result | Command wall time |
| --- | --- | --- |
| `just test -p codex-hepta-fleet --locked` | Exit 0; 41 tests across 2 binaries; 41 passed, 0 failed, 0 skipped; first attempt | 67.259014064 s |
| `just clippy -p codex-hepta-fleet --locked` | Exit 0; no Clippy warning/error; first attempt | 26.554697729 s |

The Clippy recipe expands to `cargo clippy --tests -p codex-hepta-fleet --locked`. It does not contain `--fix`. No `just fix`, lint exemption, hook change, lockfile update, sandbox guard change, source repair, or test retry was used.

The actual passing tests include both `authority_port::tests::allocation_issue_consumes_exact_live_kernel_authority_lease` (which executes the changed helper) and `authority_port::tests::allocation_binding_changes_when_owner_mutation_semantics_change`.

## Source, dependencies and tools

Source was prepared in `/dev/shm/hepta-fleet-qualification-20261028/source` in the host execution view. See `../fixture_scoped_preparation_20261028/` for the complete source preparation and original configuration inventory. Before and after execution, all **1,113 restored real source/metadata files** were verified against the exact Git objects and SHA-256 inventory. The qualification worktree remained clean.

The original NDU checkout remains clean at `4b6391e116949af0c7e59776baead67271856bdb`; the original fixture worktree remains clean at `b3a5db1a43751ad1720e47fae838866e97f64b7d`. Neither was changed by this qualification.

Cargo.lock SHA-256 remained:

`8354b4cbdf14389db7aa5508e2ed5b524fc2d4c4ea0ecb475955c933f8bea389`

The fixed fixture SHA-256 remained:

`78358f02576bd5442473d432db5bbf7273ff76c3b95d05591f2459c9e0f354db`

The independent cache downloaded 61 registry crate archives; every downloaded archive's SHA-256 was checked against the unchanged original lockfile. Exact versions and checksums are retained in `LOCKED_ARCHIVES.json`. Cargo performed the original locked Git-dependency resolution normally. No different-version bridge cache was substituted.

Actual tools: Rust/Cargo 1.95.0, Clippy 0.1.95, just 1.59.0, cargo-nextest 0.9.103. Compilation used one job and disabled incremental caching; original Cargo profiles, workspace metadata, Clippy lints, nextest configuration and source remained intact. Actual tests were run by the repository's `just test` / `run-nextest.py` path, not by a synthetic harness or direct `cargo test`.

## Warnings and evidence recovery

The original nextest configuration produced a warning that `profile.local.inherits` is unknown to nextest 0.9.103. The repository's scoped `--no-deps` metadata path also produced package-ID warnings for dependency artifacts. Both kinds of warning remain in the full test log. No warning was suppressed, configuration removed, or unexecuted test reported as passing. The original nextest output reports and individually lists all 41 passing tests.

The unchanged local profile did not produce a `junit.xml`. An initial evidence-finalization assertion expected that file and stopped; this tooling-only attempt is recorded in `FINALIZATION_ATTEMPT_001.json`. Recovery used the original successful nextest log and its 41 individual PASS lines, retained in `TEST_CASES.json`. No JUnit was synthesized, and neither tests nor Clippy were rerun to alter the evidence format.

Post-run hashes of the two ELF test binaries are recorded in `RESULT.json` as an artifact inventory. These are not deployment receipts or a claim that a new runtime loader was qualified.

## Resources and scope

The final target directory contained approximately 371 MB of files; the independent Cargo home contained approximately 315 MB. Host tmpfs retained about 2.63 GB available. The shared cgroup's OOM and OOM-kill counters did not increase during qualification. Command wall times above include their actual dependency/download/build work; they are not a performance comparison or a total engineering-cost claim.

This result establishes that the **real fleet crate and changed test helper compile, pass the actual scoped tests, and satisfy local Clippy under the recorded environment**. It does not replace the required remote Bazel gate, establish Windows/macOS success, or resolve the unknown cargo-deny and unrelated Windows test failures. Earlier terminal failures remain preserved separately.

## Files

- `RESULT.json`: exact result, source/config identities, tests, Clippy, warnings, binary inventory and resource observations.
- `test-001.log` / `test-001.json`: complete original test output and invocation/identity record.
- `clippy-001.log` / `clippy-001.json`: complete original Clippy output and invocation/identity record.
- `TEST_CASES.json`: the 41 exact passing test records extracted from the retained log.
- `LOCKED_ARCHIVES.json`: every downloaded registry archive checked against the original lock checksum.
- `EXECUTION_PREFLIGHT.json`: source identity, installed tool versions and initial cgroup/storage observations.
- `FINALIZATION_ATTEMPT_001.json`: the missing-JUnit evidence-format recovery.
- `INDEX.json`: file hashes and sizes for independent verification.
