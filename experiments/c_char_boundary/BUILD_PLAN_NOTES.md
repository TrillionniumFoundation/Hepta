# Isolated request-lifecycle experiment

`build_plan.execute(Request(...))` is experimental Python orchestration, not a
production CLI option. It adds no production files or automatic fallback. The
request is admitted before graph loading/probing: only check/build/run, C backend,
native bin, the selected char profile, and the fixed qualified options. The
existing one-header, plain-char scalar/single-pointer boundary is unchanged.

Every call loads a fresh graph with its requested lock policy, creates a private
importer instance and live Prepared session, and performs final native compilation
inside that lifetime. Eligible externs must originate in the single imported
module; manual externs and exports are rejected. Import aliases retain origins.
The original header, metadata, source graph and compiler paths are protected from
output replacement, including external original headers and symlink aliases.
All native dependencies observed by the final compiler are added to the protected
set before staging, including implicit forced includes. Immediately before
publication, observed dependency hashes and source/compiler identities are
rechecked and the staged artifact must match the final native artifact hash. Build publication uses a staged file and atomic replacement only after successful
final linking. Check/build do not execute the user program. Run executes once,
returns actual stdout/stderr/exit status, and caps execution at 30 seconds or the
request's remaining time, whichever is smaller.

A single monotonic deadline and aggregate output/invocation quota cover native
identity queries, importer probes, final C compilation/linking and program runs.
The existing bounded capture implementation handles each native subprocess;
remaining time and output allowance are not reset between calls. Deadline checks
also surround Python preparation and publication. This is not a hard real-time
bound: synchronous Python parsing/file operations are not preempted, and confirmed
process cleanup can take additional time. Capture is not a filesystem/network
sandbox and does not prove that privileged/session-escaping descendants terminate.

The original importer has no injectable runner API. This experiment loads that
same trusted repository file into a request-private module and replaces only that
module's native-process hook. It does not monkey-patch production globals. The
module is removed after every outcome. The optional underscore-prefixed Prepared
arguments are test/experiment plumbing, not serialized capabilities or supported
public compiler APIs. Production integration would need a reviewed explicit
runner interface rather than adopting this module-loading technique unexamined.

## Evidence and remaining gaps

`python -m unittest experiments.c_char_boundary.test_build_plan -v` contains 20
real/spy controls. They cover invalid requests before load/probe, locked rejection,
check/build versus a demonstrably aborting artifact, run output and exit behavior,
manual/export origin refusal, protected output aliases, failed final linking and
cleanup, source mutation, same-process fresh requests, cumulative budgets, actual
infinite-loop termination, actual output flooding, native invocation limits,
private importer cleanup and successful imported aliases. No fake user-program
execution substitutes for the positive native tests.

This is not completion of all production integration gates. In particular:

- The loaded-graph size quota is an admission check **after** the existing loader
  reads/parses source. It is not a bounded-memory hostile-input parser. Header size
  is checked before prototype preparation, but synchronous filesystem/compiler
  identity reads still need production-grade bounds and stable-read semantics.
- The isolation tests reject missing-lock projects; a full valid-package-lock
  acceptance/mutation matrix remains to be qualified for a production entry point.
- Diagnostics remain Python exceptions in this experiment, not a finalized CLI
  error/report schema. No shipped CLI behavior is claimed.
- Output atomic replacement is not a power-loss transaction or an atomic snapshot
  across mutable sources/compiler/sysroot. Dependent native files remain observed
  after compilation; no dependency authenticity or unchanged-system proof is made.
- No source-only emission, retained debug bundle, arbitrary link options, mixed
  headers, multiple native modules or additional artifact kinds are admitted.
- Foreign effects and pointer/ABI obligations, including external binary behavior,
  remain assumed. This wrapper does not extend the ABI/platform scope qualified
  by #612. Its new request lifecycle still requires independent review and hosted
  native x86_64/AArch64 verification before claiming matrix coverage.


Local prepublication validation executed 75 unique tests: 20 lifecycle controls,
6 integration-gap characterizations, 30 original prototype tests, and 19 importer
regressions. 74 passed and only the actual Rust reference skipped for absent rustc.
The hosted workflow now requires all 75, no skips/expected failures/unexpected
successes, on exact HEAD with Rust1.90 and native GCC x86_64/AArch64. Its results
are pending; #612's earlier green matrix does not qualify this new orchestration.
