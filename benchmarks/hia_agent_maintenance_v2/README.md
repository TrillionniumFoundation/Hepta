# Authored API-maintenance pilot v2

This is a new prospective cohort selected with `--campaign maintenance-v2`.
It reuses the existing maintenance runner, public catalog/check/final RPCs,
strict Codex transport, terminal hidden evaluation and complete request-cost
accounting. The earlier maintenance-v1 protocol, task definitions, freeze and
negative results remain unchanged. Selecting v2 never overwrites that freeze.

The two new authored tasks are:

| Task | Required maintenance | Resource requirement |
| --- | --- | --- |
| `cursor_api_v2` | Replace modulo cursor advance with a 0..1000 bounded API and an invalid-cursor sentinel | Preserve the exported signature and avoid overflow/traps |
| `owned_record_api_v2` | Update the owned record's length, index, byte computation and return tag | Actually allocate/store/load/end loans/explicitly release the same owner |

The cohort is exactly two tasks × two requested model selectors
(`gpt-6.1-sol`, `gpt-6-luna`) × two languages (HIA, Rust): eight cells.
The requested model tiers are compared separately, and no cell may be replaced
after its outcome is observed. These author-designed tasks are not a
representative sample of real third-party API/library upgrades.

The resource task uses the existing HIA VM operation witness and safe Rust Vec
observer. The Rust observer now has a trusted `begin_expected` entry for the
new contract. Its original `begin(x,y)` entry and original buffer-resize
semantics are retained. Only the trusted native driver receives the expected
resource tuple; candidate code still receives only `x` and `y`, is nested under
the existing restricted source profile, and cannot call observer bookkeeping.
This observes the selected Vec API, not every machine allocation or store.

Each task has supplied initial programs, six disclosed public cases, 72
terminal hidden cases and an independent mathematical oracle. Author reference
repairs are control inputs only. No reference repair or hidden input enters
a model prompt. Controls must accept the reference repair in both languages
and reject wrong output, unchanged initial behavior, wrong signature and
missing explicit resource release as applicable.

## Register and run

The protocol names actual tool locations. The freeze binds their complete
file identities, the task sources, shared runner, resource observer, compiler
sources, catalogs and public prompts. A tool relocation/change requires a
new pre-generation registration; it cannot silently reinterpret an old run.

```sh
python tools/qualify_hia_agent_maintenance.py --campaign maintenance-v2 \
  controls --output /new/controls/directory

# Commit all implementation/protocol sources before freezing.
python tools/qualify_hia_agent_maintenance.py --campaign maintenance-v2 \
  freeze --controls /new/controls/directory/RESULT.json

# Commit the new FREEZE.json; obtain the existing independent exact-freeze
# review receipt, then use that real registration commit.
python tools/qualify_hia_agent_maintenance.py --campaign maintenance-v2 \
  run --output /new/model-run/directory --review /path/to/review.json \
  --registration-commit EXACT_REGISTRATION_COMMIT
```

Author controls issue zero model requests. A successful control run proves
only that the selected tasks, evaluator and reference controls execute on the
registered tools. It is not evidence of an Agent completing these tasks.

All request usage fields, failed/repair attempts, compiler/check/native wall
time and terminal failures remain in the cost numerator. Cached input is not
added twice. Per-success costs are unavailable when there is no successful
delivery or usage is incomplete. Human review time remains unknown; it is
never replaced with zero. The descriptive within-model gate is unchanged and
cannot establish general productivity or full human/development-cost savings.

## Zero-generation readiness before a new registration

The optional `preflight` command checks executable identities, actual app-server
initialization, and small HIA→LLVM/native and Rust/native XOR programs without
sending a thread, turn, model or maintenance-task request. It keeps its output
outside the source checkout and preserves any existing `FREEZE.json` bytes.
Supply current tool paths explicitly; they never reinterpret paths in an old
protocol or replace a prior failed cell.

```sh
python tools/qualify_hia_agent_maintenance.py --campaign maintenance-v2 \
  preflight --output /new/outside-source/preflight \
  --codex /absolute/current/codex \
  --clang /absolute/current/clang --rustc /absolute/current/rustc
```

`--isolate-sqlite` records a per-invocation `sqlite_home` override below that
output directory. Independently, `--isolate-logs` sets the documented `log_dir`
to a fresh `codex-logs` child of that same admitted output. Both options are
Boolean; neither accepts an arbitrary directory, config key, home override or
thread-store implementation. Existing runtime children or symlinks refuse.
These options do not change `HOME`, `CODEX_HOME`, user configuration,
credentials, sandbox permissions or any frozen generation command. They can
diagnose local SQLite/log initialization separately from later startup failures.
Their path settings cannot relocate managed cloud storage or waive its policy.
The app-server's complete raw process output remains in `app-server/` and the
summary is `RESULT.json`; unknown events, missing initialization ACK, nonzero
exit, unconfirmed cleanup, tool/path drift and probe-source drift refuse.
The result records requested overrides and direct regular runtime file
names/sizes, with at most 128 directory entries inspected and no recursive
walk; database payloads are not read. Exclude those runtime directories from evidence
exports. A created SQLite/log file does not establish a completed startup ACK.

Passing startup/native probes does not verify model access, usage reporting or
coding productivity. The report always keeps `model_access_verified=false`,
`registered_campaign_run_authorized=false`, and `new_registration_required=true`.
A changed environment requires a new source/protocol/tool registration and
independent review before a new cohort. The earlier eight v2 initialization
failures and unknown costs remain historical results, including when a later
readiness probe passes. Neither a smoke result nor known request count zero is
substituted for complete model or human-cost evidence.

The historical v2 FREEZE and its eight initialization-failure records remain in the separate archived delivery. They are not republished with this source-only integration. This checkout has no generation authorization from that archive; any future run requires fresh registration and independent review on its actual tools and source.
