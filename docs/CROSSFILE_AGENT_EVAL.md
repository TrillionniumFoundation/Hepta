# Cross-file agent evaluation: a bounded 2 × 2 study

This is an executable experiment kit, **not evidence that an AI codes better in
Hepta**. The committed qualification uses deterministic reference-edit scripts.
It performs real compilation and native execution, reports **AI runs = 0**, and
cannot enter the provider comparison as model evidence. The original
`experiments.agent_eval` single-function harness and its evidence are unchanged.

The new package is `experiments.crossfile_eval`. It separates the language factor
from the semantic-edit-tool factor with four preregistered arms:

| Arm | Language | Editing interface |
| --- | --- | --- |
| `rust_plain` | Rust | Read files, replace complete editable files, compile, public tests |
| `rust_semantic` | Rust | Read files, query function/body/declaration nodes, replace those nodes, compile, public tests |
| `hepta_plain` | Hepta | The same plain-file interface |
| `hepta_protocol` | Hepta | The same public semantic operation set, executed by the production `hepta.workspace` / `hepta.patch.v4` store |

All four arms share nominal input/output/total token caps, wall-time caps,
observed protocol tool-call caps, native profiles, task instructions, public
cases, and private expectations. Language-specific reference text and source
lengths differ; this is not a claim of identical prompt token counts. Actual
provider receipts must account for prompts, tool responses, and generated text.

## Five real multi-module tasks

Each language has a frozen main module, two editable modules, a flawed starter,
and a trusted reference. Each reference changes both editable files. The API and
ownership tasks also compile a client of the required new interface, so keeping
the obsolete implementation while changing only its output is insufficient.

| Task | Editable modules | Target behavior | Private inputs per language |
| --- | --- | --- | ---: |
| `api_migration` | pricing, receipt | Change a price struct and function signature, return `Result`, update the caller, propagate validation errors and discounts | 75 |
| `owned_result` | storage, service | Return `Result<Packet,i32>` where Packet owns bytes; initialize data, consume success/error branches, free on early error, preserve real allocation refusal | 24 |
| `native_bridge` | foreign, adapter | Call actual C and C++ objects through an explicit C ABI, pass a struct by value, propagate native error status | 56 |
| `resource_cancel` | worker, service | Transfer a buffer to an actual worker, observe cancellation when requested, release it, and join before returning | 14 |
| `defect_repair` | data, search | Fix duplicate-data generation and half-open lower-bound search, including empty/full ranges and keys beyond either edge | 143 |

There are **312 private native inputs per language**, or **1,248 executions for
the 20 four-arm reference qualification runs**. These are test inputs, not 1,248
independent coding tasks. The task set contains five coding tasks.

Both starters first compile using their original API. All ten then fail the
target validation. In particular, the uncorrected cancellation task really
times out; it is not replaced by a mocked timeout result. Qualification checks
both facts as well as all 20 reference outcomes.

### Native instrumentation and independent expectations

The parent evaluator computes expected values using independent Python
arithmetic and `bisect`. It does not run one language implementation to derive
the other language's expected answer. Reference code is separate from the
oracle. Hidden case lists and expected values never enter the adapter bundle or
the compiler/runtime capsule; inputs are sent to the finished native program
over stdin only after the adapter process group has been terminated.

The submission is compiled to a separate `rlib` crate before being linked into
the trusted driver crate. Candidate modules cannot name or mutate the driver's
allocator counters or allocation-refusal state through Rust module visibility.

The native wrapper observes more than return values:

- A global allocator counts allocation and release of the task's requested
  `u8` buffer layout. Owned-result cases include eight real allocator refusals
  per arm. A refusal returns a null pointer for that layout; correct code returns
  the error and continues. Infallible allocation aborts and fails the task.
- GNU linker wrappers count successful `pthread_create` and `pthread_join`
  calls. The cancellation task requires one of each for valid lengths, plus
  release of its input buffer. A calculation that fabricates the expected result
  without creating a thread fails.
- The frozen C and C++ libraries count calls independently. The C++ object uses
  `std::vector` and `std::accumulate`, with exceptions caught before the C ABI.
  Reimplementing its arithmetic in the candidate without calling either library
  fails even if the returned number is right.

The instrumentation is deliberately bounded. It checks the requested byte
buffer layout, not all possible heap objects or all leak classes. Thread
wrapping is a Linux/pthreads/GNU-linker host profile. The C++ task tests an
explicit C wrapper around real C++ code; it is not an automatic translator or a
claim of general C++ ABI support. Cooperative cancellation has a test timeout,
not a scheduler-independent latency proof. Native overflow and bounds checks
remain enabled, optimization is `-O3`, and panic behavior is abort in both arms.

## Equal semantic tools and their limits

The public JSONL envelope is `hepta.crossfile_study.v2`. Both semantic arms
expose the same function/body/declaration operations and exact current-version
preconditions. Plain arms replace complete editable files. The task authorizes
interface migration only for `api_migration` and `owned_result`; the other tasks
preserve their declaration interfaces in all four arms. Hepta uses the actual
production interface representation, including borrowed return modes. Rust
conservatively compares the bounded declaration signature tokens.

Rust sessions and Hepta plain sessions prepare a complete candidate, run native
validation and publish a checked in-memory map. The Hepta protocol arm creates
an actual production workspace in a separate persistent capsule. Each operation
runs in a new bounded child process; the store survives between those processes:

1. `workspace.initialize` captures the public bundle and validates its complete
   source graph with the selected native toolchain.
2. `inspect_workspace` supplies real production node IDs. The common
   `replace_declaration` operation maps to the corresponding production
   function/struct/enum replacement.
3. `apply_workspace_patch(apply=False)` prepares an immutable native-validated
   snapshot without changing `CURRENT`. The request binds the original version,
   interface hash, authorized interface policy and native profile.
4. The independent task compiler checks that exact prepared source map, including
   the new API client contract. The trusted contract probe is never written into
   the production store.
5. The identical v4 request is submitted with `apply=True`. Prepared and committed
   version IDs must match. Production fsync/journal/CURRENT publication provides
   the actual consistency boundary; the coordinator cannot substitute a cached
   source assignment for publication.
6. A separate process calls `recover`. After the adapter exits, another `pin`
   reads the final published bytes, which become the sole scoring input.

The namespace gate precedes initialization. Initialization, source inspection,
preparation, native task validation, publication, recovery and final pin share
one wall deadline; setup does not reset the budget. `initialization_seconds`,
`validation_seconds`, per-RPC timings and `agent_wall_seconds` record that cost.
The start frame also reports the remaining budget after initialization. Hidden
scoring is evaluator overhead outside the interaction deadline.

A failed preview or task contract leaves `CURRENT` unchanged. A child timeout or
uncertain commit is a fatal attempt error. It cannot be reported as a successful
rollback followed by continued edits against stale parent state. Read/pin checks
keep the parent cache consistent with the store. Reports distinguish the source
content hash (`submitted_sha256`) from the production snapshot version
(`submitted_version`), whose identity also includes the entry and native profile.
Exact UTF-8 source bytes, including CRLF line endings, are retained.

The public semantic operations are the same for both languages:

```json
{
  "op": "replace_body",
  "target": "search.rs",
  "node": "ID_FROM_query_nodes",
  "replacement": "{ return 0; }"
}
```

The other operations are `replace_function` and `replace_declaration`.
Declarations include functions, structs, and enums. Each replacement must
reparse/index as exactly one node of the promised kind; closing a body and
appending a new function is rejected. Node IDs are tied to exact file contents
and must be queried again after relevant changes.

Hepta uses its actual parser. Rust uses a **bounded lexer and delimiter index,
not a complete Rust AST or language server**. It recognizes comments, nested
block comments, raw/quoted literals, character escapes, lifetimes, and balanced
delimiters, and indexes the supported top-level function/struct/enum items.
External `mod`/`use` declarations and the fixture's `extern "C"` blocks are
recognized support. Inline modules, top-level macros, impl/trait blocks, scoped
visibility, const-generic/where-clause declarations and other unimplemented
top-level forms are rejected. Function bodies may use ordinary Rust expressions,
local declarations and macros; rustc remains authoritative. Both Rust arms use
this same bounded source profile, so the plain arm is not granted an unbounded
language profile that the semantic arm cannot represent.

The fourth arm now exercises production initialization, inspection, semantic
edits, interface migration, whole-graph native validation, durable publication,
recovery and final pin. `production_workspace_v4_exercised` becomes true only
when recorded preparation, publication, recovery and final pin actually complete.
`workspace_evidence.py` cross-checks the request hashes, version chain, native
profiles, validation receipts, journal and final source identity. A label alone
cannot satisfy the qualification gate.

The five tasks do not exercise expression/statement edits or deliberately kill a
transaction during publication. The production store has separate real
process-death regression tests. Task qualification demonstrates persistence
across RPC worker exits and actual recovery calls; it does not relabel those
normal exits as crash injection. The temporary store is removed after the sample.
Historical v1 study evidence remains evidence of its original in-memory protocol;
it is not retroactively evidence of production v4.

## Provider protocol and isolation

A provider adapter is a standalone directory outside the evaluator tree. Its
entry command is an argv JSON array, for example:

```json
["python3", "{adapter}/provider_adapter.py"]
```

The runner copies this bundle into a fresh capsule and communicates over JSONL.
The start frame contains only the public task, source files, editable paths,
references, exact model identity, budget, available tools and current version.
The adapter emits tool frames, one final frame, or an explicit abort frame. Every frame must repeat
`request_id`, `task_sha256`, `base_sha256`, `model` and `adapter_kind` from the
request, and provide cumulative usage:

```json
{
  "input_tokens": 123,
  "output_tokens": 45,
  "total_tokens": 168,
  "tool_calls": 1,
  "provider_calls": [{
    "request_id": "ACTUAL_PROVIDER_REQUEST_ID",
    "model": {"provider": "PROVIDER", "name": "MODEL", "revision": "EXACT_REVISION"},
    "input_tokens": 123,
    "output_tokens": 45,
    "raw_usage": {"ACTUAL_PROVIDER_USAGE_FIELD": 123}
  }]
}
```

This is a schema illustration, not a receipt or evidence. Each actual provider
call requires its own unique receipt; totals must equal the cumulative receipt
sum. Earlier receipts cannot disappear or change. Model/revision mismatch,
missing usage, credential-shaped metadata, budget overrun, duplicated tool IDs,
and stale snapshots are rejected. Moving revision aliases such as `latest` are
not accepted. Comparison also enforces exclusive `(provider, request_id)`
receipt ownership across all planned samples; every sample sharing a recycled
receipt is invalidated while remaining in the denominator. Receipts are
**adapter-attested, not independently verified against
a provider billing API**. Off-protocol adapter operations and provider-side
transport hard caps are not independently verified either; reports say so.

Tool frames use `kind: "tool_call"`, a unique `call_id`, `tool`, and `arguments`.
The shapes are:

| Tool | Arguments |
| --- | --- |
| `read_file` | `{"path":"storage.rs"}` |
| `check`, `public_test`, `query_nodes` | `{}` |
| `replace_files` | `{"expected_version":"CURRENT", "files":{"storage.rs":"complete source", "service.rs":"complete source"}}` |
| `replace_nodes` | `{"expected_version":"CURRENT", "edits":[...]}` |

The final frame uses `kind: "final"` and the current `version`; it does not
contain another unvalidated source submission. The hidden native oracle runs
after the adapter is closed. Failed compilation, abort, invalid output, timeout,
and missing output cannot be scored as success.

The start frame advertises `capabilities.abort_frame: true`. An abort echoes the
same frozen identities and carries `kind: "abort"`, `usage`, `usage_complete`,
and `error: {"code": "E_STABLE_CODE", "message": "fixed non-sensitive text"}`.
`usage` may be the last valid cumulative receipt prefix or null. Null does not
erase previously validated costs and cannot mean zero cost. Abort consumes no
extra public tool call and always ends in `attempt_failed`, without hidden
scoring. Arbitrary provider error text is not persisted; the coordinator records
the stable code and its own fixed explanation.

An abort may set `usage_complete: true` only when it supplies valid nonempty
receipts and has no pending/unverified provider request. A complete paid response
that cannot produce a usable edit can therefore retain its known complete cost
while failing the task. Valid over-cap receipts are also retained before the
attempt fails. No receipt, malformed usage, or a
`pending_provider_request: {client_request_id, request_id, receipt_verified:false}`
keeps total costs incomplete. Pending metadata is never counted as a receipt.
Completeness remains adapter-attested, as with ordinary final frames.

Provider mode requires functioning bubblewrap namespaces for the adapter,
frontend, compiler and candidate execution. It fails closed before invoking the
adapter or a workspace if the probe fails. Both languages' candidate parsing,
indexing, materialization and compilation run in bounded child capsules; no
candidate parser runs in the trusted parent. The workspace capsule contains only
the Hepta package, a narrow RPC helper, and the public source/store. The adapter
capsule is separate. There is **no provider-mode bypass switch**. Fixture
qualification is a separately marked trusted-script mode with process separation
only and zero provider receipts. A fixture cannot report model tokens or become
AI-comparison-eligible. Environment variables are cleared except explicitly
requested adapter variable names; candidate execution does not inherit them.
Network access to a configured provider is explicit with `--network`.

The private oracle is hidden from an active adapter capsule, not permanently
secret from someone who can read this repository. No claim is made that public
release of this pilot prevents future benchmark contamination.

## Running and freezing an experiment

Use an installed **Rust 1.90.0** via `RUSTC` or `--rustc`; GCC and G++ are also
required, together with GNU `ar` and the GNU linker. Native support uses a whole
static archive ahead of runtime libraries so pthread observation symbols are
resolved consistently. The explicit sysroot, GNU linker arguments and archive
profile are recorded in compiler identity. No procfs mount is required.
The manifest freezes the starters, references, native support, public
cases, private oracle and language references. Plans freeze the taskset,
evaluator sources, native compiler identities, supported host profile and shared
budget. V2 plans also freeze one adapter configuration per exact model, shared
by that model across all arms: bundle hash, argv, executable hash, passed
environment **names**, and network choice. Credentials never enter the plan.
The isolated copied bundle is rehashed before execution. An unconfigured plan
has `provider_ready:false` and cannot start provider samples. A changed compiler or experiment implementation requires a new plan.
Compiler identity is the recorded binaries/version/profile, not a hash of the
entire operating system and every runtime library.

```bash
python -m experiments.crossfile_eval verify
python -m experiments.crossfile_eval probe
python -m experiments.crossfile_eval qualify-fixtures --output qualification-001.json
python -m experiments.crossfile_eval qualify-workspace --output workspace-qualification-001.json
python -m experiments.crossfile_eval plan --models exact-models.json \
  --adapter-configs adapter-configs.json --replicates 3 --output plan-001.json
python -m experiments.crossfile_eval run --plan plan-001.json --model-index 0 \
  --task owned_result --arm rust_semantic --replicate 0 \
  --adapter-dir /absolute/provider-adapter --command adapter-command.json \
  --network --pass-env PROVIDER_API_KEY --output run-001.json
python -m experiments.crossfile_eval compare --plan plan-001.json \
  --reports run-001.json --output comparison-001.json
```

`adapter-configs.json` is an array, one entry per model, with exactly these fields:

```json
{
  "model": {"provider":"PROVIDER", "name":"MODEL", "revision":"EXACT_REVISION"},
  "bundle_sha256": "ACTUAL_64_HEX_CONTENT_HASH",
  "command": ["/usr/bin/python3", "{adapter}/provider_adapter.py"],
  "executable_sha256": "ACTUAL_64_HEX_EXECUTABLE_HASH",
  "passed_environment_names": ["PROVIDER_API_KEY"],
  "network_requested": true
}
```

These placeholders illustrate the shape and cannot be submitted as hashes or
provider evidence. The reference OpenAI adapter exporter in
`tools/provider_adapter/README.md` creates the actual standalone bundle and
configuration, with metadata outside the bundle to avoid a self-referential
hash. Model identities are operator supplied. No API credentials or real model
runs are bundled with this repository.

At least two distinct exact provider model identities are required by the plan.
One replicate produces 40 planned cells: two models × five tasks × four arms.
Schedule order is frozen and shuffled with a recorded seed. Every cell starts a
fresh adapter session. All samples share the same nominal caps; the default is
32,000 input tokens, 12,000 output tokens, 44,000 total tokens, 300 seconds and
32 observed protocol tool calls. These limits are configurable only when making
a new plan. A malformed or mismatched run does not create a smaller denominator.

Every output path is opened exclusively. Existing plan, qualification, run,
replay or cost files cannot be overwritten by these commands. A report has a
content checksum, which detects changed bytes but is not a trusted signature.
Duplicate records for one planned sample invalidate that sample rather than
selecting a best retry. The caller must preserve all attempt records; this
local-file tool cannot prove an investigator has not withheld an unreported run.

Saved candidates can be rescored without a provider call:

```bash
python -m experiments.crossfile_eval replay --run run-001.json --output replay-001.json
```

A fixture needs `--trusted-fixture`; replay remains ineligible as a new AI run.
Task, evaluator, compiler and submitted-source identities must still match.

## Costs, failures and interpretation

`compare` always reports the complete planned denominator. Failed tasks,
timeouts, blocked attempts, malformed reports and missing cells contribute zero
successes. Duplicated samples do not permit selecting a successful retry. Known
token usage on a failure remains a cost, including validated receipts that
exceeded a token cap. If a timeout loses the final receipt, known usage is a
partial observation and total token cost remains null. It is not filled with
zero, and no complete tokens-per-success estimate is emitted.
`validated_tool_calls` identifies the last verified receipt prefix separately
from all observed frames. A later over-budget or duplicated tool request cannot
erase costs already validated before that rejected frame.

Human time and monetary cost are optional observations, never inferred from
wall time or invented from token counts:

```bash
python -m experiments.crossfile_eval cost --run run-001.json \
  --human-seconds 93.5 --human-observer "recorded review timer" \
  --usd 0.42 --price-source "provider billing receipt identifier" \
  --output cost-001.json
python -m experiments.crossfile_eval compare --plan plan-001.json \
  --reports run-001.json --costs cost-001.json --output comparison-002.json
```

The numbers above are illustrative commands, not measurements. Omitting an
observation leaves it `null`; explicitly recording zero requires the same source
fields as a positive observation. One total cost record is accepted per exact run
record. Duplicated totals are ambiguous and rejected. Tables distinguish known
partial costs from complete totals, and report costs per successful task only
when the relevant total is complete and at least one task succeeded.

The descriptive contrasts are Rust semantic minus Rust plain, Hepta protocol
minus Hepta plain, Hepta minus Rust under each interface, and the interaction
`(Hepta protocol − Hepta plain) − (Rust semantic − Rust plain)`. No contrasts are
reported as measured AI results when there are zero attested provider attempts.
Incomplete matrices remain `not_qualified`, even though their planned
denominators are still displayed. Complete token, human-time and monetary-cost
coverage are separate flags.

Five hand-built systems tasks are a pilot, not a random sample of software work.
This implementation reports descriptive outcomes and costs, without population
significance claims, a general productivity claim, or a claim that either
language is faster than Rust. Both use rustc for final native code generation.

## Qualification and historical evidence

The appended records are
`experiments/crossfile_eval/evidence/fixture_qualification_v4_20261024.json`
and `experiments/crossfile_eval/evidence/workspace_qualification_v4_20261024.json`.
They freeze their own taskset, evaluator and compiler identities. The first uses
the explicitly marked trusted process-separation fixture mode; the second uses
real namespace isolation for every frontend/workspace/native child.

The new `qualify-fixtures` command requires 20 successful reference-script runs,
ten compiled starters that fail the target tests, 1,248 passing private native
input executions and **five validated production v4 transaction traces**. All
provider token counts and AI-run counts remain zero. Human time and monetary
cost remain null. The final source/evaluator/toolchain identities belong to the
new qualification; earlier evidence is retained without modification.

`qualify-workspace` separately requires all five Hepta tasks to execute their
actual persistent protocol chain under `fixture=False` namespace isolation,
followed by 312 passing private native inputs. It creates no provider adapter,
no fake provider receipt and no model call. An unavailable namespace produces
`environment_blocked` with the probe error; there is no fixture-mode fallback.
`--execution-context` can annotate the outer operator environment. This annotation
is explicitly not automatic host attestation.

The managed default outer command sandbox in this session rejects namespace
creation with `NETLINK_ROUTE: Operation not permitted`. Authorized commands
outside that outer sandbox can create the required separate namespaces; the
successful qualification still uses the unchanged restrictive bubblewrap policy,
empty `/proc`, narrow read-only interpreter/toolchain mounts, no network, and no
host project/credential mounts. A successful probe in that context does not mean
the default outer context works. Each qualification records its actual probe and
whether every workspace RPC required namespace isolation.

The historical `fixture_qualification_20261024_2.json` records the corrected
in-memory v1 study: 20 reference runs, ten failing starters, 1,248 passing inputs,
and zero AI calls. The still-earlier `fixture_qualification_20261024.json` is
retained but was superseded after an independent audit found shared-crate
allocator-counter access and cross-sample receipt reuse. The accompanying
`qualification_review_20261024.json` records that correction. Neither historical
record is relabeled as production-v4 evidence.

`tests/test_crossfile_eval.py` preserves real leak, infallible-allocation abort,
missing-cleanup, fake-native-call, fake-thread and counter-spoof negative tests.
`tests/test_crossfile_protocol_v2.py` adds actual persistent transactions, failed
partial migrations, failed target contracts, fresh final pins, CRLF identities,
fatal transport failure, frozen adapter configuration and abort-cost accounting.
Synthetic receipts exist only in offline unit tests and are never published as
AI experiment evidence. No real four-arm AI comparison has yet run, and no Hepta
productivity advantage has been established.
