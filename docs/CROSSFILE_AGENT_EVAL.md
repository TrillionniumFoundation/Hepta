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
| `hepta_protocol` | Hepta | The same semantic operation set and snapshot/validation rules |

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

`StudySession` implements a separate `hepta.crossfile_study.v1` protocol. Every
snapshot identifies the complete map of file paths and source hashes. A mutation
must name the exact current version. It prepares all edits, runs complete native
validation, and publishes the entire map with one parent-process assignment only
if validation succeeds. A partial API migration, stale node, overlapping edit,
scope escape, or compiler failure leaves the current map unchanged.

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

The `hepta_protocol` arm exercises this intersection, **not the complete
production `hepta.patch.v4` workspace store**. It does not measure expression or
statement edits, on-disk atomic CURRENT publication, crash recovery, durable
compare-and-swap, or production workspace inspection. Its report explicitly
sets `production_workspace_v4_exercised` to false. A later experiment that uses
additional production capabilities needs a new, clearly different plan; these
results must not silently be relabeled as that experiment.

## Provider protocol and isolation

A provider adapter is a standalone directory outside the evaluator tree. Its
entry command is an argv JSON array, for example:

```json
["python3", "{adapter}/provider_adapter.py"]
```

The runner copies this bundle into a fresh capsule and communicates over JSONL.
The start frame contains only the public task, source files, editable paths,
references, exact model identity, budget, available tools and current version.
The adapter emits a tool frame or one final frame. Every frame must repeat
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

Provider mode requires functioning bubblewrap namespaces for the adapter,
frontend, compiler and candidate execution. It fails closed before invoking the
adapter if the probe fails. There is **no provider-mode bypass switch**. Fixture
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
required. The manifest freezes the starters, references, native support, public
cases, private oracle and language references. Plans freeze the taskset,
evaluator sources, native compiler identities, supported host profile and shared
budget. A changed compiler or experiment implementation requires a new plan.
Compiler identity is the recorded binaries/version/profile, not a hash of the
entire operating system and every runtime library.

```bash
python -m experiments.crossfile_eval verify
python -m experiments.crossfile_eval probe
python -m experiments.crossfile_eval qualify-fixtures --output qualification-001.json
python -m experiments.crossfile_eval plan --models exact-models.json --replicates 3 --output plan-001.json
python -m experiments.crossfile_eval run --plan plan-001.json --model-index 0 \
  --task owned_result --arm rust_semantic --replicate 0 \
  --adapter-dir /absolute/provider-adapter --command adapter-command.json \
  --network --pass-env PROVIDER_API_KEY --output run-001.json
python -m experiments.crossfile_eval compare --plan plan-001.json \
  --reports run-001.json --output comparison-001.json
```

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

## Current evidence

`experiments/crossfile_eval/evidence/fixture_qualification_20261024_2.json` records
20 successful reference-script qualification runs, ten compiled failing
starters, and 1,248 passing private native input executions. All provider token
counts and AI-run counts are zero. Human time and monetary cost are null.

The earlier `fixture_qualification_20261024.json` is retained as historical
evidence, not rewritten. A subsequent independent audit demonstrated that its
shared-crate driver allowed Rust submissions to set allocator counters and that
cross-sample receipt reuse was not rejected. Its evaluator/taskset IDs differ
from the corrected experiment. `qualification_review_20261024.json` records
that supersession; only the new qualification describes the corrected runner.

In the recorded environment the namespace probe is unavailable; the report
retains the exact probe error. No externally configured metered provider adapter
and exact model identities have been supplied. Consequently no real four-arm AI
comparison has been run, and no Hepta productivity advantage has been established.

`tests/test_crossfile_eval.py` verifies these native fixtures plus real leak,
infallible-allocation abort, missing-cleanup, fake-native-call and fake-thread
negative cases. It also covers edit scope, transactional rejection, stale IDs,
compiler identity, provider gating, missing denominators, synthetic receipt
validation and append-only records. Synthetic receipts exist only inside unit
tests and are never published as AI experiment evidence.
