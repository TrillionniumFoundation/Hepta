# Repository resource maintenance Agent pilot

This pilot compares complete HIA module responses with the existing
snapshot-bound structured edit API. It uses two committed repository resource
examples instead of the earlier four scalar arithmetic tasks. The examples are
real repository files; the maintenance defects are **explicitly registered
injections**. This is not evidence of historical maintenance, an actual external
library upgrade, or general Agent productivity.

## Provenance and tasks

Both target programs are bound to exact file hashes and Git blobs under Hepta
commit `1b5e946c9889b1c19ae86235cb14dfb76da10777`. The protocol records them in
`benchmarks/hia_agent_repository_maintenance/PROTOCOL.json`.

| Task | Repository source | Registered injected defect | Behavioral obligations |
| --- | --- | --- | --- |
| Offset-copy API | `examples/hia_program/offset_copy_v5.hia` | A legacy `buffer.copy` call ignores the source and destination offsets already supplied by the client. | Distinct source/destination owners, offset copy results, bounds refusal, both owner releases and loan cleanup. |
| Overlap callsite | `examples/hia_program/overlap_move_v3.hia` | The `buffer.move_within` adapter reverses source and destination operands. | Same-owner overlapping move semantics, bounds refusal, owner release and loan cleanup. |

The first uses the actual versioned `buffer.copy` and `buffer.copy_range` APIs.
The second uses the actual overlap-safe move API. A source-history query over
seven candidate paths found only their creation commits through the pinned
source; no preexisting edit pair was available from those paths. The query URLs
and returned commit metadata are retained in `history-query.json`. The
injections are therefore never described as historical bugs.

## Matched information and real tools

Both arms receive the entire same initial normalized module, public contract,
repair location, public input/output cases, snapshot digest, and structured-edit
API description. Only the required response representation differs. Both have
an 8,192-token context, a 2,048-token response limit, 120 seconds per response,
and at most two responses. Task order is fixed and arm order rotates by task.

The structured arm calls the production `apply_program_patch` function using
the exact snapshot and explicit preserve-interface policy. The full arm submits
a complete module. Both are independently reverified and must preserve every
normalized field outside the same disclosed operation. The host never repairs
an answer, supplies a reference answer as feedback, or interprets reference
controls as model successes.

Public validation actually executes the checked HIA interpreter, compiles the
submitted module with the registered Clang, links a C ABI harness and the actual
allocator observer, and executes the native binary. A public success triggers
terminal hidden evaluation: 12 normal cases and five bounds-refusal cases. The
normal cases require correct values, exact allocation/free counts, and zero live
allocations/accounting errors. The refusal cases require the owned process's
registered trap signal, rather than accepting arbitrary nonzero exits or
timeouts. Trap termination does not establish successful cleanup in a faulting
process. Hidden cases, expected values, and target programs never appear in
model messages, and hidden failure cannot trigger a retry.

Before model requests, ten author controls must pass: a native reference for
both arms on each task, an unchanged defective candidate, a missing release,
and a stale snapshot. Positive controls include hidden native tests; negative
controls must be refused. The control receipt binds all compiler, protocol,
prompt and evaluator inputs. The study also checks that every bound source file
matches its actual Git blob at the declared commit, so a commit name alone
cannot disguise dirty or untracked experiment inputs.

## Models and unavailable providers

The local model is the already available, pinned official
`Qwen/Qwen2.5-Coder-1.5B-Instruct-GGUF` Q4_K_M artifact, revision
`f86cb2c1fa58255f8052cc32aeede1b7482d4361`, SHA-256
`cc324af070c2ecbfd324a30884d2f951a7ff756aba85cb811a6ec436933bb046`.
The owned llama.cpp runtime checks the exact model/runtime bytes, process
ownership, actual token counts, greedy settings, context and response budgets.
It applies only a generic JSON-object syntax grammar, equally to both arms.
No task-specific answer fields or valid replacements are put in the decoder.

The requested second model, `gpt-6.1-sol`, has an actual provider availability
record returning a usage limit. The runner requires that raw failed-turn record
and confirmed process cleanup. It records **zero task attempts** and does not
count provider unavailability as an incorrect answer. No second local model is
silently substituted. Multi-model advantage remains unestablished.

## Running the frozen study

First commit all study and compiler inputs, then run the controls at that same
commit:

```bash
python3 tools/qualify_hia_agent_repository_maintenance.py controls \
  --output /absolute/new-controls-directory \
  --clang /absolute/clang
```

Only after controls pass, run the registered requests:

```bash
LLAMA_ARG_REPACK=0 python3 tools/qualify_hia_agent_repository_maintenance.py run \
  --output /absolute/new-study-directory \
  --clang /absolute/clang \
  --controls /absolute/new-controls-directory/CONTROLS.json \
  --binary /absolute/llama-server \
  --model /absolute/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf \
  --provider-blocked /absolute/provider-availability/request \
  --expected-head EXACT_COMMITTED_SOURCE_SHA
```

Outputs must be new directories. Every request, raw transport response,
generation receipt, public evaluation, terminal hidden evaluation and failure
is retained. A failed/incomplete model attempt is not repaired by increasing the
registered budget or rerunning a cell outside the protocol.

## Cost and acceptance limits

The report includes input/output token counts, usage completeness, all attempts
and retries, real public/hidden validation time, per-cell wall time, and the
entire shared runtime/source-admission wall time. Each arm is charged its own
cell time, half the shared noncell run time, and one full controls campaign.
Per-success token and controlled-runtime costs are reported only when success
and complete usage make the denominator meaningful. An outer command ledger
must additionally retain Python process startup, imports and report output.

Human development, task authoring, electricity and historical model training
costs are unmeasured. Two related examples and one available quantized model
cannot establish general productivity or superiority in real library
maintenance. A structured-edit success can establish an observed difference
within this small, frozen repair interface experiment, with its complete
measured execution costs and explicit limits.
