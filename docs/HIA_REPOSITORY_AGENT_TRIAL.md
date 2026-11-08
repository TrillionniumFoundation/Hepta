# One real repository Agent trial and its cost boundary

`tools/hia_repository_agent_trial.py` records one explicitly authorized CLI
session in an independently prepared clean repository. It is a separate event
profile from the MCP-only first-use runner. Command execution and file changes
are expected repository work and are preserved in original JSONL. An unregistered
MCP server is rejected. The old first-use profile is unchanged.

The coordinator must inspect the installed CLI and freeze its exact executable
SHA256, argv, requested model/profile, public prompt, source commit/tree, original
wall budget and terminal token-review threshold before launch. Do not infer a
configured model or account from old experiments. Do not supply credentials in
argv, registration or prompt. The runner does not select credentials, alter
permissions, or certify effective CLI configuration.

## What is now measured

The runner starts its outer clock before preflight, retains original stdin,
stdout, stderr and process receipt, and starts exactly one owned process group.
The shared transport stops that original group before reaping its leader and
records whether cleanup and both captured streams completed. Output directories
are create-only. An uncertain launch never authorizes another session.

The before snapshot must be clean and equal the pinned source commit and tree.
The after snapshot retains the tracked binary-capable Git patch plus bytes and
hashes of new ordinary files. Both snapshots retain Git status and HEAD/tree.
Snapshots are observations, not an atomic snapshot against an independent writer.
Only a dedicated checkout may be used.

The reported usage settlement reads the original terminal event. It supports
input/output counters with optional cache/reasoning counters and keeps the raw
original usage object. Input plus output is the review quantity. Cache and
reasoning counts are not added again because their overlap is not established.
Missing auxiliary counters remain null. A failed turn or nonzero child exit does
not erase known reported usage. Missing, malformed, multiple or incomplete
terminal observations do not become zero cost.

Live settlement binds the exact bytes it parses to the original process
receipt's stdout SHA256 and retained byte count. It also requires the observed
stdout byte count to equal the retained count and requires pipe EOF. Pipe EOF
alone is insufficient: a capped output file can retain a valid terminal prefix
while dropping later events. Any capture mismatch or truncation leaves usage
unsettled and preserves the visible terminal observations for review.

Failed, cancelled and nonzero-exit item observations are retained with their
original line numbers and hashes. A later successful update or a reused item ID
does not erase an earlier failure. Per-type tool counts use distinct observed
CLI item IDs; an ID reused across types can appear in more than one type. Neither
these counts nor failure-observation counts are physical provider request counts.

Whole-trial wall time includes preflight, provider work, and final capture.
Provider and command times are nested observations and are not added again.
A wall deadline can terminate the owned CLI; the token threshold is terminal
review, **not a hard mid-turn token cap**. With this interface a strict monetary
cap cannot be guaranteed from a token threshold.

### Stop an original running trial

The coordinator can request cancellation without looking up or signalling an
OS process ID:

```sh
python -B -m tools.hia_repository_agent_trial cancel --output /absolute/original-trial --reason 'startup has not produced events'
```

The command binds a create-only `CANCEL_REQUEST.json` to the SHA256 of the
retained original registration. It never starts a session or signals a process.
The original runner polls that exact request and asks its existing owned-process
transport to stop its original group before reaping the leader. A request seen
during preflight prevents launch. A malformed request or one bound to a different
registration is retained but does not stop the trial. Repeated requests return
the first request unchanged; a terminal trial without an earlier request is a
read-only observation.

`requested` is not confirmation of termination. Read the final original
`TRIAL.json` and its `process.cleanup_confirmed`, stream capture and return status.
If the original runner is gone or predates this cancellation protocol, the
request cannot make it poll again or prove cleanup; the old deadline and outcome
remain separate evidence. No arbitrary process, escaped descendant or past
external effect is controlled by this interface. Missing terminal usage after
cancellation remains unknown. The output directory is a coordinator-owned
same-account scope, not a credential-authenticated cancellation service.

## Why fees were absent in previous evidence

The existing structured Codex providers already retain exact invocation bytes
and terminal usage. Their descriptions and receipts explicitly set billed cost,
provider-internal HTTP request count and tariff/invoice to null. The shared
five-field usage parser is a token observation interface, not a billing API.
The strict structured-proposal providers forbid command and file tools, while
the existing fresh-session profile accepts only registered HIA MCP calls.
Consequently neither is an adequate unchanged runner for repository edits.

This new recorder keeps `billed_cost`, tariff/invoice and physical provider
request count null as well. An actual billing export or qualified tariff binding
would be an additional source. A public list price would produce an estimate,
not an account invoice, and must distinguish cache and reasoning semantics.
The enclosing ChatGPT authoring/coordinator cost, infrastructure charges and
any unavailable provider-internal retries remain separate missing costs.

## Frozen launch input

The registration schema is `hepta.hia.repository-agent-launch.v1`, with exactly
these fields:

```json
{
  "schema": "hepta.hia.repository-agent-launch.v1",
  "argv": ["/absolute/observed/codex", "exec", "--json", "--ephemeral", "--sandbox", "workspace-write", "-m", "OBSERVED_MODEL", "-"],
  "repository": "/absolute/dedicated/clean-checkout",
  "source_commit": "FULL_OBSERVED_COMMIT",
  "source_tree": "FULL_OBSERVED_TREE",
  "public_prompt": "/absolute/public/PROMPT.txt",
  "public_prompt_sha256": "SHA256_OF_ORIGINAL_PUBLIC_PROMPT",
  "executable_sha256": "SHA256_OF_OBSERVED_EXECUTABLE",
  "requested_model": "OBSERVED_MODEL",
  "requested_profile": {"kind": "observed-installed-profile", "reasoning_effort": "OBSERVED_VALUE"},
  "wall_limit_seconds": 1200,
  "token_review_limit": 32768,
  "allowed_mcp_servers": [],
  "session_freshness_attestation": {"source": "coordinator", "receipt": "EXACT_ORIGINAL_CREATION_RECEIPT"}
}
```

The example placeholders are not a runnable registration. Copy actual observed
values and confirm the exact CLI supports the frozen argv; do not guess options.
The runner reads the public prompt verbatim and never appends a candidate, hidden
oracle or implementation answer.

Run from the pinned harness checkout, keeping output outside the learner repo:

```sh
python -B -m tools.hia_repository_agent_trial run --registration /absolute/registration.json --output /absolute/new-trial
```

A retained original stream can be reviewed without launching a process:

```sh
python -B -m tools.hia_repository_agent_trial settle --stdout /absolute/original/stdout.raw --streams-complete --process-receipt /absolute/original/PROCESS.json --output /absolute/new-settlement.json
```

Only supply `--streams-complete` when the original transport receipt confirms
EOF and complete, untruncated capture. `--process-receipt` additionally binds the
parsed bytes to that receipt and checks observed versus retained byte counts.
If the optional receipt is omitted, completeness is only a caller attestation;
the offline command cannot independently establish it. A truncated valid prefix
must never be described as complete just because its last visible line is a
terminal event.

## Acceptance remains independent

An observed terminal CLI response does not accept the repository change.
`task_acceptance` stays HOLD; the recorder does not claim native verification,
adoption, consumer success, unseen-task generalization, or economic benefit.
An independent evaluator must bind the actual patch and native artifact to a
successful public acceptance run and original adoption/consumer receipts.
Task generation, evaluator design and candidate selection must be retained as
part of the scope; the task author must not impersonate the unfamiliar learner.

`tests/test_hia_repository_agent_trial.py` uses authored local subprocesses and
temporary Git repositories. These tests contact no model or external service.
They exercise three/five-counter usage, no double counting, failure retention,
truncation and duplicate-terminal handling, the distinct event profile, exact
baseline rejection, original stream capture, changed/new file capture and owned
timeout cleanup. Their success is harness evidence only.
