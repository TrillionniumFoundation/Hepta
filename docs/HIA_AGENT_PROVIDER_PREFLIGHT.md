# Provider startup, catalog and availability are separate gates

The repaired zero-generation startup probe opts out of the observed
`remoteControl/status/changed` notification before initialization. It still
requires exactly one initialization acknowledgement. On the owner host,
Codex 0.144.1 initialized using its existing SQLite state; the earlier fresh
SQLite experiment timed out. No default home, account or permission setting
was changed. A successful initialization is not model access evidence.

`tools/qualify_hia_agent_provider.py` provides three separate operations for
new experiments. It does not amend any historical cohort registration.

```sh
python -B tools/qualify_hia_agent_provider.py catalog \
  --codex /absolute/codex --output /outside/source/new-catalog

python -B tools/qualify_hia_agent_provider.py probe \
  --codex /absolute/codex --models EXPLICIT_SELECTOR \
  --output /outside/source/new-availability

python -B tools/qualify_hia_agent_provider.py replay \
  --input /retained/diagnostic/RESULT.json \
  --output /outside/source/new-classification
```

The catalog operation waits for the initialization ACK before sending
`initialized` and `model/list`. It sends no thread or generation request.
Unknown extra responses, duplicate identities, malformed flags and incomplete
pagination refuse. Advertised catalog entries do not establish entitlement.

The probe operation issues one ephemeral, read-only CLI request per explicit
selector, asking only for `AVAILABLE`. It never changes accounts, retries a
failed selector, adjusts quotas, or starts a coding task. Each process has a
deadline and owned-group cleanup. A known account quota stops all subsequent
selectors in that batch. Uncertain cleanup also stops the batch. The remaining
selectors are retained as unattempted, with unknown usage.

Cleanup is checked directly from the process receipt, even when event decoding
fails. A valid provider quota event remains a stop signal if a later JSONL line
is malformed. A valid success prefix never admits a malformed complete stream;
its usage remains unknown. Replay also refuses non-object diagnostic rows with
a structured blocked result.

Positive availability requires the existing strict event parser, exactly one
answer and complete typed usage. Typed reasoning remains a non-answer event.
Unknown events or observable tool items cannot admit a positive result. This
is event-level rejection, not an OS guarantee that the first read-only command
cannot start before its event is observed. Model routing/weights and the CLI's
inherited system context are not independently attested. No equivalent hard
output-token cap is claimed.

Negative classification distinguishes an observed `model_not_found`, observed
account quota, uncertain cleanup, transport/provider failure, and an invalid
event protocol. Only provider error events contribute quota/selector diagnoses;
an assistant message quoting an error is not provider evidence. Missing,
malformed or duplicate usage is `null`, never zero. An availability answer is
not a coding success. Server retry text is retained without inventing a time
zone or automatically scheduling a retry.

Replay performs no provider call. It classifies already recorded diagnostic
JSON and hashes its input; it does not claim to independently re-attest the
remote raw files, account entitlement, or the historical wall clock.

## Observations retained on 2026-11-03

The two originally requested 6.x selectors returned `model_not_found`.
The catalog then advertised three 5.6 selectors; the requested workhorse and
lightweight selectors both returned account usage-limit errors. All four
processes were reaped with complete cleanup; all four usage receipts were
absent. Zero coding-task requests were made. The negative raw records remain
in the owner evidence directory; the public summary contains hashes and
non-sensitive measurements only.

The command-line adapter is covered by eight regression tests, including an
actual non-model executable that checks ACK ordering, pipes and owned cleanup.
Those fixture executions are never counted as model successes. New coding
experiments still require their own exact source/tool freeze, availability,
budget, native controls and terminal hidden scoring.

## Explicit unused MCP startup dependency check

A no-tools availability probe can now take an explicit
`--disable-mcp-server NAME`. This affects only that invocation's
`mcp_servers.NAME.enabled=false` setting. Literal names are validated; arbitrary
TOML overrides, account changes, ignored rules, sandbox changes and persistent
configuration edits are not accepted through this option. The exact override is
retained in the process argv and result. This is useful only when an independently
observed configured MCP startup dependency could delay a probe that cannot use
that dependency. It is not an entitlement repair or an automatic retry policy.

On 2026-11-07, the current local CLI advertised `gpt-6-astra`. A 45-second probe
returned no stdout/stderr and no generation-turn event. An explicitly separate
same-selector diagnostic excluding the unused `cua_repl` dependency also timed
out with empty streams. Both owned process groups were killed before leader
reaping and both cleanup receipts were complete. These two observations do not
identify an account quota, an unsupported selector, or the failing internal
phase; the dependency hypothesis was not established. No coding request or
successful task is attributed to either probe. Original bytes are in
`experiments/hia_agent_first_use_20261107/provider/`.
