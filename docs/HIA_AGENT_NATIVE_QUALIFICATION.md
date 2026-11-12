# HIA qualification campaigns and original-request recovery

`tools/hia_agent_native_qualification.py` exercises all eleven tools, an explicit
native transformation, stale generation refusal, adoption and rollback. It is a
scripted integration client. Its result does not establish fresh-Agent learning,
NDU value, deployment of a formal gateway, or visibility in a ChatGPT tool list.

## Campaign identity

The CLI requires `--campaign-id`. Use a new ID for a genuinely new qualification;
use the original ID only when deliberately observing the original request
sequence through the same installed worker and its retained store. IDs contain
1–96 ASCII letters, digits, dots, underscores or hyphens, and start with a letter
or digit.

The client derives both ownership names from that one ID:

| Subject | Binding for campaign `controller-20261107-a` |
| --- | --- |
| Mutation request prefix | `hia-qualification/controller-20261107-a/requests` |
| Publication slot | `hia-qualification/controller-20261107-a/slot` |

The worker's slots are globally named within its configured store. Creating a new
context does not isolate an existing slot. Changing only request keys can collide
with the old slot's generation; reusing all default keys can instead replay an
old campaign without executing a new qualification. The CLI has no implicit
`qualification` campaign. The Python `Session` and `scripted_loop` defaults remain
compatible for existing tests that use independent disposable stores.

For an administrator-selected existing MCP command:

```sh
python3 -B tools/hia_agent_native_qualification.py \
  --campaign-id controller-20261107-a \
  --mcp-command-json "$HIA_REVIEWED_MCP_COMMAND_JSON" \
  --output /absolute/new/controller-20261107-a.json
```

The command can use the runtime's existing full-operator stdio facade to reach a
reviewed HTTP controller. Its full-server contract, token file and upstream URL
remain administrator-controlled. This client does not create execution
authority, select a different worker or change a gateway policy.

## Evidence and recovery

Both the requested output and `<output>.calls.jsonl` are create-only. Existing
evidence is refused before a transport starts or the service store opens. The
report records the campaign binding and the actual qualification-client source
digest. Each call's exact intent is flushed and fsynced before dispatch. Its
response or exception is then appended with the same sequence number. A lost
response remains `unknown`; the journal retains its original tool, key and body.
Failures retain a failed report and every observed call. Abrupt termination can
leave a `started` report, while the append-only journal remains the record of
submitted intents; it does not prove their terminal state.

After a disconnect, first observe the original durable operation or replay its
exact tool and unchanged arguments through the runtime. Do not infer a retry from
an exception or manufacture a new campaign ID to recover an uncertain request.
If resuming the deterministic whole sequence, use the original campaign ID,
unchanged client source/arguments and original worker store, and select a new
output path. The worker returns retained responses for bound requests. A changed
body under an existing key conflicts; it does not silently become a new attempt.
An unresolved original intent remains unresolved and must use runtime recovery.

Reconnection, process cancellation and actual controller replacement still need
their own original process identities and terminal receipts. A successful
scripted campaign does not prove that those lifecycle operations were performed.

Run the persistent-store isolation and lost-response regressions with:

```sh
python3 -B -m unittest tests.test_hia_agent_native_campaign -v
```
