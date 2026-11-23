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

## Installed job owner lock admission

The worker installer probes the packaged `hia-worker-prepare` executable before
publishing a `hepta.hia.mcp.controller.v20` manifest. A controller that selects
v20 sends two observations. The first uses `fstat` on the opened lifetime lock.
The second rechecks that descriptor after the supervisor obtains the exclusive
lock and inspects the job directory for prior ownership records.

| Wire field | Encoding |
| --- | --- |
| Request | Eight ASCII bytes `HIAJLK01`, then six little-endian unsigned 64-bit integers |
| Integers in order | Phase, raw file mode, file UID, caller effective UID, link count, existing-record bit mask |
| Reply | Eight ASCII bytes `HIAJLR01`, then one little-endian unsigned 64-bit integer. One admits and zero refuses. |

Both phases require a regular file owned by the caller, one link, and zero
group or other permission bits. Phase zero takes a zero mask. In phase one,
bits zero through four record the presence of `owner-intent.json`, `started.json`,
`exit.json`, `exit.witness.json` and `exit.witness.json.tmp`, respectively.
Any recorded name refuses a second owner, including a dangling link.

The HIA executable decides admission. The supervisor opens and locks the
descriptor, gathers the observations and acts on the decision. Qualification
of the complete service also requires exercising its supervisor, transport,
output handling, cancellation and original-child receipts.

## Installed owner record encoding

Controller v21 uses the installed `hia-worker-prepare` to encode the same bytes for
`owner-intent.json` and `started.json`. The existing receipt writer stages and
syncs both records before the original child launches. Capability detection
compares output against historical JSON bytes and exercises a malformed frame.

The request starts with `HIAJBE01` and six little-endian unsigned 64-bit
integers. They give Unix time in milliseconds, supervisor PID, effective UID,
job name length, kernel process identity length and invocation character count.
Four payloads follow, in order, with no separators.

| Payload | Encoding |
| --- | --- |
| Job ID | 1–128 bytes in the existing job-name alphabet |
| Launch nonce | 32 lowercase hexadecimal bytes |
| Process identity | A lowercase boot UUID, a colon and 1–20 decimal start-tick digits |
| Invocation ID | Little-endian 32-bit Unicode code points. The all-ones count represents a missing value with zero payload bytes. A zero count represents an empty string. |

A successful reply contains one ASCII JSON object, formatted in the historical
sorted field order with spaces after commas and colons and no trailing newline.
Malformed observations return exit status 2 before either record is submitted.
