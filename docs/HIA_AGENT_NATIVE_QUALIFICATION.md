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

## Installed owner lifetime lock

Controller v22 binds the installed HIA receipt writer to the original
supervisor's open file description. Descriptor 0 supplies a sealed
`HIAJLF01` request. Descriptor 1 receives the supervisor's open lock file.
The writer returns a 24-byte `HIAJRW01` receipt on descriptor 2.

The request contains four little-endian 64-bit integers after the magic:
the direct parent PID, the expected file device, inode and a zero reserved
word. The HIA program checks the direct parent and the descriptor's kernel
identity. It requires one link, a regular file owned by the effective UID,
and no group or other permission bits. It selects a nonblocking exclusive
flock on that same description. A phase-two receipt reports success or the
kernel error, including contention. A phase-one receipt reports a failed
descriptor observation.

When the writer exits, the original supervisor still holds its file
description. Another independent open remains excluded until the last
holder of the original description closes it. The installer exercises both
exclusion and release before publishing a v22 controller manifest.

## Installed owner marker observation

After the original supervisor has obtained the lifetime lock, controller v23
asks the HIA receipt writer to observe the five ownership and terminal names.
The writer receives the already pinned job directory as descriptor 1. Its
sealed `HIAJMK01` request carries the parent PID, expected directory device,
inode and a zero reserved word as four little-endian unsigned 64-bit integers.

HIA confirms the expected private directory and selects all five lookups.
Each lookup uses the pinned directory and `AT_SYMLINK_NOFOLLOW`. A dangling
symbolic link therefore counts as an existing marker. The phase-three
`HIAJRW01` receipt returns the existing v20 five-bit mask. The file-descriptor
check and directory lookup errors are reported as negative kernel results in
phases one and two respectively. Either error prevents a fresh workload
submission. The installed encoder still applies its post-lock admission rule.

## Installed lifetime descriptor handoff

Controller v24 submits the pinned job directory to the HIA receipt writer.
The sealed request begins with `HIAJLH01` followed by five little-endian
unsigned 64-bit integers: the direct parent PID, directory device, directory
inode, local Unix socket descriptor and a reserved zero word. The supervisor
creates the socket pair for this launch and passes one endpoint to the writer.

The HIA program verifies the directory and the kernel-reported peer PID and UID
before opening `owner.lock` relative to the directory. The Linux adapter opens
the lock with mode 0600 and no symlink following. HIA validates its metadata
before and after an exclusive nonblocking flock, then checks all five owner and
terminal names on the pinned directory. A fresh launch transfers the already
locked file description in one `SCM_RIGHTS` message. Its payload is the byte
`L`. The original supervisor receives one close-on-exec descriptor and holds
it until exit. Closing the writer, or closing an additional duplicate in the
supervisor, leaves the original lock intact.

The `HIAJRW01` receipt uses phase 12 and value zero for a successful transfer,
phase 20 for an unsafe lock and phase 21 with the nonzero existing-marker mask
for a replay refusal. A negative result preserves the kernel error and phase.
The installer checks the resulting inode, close-on-exec flag, contention and
release before selecting v24.
