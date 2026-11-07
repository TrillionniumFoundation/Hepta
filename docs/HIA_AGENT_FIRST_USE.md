# First-use maintenance trial

`tools/qualify_hia_first_use.py` freezes a public task, exposes the implemented
HIA domain tools through one recording broker, and independently checks the
adopted native artifact. A genuinely fresh Agent must solve the task; the broker
never supplies a candidate, transformation or sequence of tool arguments.

This is a **local domain-service trial**. It does not negotiate MCP, discover a
formal endpoint, attest that a model has never seen HIA, or supply a provider
invoice. Its judgement always retains `p1_acceptance: HOLD`. A successful task
and a complete P1 first-use acceptance are separate conclusions.

## Run a trial

Use a Python environment with the repository's ordinary qualification
dependencies. Prepare from the final source revision; changing worker, backend,
catalog, discovery documents, broker or observer bytes invalidates an active
trial. The output directory must be fresh and outside the source tree.

```sh
python -B tools/prepare_hia_first_use_example.py \
  --output /absolute/first-use-example-task.json
python -B tools/qualify_hia_first_use.py prepare \
  --task /absolute/first-use-example-task.json \
  --output /absolute/fresh-trial \
  --campaign-id unique_first_use_20261107_r1 \
  --max-calls 128 --wall-seconds 900
```

Give a new Agent session only these items:

1. `/absolute/fresh-trial/public/task.json` and `public/catalog.json`.
2. The absolute Python and broker paths, with this invocation contract:

   ```sh
   python -B /absolute/repo/tools/qualify_hia_first_use.py invoke \
     --output /absolute/fresh-trial < request.json
   ```

3. Permission to create its own request/candidate files in a separate scratch
   directory, and the instruction to read only the public task/contract and
   tool replies for HIA knowledge.

An input is either `{"method":"tools/list"}` or
`{"method":"tools/call","params":{"name":"hia_describe","arguments":{"section":"manifest"}}}`.
These are the broker's JSON inputs, not MCP transport envelopes. The first form
returns the actual eleven-entry domain catalog. The second dispatches the exact
named domain tool. Agents can save large replies to files and inspect the needed
schema fields without discarding the broker's original receipt.

Require the Agent to use `campaign_id + '/'` as the prefix of every mutating
request key and the exact registered `target_slot`. The broker enforces both.
This prevents an old campaign's completed request or global generation slot from
being mistaken for a new first-use attempt. The Agent must discover its profiles,
read its contracts, select changes, verify them, emit and evaluate both artifacts,
and conditionally adopt the accepted candidate. It receives no `Session` helper
or scripted solution.

When the Agent has stopped, the coordinator runs:

```sh
python -B tools/qualify_hia_first_use.py judge --output /absolute/fresh-trial
python -B tools/qualify_hia_first_use.py verify --output /absolute/fresh-trial
```

`judge` must run only once. It reads the actual current slot and retained
receipts, requires the exact registered baseline/workload/objective, checks that
the adopted shared image is smaller, and loads the original image bytes in a
bounded native subprocess for all registered oracle cases. Successful output
includes the candidate Core, shared image, native observations and a sealed file
inventory. `verify` rereads the original bytes and detects changed public inputs,
journal gaps, source drift, interval drift and changed sealed evidence. It does
not rerun a model or treat hashes as proof of authorship.

## Original evidence and failure behavior

Every broker attempt gets an exclusive, fsynced intent file **before dispatch**,
then one outcome file. A leftover intent blocks subsequent dispatch: an
interrupted acknowledgement must not be retried as a new execution. The exact
request, domain response, exception or rejection, captured artifact bytes and
operation interval remain in the trial, including failed attempts. File locks
serialize the broker. Repeated domain calls still preserve their actual new
observations; the underlying request key keeps the domain idempotency semantics.

A frozen allowance limits the number of dispatched calls and elapsed time from
the first broker invocation. The elapsed interval includes gaps between tool
calls, including Agent reasoning after the first call. Initial model startup and
any reading before the first invocation remain outside that measured interval;
therefore it is not called complete task cost. Nested tool durations are reported
separately and never added again to the enclosing elapsed interval. The judge's
own cost is separate. All provider usage, monetary cost and missing model cost
remain `null`, not zero.

The owning model platform must separately retain the **original model
interaction**, session creation/freshness receipt and provider usage. A typed
summary, a transcript rewritten by another model, a synthetic conversation or
a scripted control does not supply those facts. This harness does not grant
itself a full-cost or fresh-session attestation, even after successful native
execution. Learning-scope compliance must be checked against the actual model
interaction; a shell-capable Agent is not physically prevented from reading
other local files.

## Task and interpretation

The task generated by `prepare_hia_first_use_example.py` is a public synthetic
wrapping-u8 maintenance problem with 256 independent mathematical oracle inputs. Its public source has
avoidable work and the objective is a strictly smaller shared image with the
same scalar ABI and behavior. It exercises tool learning and lifecycle handling.
It is not a previously unseen real repository demand and cannot establish broad
Agent generalization. For a real maintenance study, replace the task file with
an independently chosen maintenance request and pre-register its provenance and
oracle before the learner sees it.

`tests/test_hia_first_use.py` includes a deterministic positive control that
executes a real artifact, checks all 256 inputs and still requires `HOLD` and
unknown model usage. Other controls reject changed inputs, foreign request keys,
pending invocations, exhausted call budgets, modified sealed responses and
post-judgement dispatch. These are harness checks, never model success counts.
