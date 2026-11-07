# Isolated HTTP qualification adapter

This package reuses the exact Hepta `205f94ec811018f89fbf68c987c6ab8e826bb15b`
qualification and transport source bytes, together with their exact HIA catalog.
`Session`, `ToolClient`, and `scripted_loop` remain unchanged. The added adapter
implements local HTTP JSON/SSE framing and records each original request and raw
response body. It is not a model provider or a policy-benefit experiment.

The sole application-argument mapping replaces the original `qualification`
target label with a registered, unique `qualification-http-<runtime SHA prefix>`
label. The original expected generation/epoch `0/0`, stale-CAS rejection, rollback,
schema checks, native workload and full-cost reads are preserved. The output
directory is created exclusively before any HTTP call. An existing directory
cannot be used to rerun the loop. No worker database or existing target is reset.

The first HIA RPC is observed exactly once. Every accepted or unknown result is
reconciled by read-only `process_wait` and `process_read` calls for its exact
original x230 job. Complete and durable terminal
publication, strict byte cursors, worker/source bindings and the full original
report are required. Only then is the identical HIA binding observed once more;
the provider-admitted result must equal the original report. A raw worker report
is never substituted for a provider result. Terminal rejected results remain
rejected, including the intentional stale-CAS step.

Credentials are read only from an owned mode-0600 local token file. HTTP redirects
and proxies are disabled, and only the specified loopback MCP endpoint is allowed.
Headers and token bytes are never included in receipts. Raw response bodies,
protocol records, failed attempts, and all application records are retained in the
owned output directory. No process or controller is stopped by this adapter.

`mac-wheels/`, `requirements-mac.lock`, and `DEPENDENCIES.json` contain five pinned
Python 3.14/arm64 or pure-Python wheels and their hashes. Install only into this
task's private virtual environment, using `--no-index --require-hashes --no-deps`.
There is no global dependency installation.

Run only after the selected shadow endpoint has been qualified, with its exact
runtime commit, independently registered prefix/slot, local token path and a new
output directory. A passed result requires the original 39 application calls and
all 11 HIA tools, then restoration of generation 0 at epoch 2 in the owned slot.
It establishes this transport lifecycle only. Model costs remain unknown and no
net optimization benefit is claimed.

The nine local adapter tests cover framing, exact slot substitution, binding,
strict durability and byte cursors, original-key reconciliation, refusal to
manufacture completion, redirect refusal, and duplicate-registration refusal.
They are not native lifecycle evidence. The actual HTTP lifecycle has a separate
registration and execution receipt. The runtime commit argument is caller-supplied;
actual controller binary/PID/listener identity belongs to independently observed
shadow receipts immediately before and after the loop.
