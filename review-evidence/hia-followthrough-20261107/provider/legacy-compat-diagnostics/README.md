# Actual provider diagnostics continuation — 2026-11-07

This packet continues the separately retained `macro-provider-diagnostics-20261107`.
It does not replace any original failure or splice a later provider result into an
old native campaign. P1 remains HOLD, and no actual-provider four-arm campaign
or provider mechanism smoke was completed.

## Observations

The source-bound Codex 0.133 default-stdio adapter completed a zero-generation
catalog query with confirmed process cleanup. The initial failed `--stdio` query
is retained in the prior packet with its original `cleanup_confirmed=false`.
A separate read-only complete process snapshot later found its original PID and
PGID absent; that later observation does not change its original receipt.

The same configured main account then received an explicit availability request
for the actual directory's default `gpt-5.5`. The provider returned HTTP 400 with
`model_not_found`. After a separate explicit instruction, exactly one additional
availability diagnostic used the directory's `gpt-5.3-codex`; it was rejected with
the same code. Both processes were cleaned up, both usage values remain null,
and neither result proves that every model on the account is unavailable.
No further selector or account was tried. The prior packet also retains the
local `gpt-6.1-sol` availability timeout and its complete owned cleanup.

The legacy CLI logged an upstream model-metadata parsing failure for the enum
value `max`. Its returned model directory cannot establish actual support or
account entitlement. The raw provider rejection JSONL is retained here.

## Exact scope and originals

`SUMMARY.json` states exact source identities, durations, limits and outcomes.
`FILES.json` inventories the distributed bytes. The CLI wall durations are
observed child-process costs. Their sum is not the complete Agent lifecycle,
not a same-budget four-arm comparison, and not a billing total. Missing provider
usage and monetary costs are never replaced by zero.

The compatibility adapter is the original file committed at
`959ee89922a60f1e025e8bd5da34df09d26d449e`, using dependency bytes from
`3da166c26b08159831e395cc3756fc4258ba0f2c`. The later combined source commit is
not retroactively assigned to these observations.

## Explicit redactions

The legacy CLI included entire upstream model-registry response bodies with
embedded provider instructions in stderr. Those bodies are unnecessary to
assess the error and are not distributed. Exact original stderr files remain
unchanged in the private working-session evidence directory. Their original
SHA-256, byte counts, and removed-section hashes are recorded in
`STDERR_REDACTIONS.json`. The distributed `stderr.redacted.txt` files are labeled
derivatives, not purported original stderr; the original `PROCESS.json` entries
still point to their original stderr digests. This public packet therefore is
not a complete raw-stderr archive. No logs database, state database, configuration
file, credential, or full model-registry instruction body is included.
