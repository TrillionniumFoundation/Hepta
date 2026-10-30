# Independent V11 integrity review before model execution

The pre-fix source was integration commit
`cce66214bb659e78dccd3df08da9d4f526380761` (original feature commit
`cc151b2814adf8128953f7d1757436b53de410f6`). The reviewed repair is
`648dde4e4fe5752028ac004e01a3069fc37f6d0b`. No blocking finding remains within
this review's scope after the repair and independent replay. This evidence
does not qualify a later integrated head or grant model-study eligibility.

**This review performed zero model loads, zero generation requests and zero
runtime executable invocations.** The error-path engine is an explicit test
double. Its results are neither capacity successes nor model qualifications.

## Findings and repair

| Finding | Pre-fix observation | Repaired boundary |
| --- | --- | --- |
| The declared runtime archive was not enforced against supplied executable/library bytes | `tool_identities` accepted Python as both helper roles and established identities; this only demonstrated the missing pin, not that Python could pass real capacity | Exact `llama-server`, `llama-tokenize`, and 38 shared-library members must match the fixed archive's names, kinds, symlink targets, sizes and SHA-256 values |
| Final identity failure could prevent terminal cost evidence from being saved | The injected final identity exception propagated after PLAN, with no CAPACITY or service-cost report | The same fault now retains PLAN, CAPACITY and service costs; CAPACITY remains incomplete, with finalization failures recorded |

Related source inspection found that a shutdown exception could bypass the
study engine-record append and make prior request totals appear zero, and that
main's final summary could reread a changed protocol after identity failure.
The repair registers counters before fallible finalization, records each
failure independently, preserves unknown usage, and uses the run's frozen arms
for the final summary. A complete terminal SSE receipt can recover exact cost
once, without turning a failed submission into a qualification success.

## Independent runtime comparison

The reviewer independently read the official b11669 archive with SHA-256
`cf07c1c112d709bd67e522017471de57ed0ec8bea031d732c5422351c07f65ac` and size
17,851,611 bytes. The selected inventory has 40 members: 30 regular files and
10 symbolic links, all under `llama-b11669/`. It includes the substantive
`libllama-server-impl.so` implementation and all CPU plugin variants.

The independently calculated manifest has SHA-256
`3bf3805e63245ac06d434c03f8d91e9815788ff00377acbd94e43f7bd3325f92` and was
adopted as the fixed manifest. After the repair, `verify_runtime` accepted the
actual extracted archive's complete 40-member inventory and rejected Python
in the helper roles. Only file identities were read; nothing was executed.

The operating-system loader, external libraries, kernel and host remain
trusted. These checks do not claim runtime mapping attestation, upstream model
weight reconstruction, or complete software supply-chain verification.

## Frozen experimental conditions

The review compared all 21 recorded protected protocol fields before and after
the repair, including tasks, arms, prompts/history rules, model and official
template pins, runtime release, generation/native budgets, hidden seeds,
decoder, public feedback, stop rules, advantage gate and qualification rules.
They are unchanged. The added protocol material records only the prospective
runtime and failure-accounting integrity correction before model execution.

The actual model remains one pinned third-party Qwen3.5-4B quantization with
the original model provenance separately stated. The owned server must match
the fixed official plain non-thinking template branch before generation.
Reference controls are not model answers or qualification successes.

Main still requires a fresh, same-source V11 capacity record and actual 3/3
qualification with complete usage. Earlier V8/V9/V10 schemas, model identities
or success booleans do not grant V11 eligibility. A failed qualification keeps
main unstarted; this review neither changes nor supplies those outcomes.

## Reproduction and evidence

`reproduce.py` exercises only the explicit finalization fault and runtime role
comparison. Set `PYTHONPATH` to the checkout being examined and select a new
output directory:

```bash
python reproduce.py --source-sha FULL_REVIEWED_COMMIT \
  --output /absolute/new/review-directory
```

The original pre-fix control receipts are retained, along with fixed-source
receipts, the full incomplete terminal CAPACITY/PLAN/service reports, the
independent archive inventory and source hashes. `RESOLUTION.json` records the
observed distinction between the two runs. These are review controls and are
excluded from all actual model requests, qualification tasks and main cells.
The implementing agent's unit tests are a separate denominator.
