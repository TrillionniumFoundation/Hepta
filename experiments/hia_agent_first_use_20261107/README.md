# Agent first-use and P2 evidence, 2026-11-07

Base source: Hepta `205f94ec811018f89fbf68c987c6ab8e826bb15b`.
This work adds a reusable contract-only task broker and keeps observed limitations
in its executable acceptance policy. No genuine model task has run in this
experiment yet. The task pack is ready for a fresh session after integration.
See `docs/HIA_AGENT_FIRST_USE.md` for the exact handoff and judgement procedure.

## Provider availability

The current `/opt/codex/bin/codex` is `0.167.0-alpha.4`, SHA-256
`57c94ea520df28beb76955316c5c48f672550fe42c6cff7003badb76e1ee10d8`.
The fresh catalog succeeded and listed eight selectors, including `gpt-6-astra`.
Catalog visibility is not generation entitlement.

| Attempt | Changed condition | Wall ns | stdout / stderr | Generation turn | Diagnosis |
| --- | --- | ---: | --- | --- | --- |
| baseline-probe | inherited configuration | 45,007,033,838 | 0 / 0 bytes | none observed | transport or provider failure |
| no-cua-probe | only `cua_repl` disabled for this no-tools invocation | 45,006,413,881 | 0 / 0 bytes | none observed | transport or provider failure |

Both attempts confirmed process-group cleanup, leader reaping and complete
streams. Usage remains unknown, not zero. There were no coding requests and no
coding successes. No further selectors or accounts were tried. Raw stdin,
stdout/stderr, process records and result records are preserved per attempt.
The second invocation does not establish that CUA caused the initial failure.

Earlier local `gpt-6.1-sol` evidence was likewise a 60-second zero-output timeout.
Historical Mac probes of `gpt-5.5` and `gpt-5.3-codex` instead emitted explicit
400 `model_not_found` errors stating that those selectors were unsupported with
a ChatGPT account. Those are different failure classes and do not establish the
current account's quota. The old receipts remain in their original experiment;
this work does not rewrite their diagnosis or count them as new requests.

## Four-arm NDU comparison

`macro-replay.json` is a fresh read-only replay of the existing original-receipt
campaign at
`/workspace/scratch/372e7da9bde9/evidence/final-205f94e/macro-campaign`.
It verified 1,458 original objects, 440 events, 32/32 correct native task arms,
32 retained failed/rejected attempts, and eight source-bound Native NDU calls.

| Arm | Complete observed task-lifecycle wall ns |
| --- | ---: |
| Fixed | 25,675,926,451 |
| Greedy | 7,155,146,831 |
| Ordinary | 7,163,077,954 |
| Native NDU | 7,756,494,223 |

Native NDU's saving versus the best observed control is **-601,347,392 ns**.
These are deterministic fixture tasks and the Ordinary arm is a deterministic
full-cost controller. They are not a same-real-Agent comparison with a strong
model controller, and the provider was unavailable for that comparison.
`economic_benefit_established` remains false; P1 remains `HOLD`. A claim upgrade
is not justified by the observed ranking or by the comparison's task scope.

## Machine-plan decision

`machine-hotspot-review.json` binds the earlier complete register-plan result by
SHA-256. Its five emitted variants passed 462 native correctness cases each, and
all three intended refusal cases were retained. Their whole shared images were
all 14,416 bytes. Canonical text was 2,792 bytes, register-assigned text 2,831,
scalar-select text 2,778, layout text 3,257 and combined text 3,126. Timing samples
measure a synthetic Python/ctypes batch and fluctuate across variants.

This provides implementation correctness and limited synthetic cost evidence.
It provides no representative application hotspot, complete Agent search cost
or reason to add another register class, instruction or target. This work adds
none. The next expansion must be selected from a retained real workload profile,
with an independent preservation checker and all lifecycle costs measured.

## Controls and remaining acceptance

The first-use broker controls execute a real shared image and independently
validate all 256 oracle inputs, then deliberately keep provider usage unknown and
P1 on `HOLD`. This proves that the harness can observe success without falsely
claiming a model experiment. It also preserves failed invocations, blocks
uncertain intent replay, enforces unique campaign request keys/slots and detects
changed sealed evidence. It is ready for a new empty-history teammate session;
that session's original model interaction and cost evidence are still required.
