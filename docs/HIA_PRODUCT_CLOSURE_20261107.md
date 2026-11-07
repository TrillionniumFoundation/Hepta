# HIA product closure, 2026-11-07

This candidate implements the next bounded steps in the requested order. It
does not declare every product, language or economic gate passed. The default
entry is `python3 -B tools/hia_release.py`; the generated
`releases/hia-current.json` binds the exact source pair and installed identities.
The source commit precedes its metadata lock commit. Always materialize that
lock before installing a worker; the metadata checkout is not the installation.

## 1. Original production operations, before any replacement

The original production cutover has now been reconciled from its native
authoritative status, complete original stdout and independently read result
file. It failed. A later working service is not evidence of that cutover's
success.

| Original operation | Authoritative observation |
| --- | --- |
| Cutover `1a1b54d0050-fc05-8be3` | `failed`, exit 1; complete, durable, terminal publication confirmed |
| Cutover source | Hepta `205f94ec811018f89fbf68c987c6ab8e826bb15b`, runtime `c81a938150d2e533843a42af77739cb888812338` |
| Cutover failure | `launchctl bootstrap` exit 5, Input/output error |
| Conditional rollback | Config, plist and link restored; bootstrap again failed; `rollback.complete=false` |
| Original sentinel `1a1b54d25e3-fc05-8be5` | Succeeded after release-on-failure; not proof of continuity across a successful restart |
| Evaluate `1a1b59f7d31-12894-7d` | `succeeded`, exit 0; complete, durable, published original worker report |
| Evaluate domain result | `unchanged`, `adopted=false`, same baseline/candidate artifact; planned workload complete |

Original cutover result SHA256:
`b4f03d40ae43ab5ae3ab1a0858f8400c41611ea3b34a5328dfd22a6aef4019f5`.
Original evaluate request SHA256:
`c752a30e7565b3bf10bd210354088605d2c529923e2802dd646ac72ce89c2a0c`.

The raw captures and locally recomputed reconciliation receipts are in
`review-evidence/hia-closure-20261107/`. The pure offline
`tools/hia_original_reconcile.py` requires the original host/job/launch nonce,
authoritative terminal publication, exact output bytes, offsets, lengths, EOF,
durability and retained cancellation/timeout flags. An explicit contradictory
nonce or non-authoritative status rejects. Its receipt grants no retry,
deployment, transport authentication or economic qualification.

```sh
python3 -B tools/hia_original_reconcile.py \
  --binding original-binding.json --status original-status.json \
  --output original-output.json --receipt new-reconciliation.json
```

### Exact observed v4 composition

The previous formal v4 workflow belongs only to this pair:

| Identity | Value |
| --- | --- |
| Hepta | `894d2dfce54ff25271b8de2c18c902394484d5cc` |
| Runtime | `c81a938150d2e533843a42af77739cb888812338` |
| Worker | `b75a689c159beab75d3af985badede167c247f482dd7dc86dfe99973a5aab079` |
| Backend | `1fd7feedfd68a0cc4f1aec1ba053d7066505817bfe2366a0ca8db1dfb7617873` |
| Catalog | `8b880cc02efc93e10d920bf812bccbb33197aa00f6b92282536a000238ba5e9e` |

Retained evidence includes 39 domain calls covering all eleven HIA tools,
candidate/verify/emit/evaluate/adopt/actual use/rollback, and rejection of stale
generation with `E_HIA_GENERATION_STALE`. Rollback restores generation 0 at
epoch 2 and applies to future calls; it does not undo effects already executed.
The completed original evaluation also replayed across a new HTTP session with
the same original worker report. That replay did not cancel a live task and
did not prove global absence of duplicate jobs.

The improved lifecycle client is retained under
`experiments/hia_product_closure_20261107/http-client/`. It requires a complete
inventory before setup and before the one cancellable submission. It binds a
previous failed attempt's externally pinned result, every consumed manifest
file, original accepted job, authoritative running incarnation, complete
canonical worker request, profile and installation pins. A separately
registered later trial needs different request and slot namespaces. Every
cancelled-output page is checked, and the complete terminal is reconciled.
The c81 running systemd projection is decoded only after checking its audited
unit description, invocation and PID; absence of a top-level nonce does not
license guessing one from arbitrary process metadata.

**Live cancellation remains unqualified.** c81 rescans the complete controller
job directory on every inventory page, before applying the host filter. The
observed source scan exceeded its original 5-second budget. It returned no
partial inventory, so no fresh cancellation trial was submitted to conceal
that failure. A separate runtime optimization patch preserves the existing
limits and still needs its required development-server and real-directory
qualification. It is not part of the runtime commit named by this lock.

### Costs and incomplete observation

The original evaluation's SHA-bound ledger reports 46.849549849 seconds through
report publication and 27.186120316 seconds of native child wall time. These
are overlapping measures, not additive costs. Context tool time before that
evaluation is 0.706561235 seconds; 4.354492860 seconds of unscoped discovery and
read work cannot be uniquely attributed. Model tokens/wall time, adoption and
future use remain unknown or unobserved. `full_search_cost_complete=false`,
`external_costs_complete=false`, and `net_optimization_benefit_proved=false`.

A later read-only cost capture timed out at its original 300-second limit.
The full ledger and evaluation receipt were already saved and hash-verified.
A separate readback recovery reused four retained pages, then the formal HIA
entry reported `HIA_OBSERVATION_UNAVAILABLE` for original read job
`1a1b5bcfe89-12894-d3`. Native status and all 73,616 original output bytes were
subsequently collected: that read job succeeded and its output was durable.
The API observation failure remains retained; it does not become an evaluate
failure or a successful transport recovery. The large measurements artifact
has not been claimed as a complete locally authenticated download.

Current conversation tool discovery exposes no `hia_*` tools. An HTTP catalog
containing HIA is a different observation. The prior ordinary-model launch
failed because the account did not support its selected model; a READY probe
from an approval-review model does not establish a normal fresh-Agent trial.
The preregistered private first-use task and real provider/native-NDU comparison
remain blocked on a usable, correctly registered Agent/provider environment.

## 2. Closed Safe Core final-image validation

The opt-in profile
`hia.safe-core.unsigned-acyclic-single-borrow.x86_64.v1` covers one function,
unsigned scalars/Boolean operations, acyclic control flow and one borrowed
buffer. It checks the actual final linked bytes with an independent Core
interpreter, x86 decoder/symbolic executor and ELF binding checker. The chain
includes stack/register ABI, internal call relocation, abort PLT/GOT relocation,
dynamic symbol/hash/version tables and their actual loader mapping.

Each accepted image needs a nonempty caller contract and four UNSAT obligations
for memory bounds, ABI, terminal coverage and Core/image behavior plus caller
bytes. Solver unknown, a deadline, incomplete paths or unsupported instructions
reject. Only the exact successfully validated final bytes are published.

The combined worktree qualification passed 25 tests, three positive images,
four wrong-backend SAT counterexamples and 27 raw-query replays. The wrong
backends implement add as subtract, admit an equal-to-length index, widen a byte
store and corrupt a saved register. Their self-consistent object regeneration
cannot make the independent checker accept them.

See [scope, trust assumptions and reproduction](HIA_SAFE_CORE_MACHINE_VALIDATION.md).
The Python models, Z3, source checker, live/exclusive caller allocation, available
stack, loader and nonreturning libc abort remain explicit trust assumptions.
Full ISA refinement, checker soundness and whole-language soundness remain
unproved. This profile is not silently enabled for every HIA emission.

## 3. Selfhost-Core capacity

Selfhost-Core v5 raises the instruction limit from 3,072 to 8,192, while keeping
the original 1 MiB source/output/workspace limits and original CPU, memory and
child deadlines. Structural nodes are counted exactly and relocation capacity
is checked before output mutation. The compiler itself has 3,044 instructions.

The capacity branch retained 154 native checks, 10 cold-replay checks with 154
inner checks, and seven direct v4-to-v5 upgrade checks. An 8,192-instruction
program really executes; 8,193 rejects. The 262,144-node boundary passes its
structural gate but the constructed example then exceeds output capacity;
262,145 nodes reject structurally. Neither is represented as a successfully
executed oversized image.

The final integrated source regenerated its complete Python seed inventory
and passed its own cold replay: 10/10 outer checks and 154/154 inner native
checks. B1=B2=B3 is `76446640911c583bc70b7f5a0c59973383b01dacb007d6f1f5b5239e70b25ad6`;
modified M2=M3 is `71f31e85003cb28ba081426106576322464ae2c15dcb97b7ab6c3ac344d59d55`.
The source export, modified fixed point, counterexamples and independent
VM/native comparisons are retained. Existing ownership,
general checker, returned loans, recursion, external-symbol linking and general
native-backend exclusions remain explicit in the support matrix.

## 4. NDU against a strong ordinary control

The ordinary controller now evaluates all admitted finite plans (at most 16),
including uncertainty, remaining workload and the original remaining time/token
budget. Failures, timeouts, cancellations and already incurred controller costs
remain charged. Unknown costs block a benefit claim. Empty candidate sets,
keep-existing, no-adopt and stop are valid; incumbent plans win ties.

The related 73 tests pass. A real local native campaign completed 32/32 task
arms and retained 440 events and 1,457 raw objects. Its first environment
failure is also retained. It did not invoke a real model or native NDU bridge,
so it establishes neither fresh-Agent performance nor NDU economic benefit.
Replaying older native NDU trials against their strongest control gives mixed
full-cost savings; the stable-benefit gate remains open.

## Remaining promotion gates

| Gate | Current result |
| --- | --- |
| Original cutover/evaluation authority | Reconciled; cutover failed, evaluation unchanged |
| Exact v4 core HTTP workflow | Retained pass for its old source pair |
| Live cancel/reconnect/no-duplicate inventory | Incomplete; original inventory gate preserved |
| Fresh Agent sees tools and learns language | Not completed in an ordinary registered Agent |
| Safe Core model-to-final-bytes chain | Implemented and locally qualified for the declared profile |
| Selfhost 8,192 instruction subset | Implemented; integrated cold replay 10/10, inner 154/154 |
| General ownership/checker/recursion/linking/backend | Outside current subset |
| Strong ordinary baseline | Implemented; native task observations retained |
| NDU final-use benefit at equal complete cost | Not established |
| Default-branch or live-service promotion | Not granted by a source lock or these local results |

The next live attempt must name a qualified exact runtime/source pair and use
the reconciled original operation as its predecessor. Old failures, unknowns,
timeouts and costs remain part of the record.
