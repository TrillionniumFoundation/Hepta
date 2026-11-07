# HIA integrated Agent/native candidate

This candidate extends the exact Agent-native implementation from PR #787 and
includes the regression and artifact-directory permission repair from #789/#791.
Its runtime companion remains the existing, unchanged source
`TrillionniumFoundation/hepta-runtime@9f60a30530f47925f4f6ae495660a1d68bb6947d`.
No production connector endpoint is implied by this source pairing.

## Language and implementation findings

HIA has its own primitive Core syntax and semantics, opcode catalog, type/effect/
ownership checker, interpreter and compact assembly spelling. The direct backend
encodes x86-64 instructions and ELF objects itself. An external linker handles
shared-library linkage after instruction generation. LLVM is not required on
this direct path.

The present HIA assembly is a typed, SSA-oriented systems representation; it is
not a one-mnemonic-per-hardware-instruction notation. Explicit deterministic
lowering and checking remain necessary even when all profitability decisions
are made by the Agent. Independence of a language and selfhosting of its
implementation are separate properties. Python still implements the general
assembler/checker/backend, and Rust implements the runtime/tool process owner.

## Delivery and remaining acceptance

| Priority | Source delivered | Acceptance still required |
| --- | --- | --- |
| P0 | Unified secure source; worker/backend/catalog identity recomputation; source-pair prepare/verify/probe helper; exact runtime contract integration | Actual configured operator profile and endpoint, full deployed catalog observation, live new-source worker round trip |
| P1 | Explicit native-NDU macro advice; observed attempt ledger including unknown/failed costs; four-arm same-Agent/same-budget assessor; discoverable guidance | Real qualified tasks, complete original provider/adoption/downstream-use receipts and independently checked net strategy benefit |
| P2 | Explicit bounded borrowed-byte ABI; disposable source-verified invocation; actual HIA lexer and finite parser/validator/instruction emitter | General sufficient HIA toolchain subset; own-source compilation; genuine B0→B1→B2→B3 and changed-toolchain rebuild |
| P3 | Checked scratch-register mapping, exact immediate forms, function/block layout and actual ELF alignment; separate observations per choice | Broader SSA allocation/instruction families and real-task full-cost advantage; universal refinement remains unproved |

### P0 identities and entry

The installed worker digest measures all `hepta/**/*.py` and the literal
`DISCOVERY_FILES` in `hepta/hia_agent_contract.py`. The backend digest includes
the actual checker, encoder, object writer, byte wrapper and machine-plan
checker. Catalog identity remains its exact bytes; adding referenced discovery
resources does not invent a twelfth MCP tool or change that wire schema.

The existing eleven tools remain: describe, artifact, read, context, inspect,
candidate, verify, emit, evaluate, adopt and rollback (all with `hia_` prefix).
The existing runtime owner retains command authority, budgets, request identity,
no-relaunch semantics, generation/epoch checks and retained versions.

`tools/hia_candidate_preflight.py` prepares measured source/config bindings and
verifies both the HIA family and the whole actual server catalog. Offline
captures are identified as captures. Only an actual probe can report live
observation; neither source tests nor a generated config is deployment evidence.

### P1 macro decisions

The Agent can explicitly ask whether to discover, propose, verify, emit,
evaluate, adopt, use, roll back or stop. The native cost-profile NDU interface
ranks the Agent's finite, source-bound forecasts. It is not a hidden compiler
optimizer, learned world model or proof of independent NDU advantage.

The ledger retains setup, discovery, model calls, search, verification, emission,
evaluation, adoption, rollback, future use and controller costs. Failed/rejected
attempts remain charged; unknown is not zero; budgets do not restart. The
comparison assessor cannot authenticate task outcomes from hashes alone.
Successful native evaluation is separate from a successful economic experiment.

### P2 bootstrap boundary

The HIA lexer reads its actual complete HIA source. The small HIA parser/emitter
reads a supported assembly source, checks its names and integer literal, and
emits actual x86 instructions derived from that input. Mutation changes actual
native results. However, that restricted compiler rejects its own full source.
This is deliberately retained as an unmet selfhosting test, not relabeled a
successful bootstrap.

### P3 explicit plans

The Agent chooses reviewed encodings and layouts; the backend realizes exactly
those choices. The `r10/r11` mapping is a bounded scratch-register bijection, not
general register allocation. Every plan is bound to Core and implementation;
the canonical path remains unchanged when no plan is supplied.

## Reproduce the finite gates

```sh
python -m pip install 'jsonschema==4.25.1'
python -B tools/qualify_hia_candidate.py --output /absolute/new-tests.json
python -B tools/qualify_hia_machine_choices.py --out /absolute/new-machine-observations
python -B tests/hia_candidate_preflight_integration.py --runtime-checkout /absolute/pinned-runtime -v
```

The unified workflow asserts the exact executing commit and preserves complete
logs/results. All old direct-backend tests remain collected, with no skipped,
expected-failure or omitted cases accepted. Native NDU build/call receipts,
bootstrap observations and any live runtime probe remain separate evidence.

This candidate does not authorize adoption, deployment, global optimality,
complete selfhosting or universal safety/performance claims by itself.
