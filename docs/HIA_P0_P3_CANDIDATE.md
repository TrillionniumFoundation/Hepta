# HIA integrated Agent/native candidate

This candidate extends the exact Agent-native implementation from PR #787 and
includes the regression and artifact-directory permission repair from #789/#791.
Its runtime contract is paired with the existing source
`TrillionniumFoundation/hepta-runtime@9f60a30530f47925f4f6ae495660a1d68bb6947d`.
Platform build changes require their own retained source/build identity. A
production connector endpoint requires its separate live deployment receipt.

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
| P1 | Explicit native-NDU macro advice; original-byte four-arm native campaign; complete observed phase ledger; optional same-provider adapter and strict usage accounting | Real qualified tasks, complete original provider/adoption/downstream-use receipts and independently checked net strategy benefit |
| P2 | Bounded borrowed-byte ABI; HIA-authored fixed-Core scanner, parser, verifier, x86 generator and relocator; actual B0→B1→B2→B3 plus modified compiler rebuilding itself | Preserve the exact generation/rejection evidence on each candidate; broader HIA language coverage and formal compiler correctness are separate extensions |
| P3 | Checked SSA assignments to rbx/r12–r15, register-only CMOV selection, scratch mapping, immediate forms, function/block layout and ELF alignment | Broader register classes/instruction families and real-task full-cost advantage; universal refinement remains unproved |

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

`tools/qualify_hia_macro_campaign.py` runs eight deterministic tasks across
fixed, greedy, ordinary and NDU arms, preserving all planned arms and failures.
Its verifier rechecks original content-addressed bytes, causality, actual native
outputs and cost reconciliation. Two complete native observations changed the
sign of NDU's saving against the strongest control; both remain P1 HOLD. These
fixtures and the optional provider mechanism cannot qualify real-task economics.
See `HIA_AGENT_MACRO_CAMPAIGN_RESULTS_20261107.md` for the measured observations.

### P2 actual fixed-Core self-hosting

`examples/hia_bootstrap/selfhost.hepta` implements the complete selected
toolchain in HIA. Its fixed subset includes integers, booleans, borrowed byte
buffers, branches, loops and forward function calls. B0 uses the existing Python
toolchain only to build the seed. B0's native HIA compiler then reads its full
own source to produce B1; B1 builds B2 and B2 builds B3. Qualification requires
byte-identical successors and retains every input, executable and invocation.

After B0, the standard-library loader only copies and hashes bytes, maps an
image RW then RX, and invokes the fixed byte ABI under resource limits. All
parsing, Core-subset checking, machine encoding and relative relocation are
performed by the executed HIA image. A source edit to the HIA wrapper emitter
must propagate into changed machine instructions and reach a new M2=M3 fixed
point. Independent sample behavior and rejection tests remain required.

`HIA_SELF_HOSTING_CORE.md` specifies the exact grammar, resource/ownership
restrictions and trust boundary. The older finite constant compiler keeps its
correct own-source rejection result; its separate result is not rewritten.

### P3 explicit plans

The Agent chooses reviewed encodings, locations and layouts; the backend
realizes exactly those choices. Version 3 accepts explicit scalar SSA locations
in `rbx/r12–r15`, with conservative inclusive block-local live intervals,
independent edge staging and callee-save preservation. It also permits explicit
register-only CMOV lowering for scalar select. Version 2 retains the `r10/r11`
scratch bijection, immediate and layout choices.

Every plan is frozen as bounded plain data, checked, and bound to Core and
implementation. Native correctness, independent ABI observations and the costs
of failed choices remain separate gates. The register campaign records full
image sizes as well as text sizes; no whole-image saving is inferred from a
smaller instruction sequence.

## Reproduce the finite gates

> Removed source/mixed-campaign reproduction command; its harness is not
> delivered. No historical result is promoted to current qualification.

The unified workflow asserts the exact executing commit and preserves complete
logs/results. All old direct-backend tests remain collected, with no skipped,
expected-failure or omitted cases accepted. Native NDU build/call receipts,
bootstrap observations and any live runtime probe remain separate evidence.

Adoption and deployment require their ordinary authority and live evidence.
Whole-language self-hosting, global optimality and universal safety/performance
claims remain outside the finite evidence collected here.
