# Original select delta: strict Agent verification remains HOLD

The original frozen maintenance patch has now been imported as a real
baseline/candidate pair and sent through the actual pinned Agent worker
protocol. Buffer snapshots admit this compiler ABI. The remaining blocker is
the required proof property and its supported domain, not buffer invocation.

The current strict evaluation request is refused before workload evaluation,
and no adoption is attempted. A concrete Core VM observation shows why a
whole-domain equality claim cannot describe this intentional language
extension: the old compiler returns `INVALID` for a valid select-using input,
while the frozen revised compiler returns a generated-image length of 421.
This observation is separate from the existing formal checker, which returns
`unknown` for the requested equivalence.

## Exact original subject

The public task is `selfhost-scalar-select-d1c97d22-20261108`, registered in
`experiments/hia_repository_select_trial_20261108/public/task.json`. Its prompt
requests support for scalar select and preservation of the existing grammar,
other operations, resource rules, limits and errors. It explicitly permits a
precise unsupported lifecycle result while leaving that acceptance item open.
This replay does not modify or retrospectively rerun the original learner study.

| Item | Frozen identity |
|---|---|
| Original source revision | `d1c97d22d503b395ba9b0dfaa87e5a1c1b208fe6` |
| Original source tree | `5e16f76e52f2b44d84b926161333bdfa94671e5f` |
| Original compiler source SHA256 | `85288cfc4b649b2be13175675880f5372f16bf3d9c5d4b78ba21ffa2c90b6b44` |
| Revised compiler source SHA256 | `2dd847d9df46392e4ef4b99c781b45f56c9841ae61127a260be6e8523f042845` |
| Original patch SHA256 | `e74f3c27d6ea7e7ccfc1c9e2a4e7674fecabef08ee0e05236e5a6e2b5bd75cb4` |
| Original canonical Core SHA256 | `40817012035aa8d156a0a9cf24752c0da24138ea207280b4f9fdd4cc25353850` |
| Revised canonical Core SHA256 | `10284cea893a06091e3bb1de5c9e593148915469f820993d49952386503c428b` |

The original compiler has 44 functions; the revision has 45. Both are Core v8.
Applying the compiler-source member of the original multi-file patch to the
exact original source reproduces the candidate bytes. Neither source is
replaced by the current v12/v13 compiler, and neither is used as its own base.

## Actual strict result

The final replay sends 20 calls through fresh, fixed-command worker processes.
Each request and response is bound to the measured worker/backend/catalog
identities and retained with its original correlation values. The frozen
objective requires all four existing acceptance claims; no claim is removed.

| Request/property | Actual result | Meaning |
|---|---|---|
| `core_admission` | `proved` | The revised exact Core passes the whole-program checker |
| `behavior_equivalence` against the real original | `unknown` | Core v8 lies outside the v1-v7 compositional profile; the programs also differ in CFG/effect skeleton |
| `encoding_check` | `proved` | The exact emitted native artifact matches canonical rederivation; this is not semantic machine refinement |
| `lowering_refinement` on the revised native artifact | `unsupported` | The independent Safe Core scalar ELF profile excludes the compiler's borrowed-buffer entry and general resource/CFG behavior |
| `hia_evaluate` | `rejected`, `E_HIA_CLAIM_REQUIRED` | No exact proved `behavior_equivalence` receipt exists for this baseline/candidate pair |
| `hia_adopt` | Not attempted | No qualifying evaluation receipt exists; adopted slot and lease counts remain zero |

The accepted encoding check does not authorize a semantic claim. The rejected
evaluation request did not execute a workload or issue an evaluation receipt.
No alternative objective, fabricated receipt, machine-plan claim or local load
is substituted for that missing gate. All proof responses retain subject,
property, profile, assumptions, checker identity and unproved obligations.

Two independently owned Core-VM child processes then execute the exact
original and revised compilers on the same source/output/workspace snapshots.
Both terminate normally within the unchanged reference budget. The original
returns `4294967295`; the revision returns `421`. Raw VM requests, stdout,
stderr, canonical Core inputs and receipts are retained. The witness executes
no native program and grants no positive all-input proof or adoption authority.
It demonstrates an observable difference under the existing Core VM semantics.

## What would be needed to close this item

The original request is a language capability extension. Its appropriate
semantic obligations are preservation over the formerly admitted source
domain and correct admission/lowering over the new select domain. The current
Agent acceptance vocabulary has only `core_admission`, `behavior_equivalence`,
`lowering_refinement` and `encoding_check`. It has no checked source-language
extension property, and its optimization policy admits no producer-supplied
precondition that could silently narrow the domain.

Closing the original strict task therefore needs an explicit property and a
checker that establishes those domain boundaries and compiler obligations,
plus the missing general machine refinement where required. The source
parser, dynamic buffers, loops, effects, resources and target behavior must
remain part of that subject. Checking a scalar select leaf or a finite set of
compiler inputs cannot be promoted into that whole-compiler conclusion.

The earlier 25-call same-Core continuation still demonstrates the supported
buffer lifecycle and consumer mechanics. It remains a distinct activation
experiment. It neither verifies this semantic delta nor supplies the original
learner's unavailable provider interaction, token ledger or bill. Those costs
remain unknown; the newly observed calls are not appended to the historical
provider transcript as if they had occurred in that learner session.

## Replay and evidence

The immutable raw archive contains both completed replay attempts, the first
attempt's source, the final single-capture input-binding hardening, the exact
installed worker/client source snapshot, frozen original inputs, public task
provenance, all request/response records and retained proof/build artifacts.
SQLite authority state is excluded; no adopted generation was created.

```sh
python -B tools/qualify_hia_agent_original_select_delta.py \
  --original original-selfhost.hepta \
  --candidate candidate-selfhost.hepta \
  --patch fresh-select.patch \
  --output fresh-strict-replay
```

See `analysis.json` (historical path `../review-evidence/hia-agent-original-select-delta-20261108-5e6c/analysis.json`; not shipped in this tree)
for the measured worker identities, all checker/source bindings, exact result
statuses and the remaining property boundary. This is a new isolated worker
reenactment, not remote MCP endpoint qualification, production deployment or a
new fresh-Agent study.
