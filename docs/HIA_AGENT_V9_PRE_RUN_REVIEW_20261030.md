# Independent static review of the prospective V9 Agent run

Date: 2026-10-30. Reviewed source commit:
`28a013dc8b33c190f09fc26a16e205a62858fcaa`.

This is a source review before the proposed fresh V9 run. The reviewer read
protocol, prompt, runner, admission and accounting implementation, plus the
existing V9 test source. The reviewer did not open generated-answer evidence,
see future V9 model responses, run model generation, or rerun tests for this
review. No task, prompt, answer, acceptance rule or experiment script was
modified. This review supplies no Agent success or productivity observation.

## Disposition

The reviewed code supports one prospective, bounded V9 run: 19 successful
capacity controls, then the three fresh qualification cells, then the 16 main
cells only if qualification succeeds. The generic disclosure amendment does
not add a solution or change edit authority. The operational qualifications
below must be observed; in particular, the one-run stop rule and the initial
runtime release provenance are not fully enforced by these scripts.

## Findings from the source

1. **The prompt amendment is limited to the registered node contract.** A
   direct comparison of the checked-in V8 and V9 prompt modules has two changed
   strings: each node ID may occur at most once; Rust replacements must match
   their type/expression category and use disjoint same-file spans. Full-file
   prompt construction, source catalogue rendering, repair messages and chat
   framing are unchanged. The existing `checked_edits`, `propose_rust` and
   `validate_fragment` functions already enforce these rules. V9 adds no
   overlap deletion, host answer repair, selected repair site or extra edit
   authority.

2. **No reference answer flows into a generation request in the reviewed
   path.** Prompt construction selects original/public source, the declared
   task specification and public input/expected pairs. Queries enumerate
   original-source nodes. The shared response schema specifies envelope
   syntax, never a golden node ID, replacement expression or answer. Capacity
   controls intentionally read reference solutions, compile and execute them,
   and send reference histories to template/tokenizer endpoints; they make
   zero `/completion` requests. Qualification/main read the capacity receipt,
   not its reference-answer files. Repair history contains the unchanged
   initial prompt, the model's own immediately previous complete response and
   public feedback only.

3. **The stage gate is fail closed for ordinary runner-produced receipts.**
   `validate_capacity` requires the V9 schema, all 19 registered IDs, successful
   reference/native/resource and token-capacity flags, matching source/prompt/
   model/tool/protocol identities, zero generation requests and an exited
   engine. `validate_qualification` requires the same capacity digest, the
   exact three fresh Rust-node qualification tasks, correct terminal hidden
   outcomes and complete per-attempt usage within the three-submission budget.
   The main runner checks this before starting an engine. Old V8 eligibility
   cannot satisfy the V9 bindings. These are local evidence integrity checks,
   not cryptographic attestation against fabricated receipt files.

4. **Hidden evaluation is terminal and rejected changes are not accumulated.**
   Only accepted public/native/resource candidates reach hidden execution.
   Both hidden success and hidden failure break the attempt loop. Rejected
   node transactions preserve the original source revision; retries use the
   captured original query and must resubmit the entire edit set. Full-file
   rejects likewise install nothing. Each distinct cell starts a fresh message
   history; generated code is not truncated or silently completed by the host.

5. **Capacity is a prospective control, not proof that arbitrary future
   histories fit.** The 19 controls exercise the reference outputs, no-op
   feedback histories and the registered conservative allocation envelope.
   The complete actual server-rendered request is independently tokenized
   again before every real generation, reserving all 1,536 output tokens.
   An actual overflow ends the cell. Public case/resource fields survive
   feedback clipping; raw diagnostics and consumed costs remain evidence.

## Material operational qualifications

- **Initial runtime provenance needs a retained external receipt.** The GGUF
  byte count and SHA-256 are checked against the protocol. In contrast,
  `tool_identities` records the supplied server, tokenizer and companion
  library files and binds later stages to those first-observed files. The
  shared engine records `--version` output, but these entry points do not
  compare the actual runtime against the protocol's b11669 archive SHA-256
  or require a particular version string. Before capacity, verify and retain
  the official archive identity and extraction/version evidence. Stable
  arbitrary runtime bytes alone do not establish that b11669 was used.

- **Qualification exit code is not eligibility.** A complete, stable
  qualification with failed tasks can return exit code 0 because the CLI
  reports `valid_observation`. The controlling result is
  `calibration_eligible`; the main-stage validator separately rejects a failed
  qualification before inference. Do not count a successful process exit as
  3/3 qualification.

- **The single-run failure stop rule is an operator/protocol constraint.**
  A failed qualification blocks main, but the runner has no persistent
  cross-directory ledger preventing another calibration invocation with a new
  output path. For this prospective run, retain every attempt, finish the
  registered three-cell qualification, and stop if it is ineligible. Do not
  tune these prompts, discard costs, substitute tasks or silently repeat this
  7B qualification. A later experiment would need the independent model or
  resource justification specified in the frozen protocol.

- **Run all stages on one integrated, committed source and stable paths.**
  The bindings include compiler and experiment implementation. Capacity from
  a pre-integration checkout is not reusable after relevant code changes.
  Tool/model identities include resolved paths as well as bytes; relocating
  them between stages invalidates the binding. Keep the source and identities
  fixed until the registered run ends.

The protocol already acknowledges adaptive follow-up from V8 and estimates a
small full-file/node tool bundle comparison. Even a successful main run would
be descriptive evidence for these four tasks and this pinned model/runtime;
it would not establish general language superiority, long-term maintenance
productivity, compiler soundness, or formal resource safety.

## Reviewed entry-point identities

The following five file hashes also matched the integration worktree when
reviewed. Imported V8 engine/budget/validation, V7 session/editing/parser, V4
prompt/evaluator, V6 feedback and the owned-runtime implementation were read
to trace the relevant boundaries. No historical result was rescored.

| File | SHA-256 |
| --- | --- |
| `experiments/hia_agent_toolstudy_v9_20261029/PROTOCOL.json` | `3728cbe786092e05070986410357ecf13ad351c82eeeec2ae925cb13242a253c` |
| `experiments/hia_agent_toolstudy_v9_20261029/prompts.py` | `3e8630f11e61eff18fe08f90513a6ee870dc09f69e380c0269210e24df7805cd` |
| `experiments/hia_agent_toolstudy_v9_20261029/support.py` | `c89a0d284e8d48c3dfce1648d53752445952b81153301290d70ba845315adf6e` |
| `tools/qualify_hia_agent_toolstudy_v9.py` | `e809c1c3ef0cb68e1cb83fcd8fde666d7a6a0fd3219680d7440c117befed4218` |
| `tools/qualify_hia_agent_tool_capacity_v9.py` | `be63d4eeb00a4eace4a4ede5118e02c953b233a94d36c1a6f73ca3e8acb75998` |
