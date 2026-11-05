# Agent delivery and cost audit

**No Agent productivity improvement is established. The sole referenced historical cohort delivered 0/16 correct cells after 29 model requests: 26 completed answers and three timed-out requests.**

This audit made no model requests, opened no tokenizer/model capacity session and executed no new native candidates. It checks retained raw files and source identities. The full per-attempt ledger, including all three unknown timeout output counts, is in `agent-audit.json`.

## Distinct evidence sets

| Evidence | Source | Denominator and outcome | Meaning |
| --- | --- | --- | --- |
| Historical upstream v10 | `b47ce924c5941b42448e9da0b07a2bcedaf75d1f` | 16 cells, 29 requests, 26 complete returns, 3 timeouts; 0 correct | Actual model cohort |
| Public-edit-feedback change | `c151c505c6feedd811f95d17854e7c5ee84c0baa` | 26 saved answers replayed, 26 unchanged edit verdicts; 0 new requests | Feedback implementation/replay evidence |
| S3 composition Agent controls | `996e2626d9aa89bc0e2b1017ebb858c6666604e7` | 10 reference/rejection controls passed; 0 model requests | Infrastructure qualification |

Four historical arms each have four cells and zero correct deliveries. Thirteen cells ended at public validation failure; three Granite/HIA cells ended at the 240-second generation deadline on their first attempt and were not retried. Seven terminal cells failed the edit contract. The 14 returned answers admitted past editing were not correct solutions. All five owned model sessions have retained successful reaping/identity cleanup records.

## Model, tool and budget boundary

The fixed models are Qwen2.5-Coder-1.5B-Instruct Q4_K_M and Granite-3.3-2B-Instruct Q4_K_M. Recorded model hashes and the full 39-file llama b11669 runtime inventory remain in the machine report. Every arm received the same 32,768-token context, 7,168-token output ceiling, 240-second request deadline, maximum two attempts, greedy seed 0 decoding, generic JSON-object syntax and no prompt cache. The owned servers used CPUs 16-19, four inference/batch threads, one slot and `--device none`; no GPU was used. This is historical configuration evidence; the audit did not rehash the multi-gigabyte model files for an unrequested new run.

Same public information does not mean equal prompt length: Qwen floor full-source prompts were 5,398 tokens for HIA assembly and 755 for Rust (Granite: 6,450 and 844). These representation costs are retained. This bounded harness supplies compile/public-native feedback; it is not evidence about a general repository Agent with an unrestricted tool suite.

## Costs and failures

Known inputs total 63,255 tokens and known returned outputs total 6,729. The three timed-out output totals remain null, so total output usage is incomplete. All cost-per-correct fields are null because no arm delivered a correct task.

The original outer observer records **2,564.181270859 seconds** for preparation and the complete cohort. Its child phases are 42.564103902 s preparation and 2,521.403895170 s run, with 0.213271787 s outer overhead. The inner cohort (2,521.096332288 s) and inner preparation (41.888793866 s) are contained in those totals and must not be added again. Hypothetical solo-arm allocations duplicate shared costs; they cannot be summed as actual elapsed time. Earlier development, human work, historical model acquisition and energy are not established as zero.

## What the real upstream tasks actually change

Both tasks adapt the same stb commit `c38ec91d229cbe56167f8af865c05b3d92db705f`, whose parent is `dcb1116f1351bc8edad059d9ca432e8f322ba922` (stb_divide 0.93). The post-fix complete header is pinned at `003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5` (0.94). The report includes exact diffs extracted from both retained complete headers.

The floor repair replaces overflow-prone prechecks/expressions in two signed branches with range checks against `INT_MIN` and safely grouped expressions. The Euclidean remainder repair replaces positive absolute-value construction with a negative magnitude so `INT_MIN` need not be negated. Both selected function signatures stay unchanged. These are real, correlated arithmetic maintenance problems; they do not exercise interface migration, multiple modules, ownership/resource lifecycles or maintenance of the full upstream repository.

The starting HIA floor port has 29 blocks and 94 operations. Its accepted reference is a separately authored widened quotient/remainder solution (one block, 16 operations), because the proposed full captured after-version inlining remained unknown under the existing solver budget. It is not a proved C-to-Core rewrite. The remainder has a captured scalar representation with its stated bounded inlining/representation checks; a general C refinement theorem remains absent.

## Why another run of these two tasks cannot close the requested goal

The new public editing feedback is actually connected to the second model request and treats both languages/interfaces symmetrically. It exposes only previously disclosed contract facts; initial prompt and edit-materialization functions are unchanged. Running it on the old tasks would be a new feedback engineering observation, but the tasks were already inspected and used to design this change. Such a run cannot supply independent task-generalization evidence, and it would still omit interface and cross-module work. No such run was launched.

The current evaluator explicitly requires one source file and one `target(i32,i32)->i32` function. Its admitted language profiles exclude imports, extra functions, resources, loops and FFI. Merely adding more prompts cannot turn this into an interface-upgrade or cross-module study. The evaluator and negative/reference controls must first support those task shapes.

## Requirements for the next independent protocol

Select and freeze previously unused real upstream maintenance, API-upgrade and multi-module tasks, with pinned before/fix commits, build options, ABI contracts and error/lifecycle checks. Do not reduce the broader tasks to scalar kernels or select tasks after inspecting model outcomes. Build equal tool capabilities and full/patch interfaces for both languages, quarantine references and hidden cases, and qualify every reference and historical-defect control before generation.

Freeze the complete candidate and model/runtime identities, all expected cells and common budgets, actual tokenizer/reference capacity, public-only feedback, terminal hidden evaluation, timeout/cleanup rules and full outer cost ledger before requesting answers. Retain every failure and missing usage in the planned denominator. Report results by model and task family with enough independent repetitions to support the intended claim. No new task corpus or runnable protocol is falsely claimed to be ready in this audit.
