# Matched Agent maintenance and upgrade study, v3

This is a new four-task experiment. It does not rewrite, repair, or rescore the
previous `hia_optimizer_eval/next_20261028` experiment. The old model failures
remain historical observations.

## Completed observation

Both registered model families finished all eight cells. **No task passed the
public correctness gate, so no hidden validation ran.** Maintenance, upgrade,
and joint Agent-advantage gates are all false. This is a complete negative
observation for the registered finite pilot, not a general comparison of the
languages or of larger models.

| Family | Attempted cells | Correct cells | Requests | Complete responses | Timeouts | Whole study process seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen2.5-Coder 1.5B | 8 | 0 | 16 | 15 | 1 | 1100.226681 |
| Granite 3.3 2B | 8 | 0 | 14 | 11 | 3 | 1378.620626 |
| Total | 16 | 0 | 30 | 26 | 4 | 2478.847307 |

Every complete response satisfied the common `files` envelope: 26/26. Fourteen
submissions compiled and executed but produced wrong public observations; ten
were refused at source admission; two were refused by the native compiler; four
requests timed out. The timeout cells ended immediately, and subsequent cells
continued through fresh owned processes. Six owned server processes exited,
and every cell boundary identity check passed.

The complete input count is 30,496 tokens. The known output subtotal is 10,953;
four timeout output counts remain unknown, so the full output and combined
token totals are **null**. Fourteen automatic public-feedback repair rounds
were used, with no manual repairs. Human labor and tool-development time were
not measured.

The independent readout is
[`READOUT.json`](../hia_agent_matched_v3_readout_20261028/READOUT.json), schema
`hepta.agent.matched-v3.acceptance-readout.v1`. It binds the detailed
[`RESULT.json`](../hia_agent_matched_v3_readout_20261028/RESULT.json) and
[`DIAGNOSIS.json`](../hia_agent_matched_v3_readout_20261028/DIAGNOSIS.json), which
retains original response text and compiler/admission diagnostics. The readout
checks 323 raw evidence files without rerunning a model or candidate.

The registered evaluator, protocol, and original responses stayed unchanged.
The pre-response registration SHA-256 is
`10fdf62284c36ff8251ce1a347c8beaa67c7b92cb90d67dcf6d6f9550db68088`.
The complete raw model folders are retained losslessly in
[`qwen-run-01.tar.xz`](qwen-run-01.tar.xz) and
[`granite-run-01.tar.xz`](granite-run-01.tar.xz), with 275 and 249 verified members
respectively. Their adjacent manifests bind every retained file. Model weights
are excluded. `SUITE_PLAN.json`, `COHORT_RESULT.json`, and both outer process
receipts/logs retain the suite-level context.

### What failed

Qwen's 16 submissions divide into eight executed wrong results, five admission
refusals, two Rust `E0308` compile refusals, and one timeout. The compile refusals
were actual caller/provider argument-width mismatches. Its rounded-tiles Rust
submissions were refused for an undeclared `ceil(...)` call.

Granite's 14 submissions divide into six executed wrong results, five admission
refusals, and three timeouts. The Rust absolute-gap responses contained
`.extend(128)` on an integer expression and were refused by the scalar method
profile; HIA refusals exposed malformed cast attributes or duplicate SSA names.
An admission refusal is distinct from an executed wrong answer. The Rust prompt
describes primitive integer methods more broadly than the reused closed
whitelist; that protocol limitation remains disclosed rather than changed after
responses. The observed `.extend` refusal does not establish that the generated
method is valid Rust.

Thirteen complete responses left the provider unchanged, twelve left the
consumer unchanged, and ten second responses repeated the preceding response
byte for byte. HIA equality compares decoded function objects and Rust equality
ignores whitespace; these counts describe source retention, not semantic
equivalence. The transport envelope worked in this run, while the registered
maintenance and API-upgrade requirements remained unsatisfied.

Both HIA and Rust receive the same mathematical requirement, target interfaces,
public cases, provider obligations, two-submission budget, and hidden oracle.
Each receives its complete two-file workspace and language-specific syntax
instructions. A decoder schema enforces only the common `files` envelope,
declared filenames, and content types. No correct operation, constant, function
body, or reference answer enters that schema. HIA's larger representation and
all syntax guidance are charged in the actual token counts.

## Registered scope

| Stratum | Task | Required change |
| --- | --- | --- |
| Maintenance | `carry_sum_tag` | Preserve the carry of a u32 sum in u64, retaining the tagged consumer |
| Maintenance | `absolute_gap_bias` | Compute an order-independent absolute difference and complete bias |
| Upgrade | `wide_product_tag` | Migrate both operands and result width, then update the caller's tag layout |
| Upgrade | `rounded_tiles_v2` | Migrate to a validity/count pair, support full-width inputs, and reject zero tile size without trapping |

There are three public cases per task and 188–190 hidden cases generated from
fixed boundaries and a new, fixed random seed. Hidden validation runs once,
after the first public-pass submission. A hidden failure never creates another
submission or supplies feedback. The two strata have separate denominators and
gates.

Models are official Qwen2.5-Coder **1.5B** Instruct Q4_K_M and IBM Granite 3.3
**2B** Instruct Q4_K_M, pinned by revision, length, and SHA-256. The Qwen model is
smaller than the earlier 7B experiment, so comparisons across those studies are
not matched model comparisons. Each family has eight cells (four tasks by two
languages), at most two submissions per cell, 2,048 output tokens per submission,
180 seconds per request, 8,192 context tokens, four CPU threads, and greedy
decoding. `LLAMA_ARG_REPACK=0` is checked on the actual owned server process.

This is a **full-context** experiment. It does not measure semantic edit-query
advantage or large-project maintenance productivity.

## Admission and execution

The existing hardened finite scalar source admission is reused unchanged. HIA
adds an acyclic 16-block / 128-operation limit per function. Unsupported
resources, extra functions, recursion, unsafe code, external calls, and other
out-of-profile syntax are refused. A common `files` envelope is checked again
after decoding; schema generation does not confer candidate authority.

Every admitted candidate is actually compiled. Its executable bytes are copied
into a sealed `memfd` before execution, under CPU, address-space, and wall-time
limits. This is a finite source profile and resource envelope, not a general OS
sandbox or a proof of the compiler/OS/hardware.

Entry output alone is insufficient. The provider must independently return the
specified value; the consumer must invoke it once with the original arguments.
Rust uses a trusted native API wrapper and a separate native provider call.
HIA uses an actual call trace in the exact hashed Core VM, together with a
separate native entrypoint execution and VM/native agreement. The HIA trace is
**not** described as a native call counter.

## Failure and identity handling

Each request, response, diagnostic, public validation, hidden validation, and
cost remains in the evidence. A request timeout terminates that cell with
unknown output usage; its missing token count is not zero. The owned process is
closed and identity-checked. The next *different* registered cell uses a new
owned process; the failed cell is not retried. A transport owner, decoder
protocol, native artifact, or other infrastructure failure invalidates the
observation and halts the cohort. Registration, source, tool, runtime, and model
identities are checked at every completed cell boundary.

The final report distinguishes actual cells, submissions, completion requests,
returned responses, correct tasks, failed attempts, token lower bounds, complete
usage, inference time, verification time, automatic repair rounds, server
restarts, and whole-run costs. Human labor and tool-development time remain
unmeasured. Reference controls are never counted as model successes.

## Controls and registration

The 24 reference controls execute both correct and original programs and expose
partial interface migrations. Six additional hostile native controls produce
the correct entry result while violating provider arguments, provider results,
or dynamic invocation; the independent provider checks reject all six. Two
initial hostile fixtures were rejected earlier by syntax admission; their
original records are retained, and corrected fixtures exercise the intended
dynamic checks. Orchestration controls cover timeout continuation, source and
runtime identity rejection, failure-cost retention, and hidden-feedback
exclusion. These are evaluator controls, not generated answers.

`REGISTRATION.json` is created once, after control qualification and independent
review and before any new completion. It binds protocol, tasks, prompts, schema,
evaluation sources, and actual control records. `tokenizer_check.py` can inspect
prompt/reference capacity without issuing any `/completion` request; reference
text is only tokenized and never supplied to inference.

```bash
python3 -B -m unittest discover -s experiments/hia_agent_matched_v3_20261028 -p test_protocol.py -v
python3 -B experiments/hia_agent_matched_v3_20261028/run_study.py register
python3 -B experiments/hia_agent_matched_v3_20261028/run_study.py validate
```

Actual runs additionally require the exact registered model/runtime bytes and
explicit Clang/Rust compiler paths. Outputs use new directories and cannot
overwrite an existing model run. All references to scientific gates describe
this finite paired pilot; they cannot establish a general language advantage.
