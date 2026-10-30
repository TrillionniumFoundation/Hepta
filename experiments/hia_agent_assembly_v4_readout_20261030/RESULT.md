# Three-arm Agent v4: actual results

This readout reconstructs scores and costs from retained transport, candidate and native-execution evidence. It performs no new inference, compilation, VM execution or native execution. Admitted assembly is reparsed through the exact frozen frontend to check the submitted source-to-Core binding.

| Family | Stratum | Language | Correct / attempted (planned) | Submissions | Input tokens | Output tokens | Total tokens | Full validation seconds |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| qwen_coder1_5b | maintenance | hia | 0/2 (2) | 3 | 3340 | unknown | unknown | 4.044642 |
| qwen_coder1_5b | maintenance | assembly | 0/2 (2) | 4 | 3925 | 1170 | 5095 | 3.001004 |
| qwen_coder1_5b | maintenance | rust | 0/2 (2) | 4 | 2679 | 444 | 3123 | 3.981491 |
| qwen_coder1_5b | upgrade | hia | 0/2 (2) | 2 | 2004 | unknown | unknown | 5.901679 |
| qwen_coder1_5b | upgrade | assembly | 0/2 (2) | 3 | 3093 | unknown | unknown | 7.337542 |
| qwen_coder1_5b | upgrade | rust | 0/2 (2) | 4 | 3800 | 574 | 4374 | 7.720573 |
| granite2b | maintenance | hia | 0/1 (2) | 1 | unknown | unknown | unknown | unknown |
| granite2b | maintenance | assembly | 0/1 (2) | 1 | unknown | unknown | unknown | unknown |
| granite2b | maintenance | rust | 0/1 (2) | 1 | unknown | unknown | unknown | unknown |
| granite2b | upgrade | hia | 0/0 (2) | 0 | unknown | unknown | unknown | unknown |
| granite2b | upgrade | assembly | 0/0 (2) | 0 | unknown | unknown | unknown | unknown |
| granite2b | upgrade | rust | 0/0 (2) | 0 | unknown | unknown | unknown | unknown |

Actual completion requests: **23**; complete responses: **15**. Every failed attempt remains in the task denominator.

Attempted cells: **15/24**. Complete valid cohort coverage: **False**. Unattempted cells are missing observations, not failed model answers; an incomplete family cannot support a completed cross-family comparison.

Cross-family maintenance gate: **False**. Cross-family upgrade gate: **False**.

Assembly versus JSON maintenance gate: **False**. Assembly versus JSON upgrade gate: **False**.

Validation includes compilation, public and hidden native checks, provider observations and boundary identity checks. Model wall time also includes reference controls, hashing, startup, shutdown and restarts. These are nested intervals and must not be added twice. Download, non-generative capacity checks and archive creation are separate retained costs. Human labor and tool development are unmeasured.

All three arms used answer-free files envelopes and the same two-submission budget, 2,048 maximum output tokens and a hard 180-second entire-generate deadline. The HIA provider trace is an actual same-Core VM trace beside a separate native entrypoint; the Rust provider trace is native. These are full-context arithmetic tasks in two small quantized model families; there is no query advantage, large-project or universal-language claim.

The independently frozen source snapshot binds 31 actual evaluator dependencies. It is modified from the recorded base commit and is not represented as the final complete repository tree. Prior v3 results remain unchanged.
