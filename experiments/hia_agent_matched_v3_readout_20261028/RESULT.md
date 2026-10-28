# Matched Agent v3: actual results

This readout reconstructs scores and costs from retained transport, candidate and native-execution evidence. It performs no new inference, compilation or native execution.

| Family | Stratum | Language | Correct / 2 | Submissions | Input tokens | Output tokens | Total tokens | Validation seconds |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| qwen_coder1_5b | maintenance | hia | 0/2 | 4 | 5616 | 3518 | 9134 | 4.264775 |
| qwen_coder1_5b | maintenance | rust | 0/2 | 4 | 2367 | 436 | 2803 | 4.938579 |
| qwen_coder1_5b | upgrade | hia | 0/2 | 4 | 6303 | unknown | unknown | 2.448514 |
| qwen_coder1_5b | upgrade | rust | 0/2 | 4 | 2954 | 536 | 3490 | 3.329571 |
| granite2b | maintenance | hia | 0/2 | 3 | 3546 | unknown | unknown | 4.864582 |
| granite2b | maintenance | rust | 0/2 | 4 | 2506 | 506 | 3012 | 5.147364 |
| granite2b | upgrade | hia | 0/2 | 3 | 4003 | unknown | unknown | 3.620466 |
| granite2b | upgrade | rust | 0/2 | 4 | 3201 | 651 | 3852 | 6.791251 |

Actual completion requests: **30**; complete responses: **26**. Every failed attempt remains in the task denominator.

Cross-family maintenance gate: **False**. Cross-family upgrade gate: **False**.

Validation includes compilation, public and hidden native checks, provider observations and boundary identity checks. Model wall time also includes reference controls, hashing, startup, shutdown and restarts. These are nested intervals and must not be added twice. Download, non-generative capacity checks and archive creation are separate retained costs. Human labor and tool development are unmeasured.

Both languages used the same answer-free files envelope and two-submission budget. The HIA provider trace is an actual same-Core VM trace beside a separate native entrypoint; the Rust provider trace is native. These are full-context arithmetic tasks in two small quantized model families; there is no query advantage, large-project or universal-language claim.
