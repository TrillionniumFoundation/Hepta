# V4 response diagnosis

This analysis reads the original response bytes and recorded validation outcomes. It does not repair, compile or rescore a candidate.

Complete scored responses: 15; valid declared files envelopes: 15. Unchanged providers: 8; unchanged consumers: 12; byte-identical second responses: 6.

The following table separates admission from executed public semantics. A profile refusal does not prove that the program body is semantically wrong.

| Family | Cell | Submission | Recorded outcome | Envelope valid | Provider unchanged | Repeated text |
| --- | --- | ---: | --- | --- | --- | --- |
| qwen_coder1_5b | average_floor_stamp_hia | 1 | budget_timeout | None | None | None |
| qwen_coder1_5b | average_floor_stamp_assembly | 1 | response_rejected | True | False | False |
| qwen_coder1_5b | average_floor_stamp_assembly | 2 | response_rejected | True | False | True |
| qwen_coder1_5b | average_floor_stamp_rust | 1 | observable_wrong | True | True | False |
| qwen_coder1_5b | average_floor_stamp_rust | 2 | observable_wrong | True | True | True |
| qwen_coder1_5b | clamped_delta_bias_assembly | 1 | observable_wrong | True | True | False |
| qwen_coder1_5b | clamped_delta_bias_assembly | 2 | observable_wrong | True | True | True |
| qwen_coder1_5b | clamped_delta_bias_rust | 1 | observable_wrong | True | True | False |
| qwen_coder1_5b | clamped_delta_bias_rust | 2 | observable_wrong | True | True | True |
| qwen_coder1_5b | clamped_delta_bias_hia | 1 | observable_wrong | True | True | False |
| qwen_coder1_5b | clamped_delta_bias_hia | 2 | observable_wrong | True | True | True |
| qwen_coder1_5b | stride_span_v2_rust | 1 | compile_rejected | True | False | False |
| qwen_coder1_5b | stride_span_v2_rust | 2 | compile_rejected | True | False | False |
| qwen_coder1_5b | stride_span_v2_hia | 1 | budget_timeout | None | None | None |
| qwen_coder1_5b | stride_span_v2_assembly | 1 | budget_timeout | None | None | None |
| qwen_coder1_5b | floor_multiple_v2_hia | 1 | budget_timeout | None | None | None |
| qwen_coder1_5b | floor_multiple_v2_assembly | 1 | response_rejected | True | False | False |
| qwen_coder1_5b | floor_multiple_v2_assembly | 2 | budget_timeout | None | None | None |
| qwen_coder1_5b | floor_multiple_v2_rust | 1 | compile_rejected | True | False | False |
| qwen_coder1_5b | floor_multiple_v2_rust | 2 | compile_rejected | True | False | True |
| granite2b | average_floor_stamp_assembly | 1 | budget_timeout | None | None | None |
| granite2b | average_floor_stamp_rust | 1 | budget_timeout | None | None | None |
| granite2b | average_floor_stamp_hia | 1 | generation_infrastructure_failure | None | None | None |

The v4 Rust prompt enumerates the reused finite method whitelist explicitly. The scalar scanner remains restricted and may reject otherwise valid Rust spellings, including callable-looking '} (' syntax. A profile refusal does not establish whether a submitted body is semantically correct. Preserve the raw code and observed diagnostic; no prompt, whitelist, response or score was changed after model requests began.

The envelope-only schema does not encode a repair. Its success can remove a transport-format failure while leaving the original semantic bug or interface unchanged. This finite descriptive observation does not establish a general Agent productivity advantage.
