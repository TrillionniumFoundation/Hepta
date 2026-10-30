# V3 response diagnosis

This analysis reads the original response bytes and recorded validation outcomes. It does not repair, compile or rescore a candidate.

Complete scored responses: 26; valid declared files envelopes: 26. Unchanged providers: 13; unchanged consumers: 12; byte-identical second responses: 10.

The following table separates admission from executed public semantics. A profile refusal does not prove that the program body is semantically wrong.

| Family | Cell | Submission | Recorded outcome | Envelope valid | Provider unchanged | Repeated text |
| --- | --- | ---: | --- | --- | --- | --- |
| qwen_coder1_5b | carry_sum_tag_hia | 1 | observable_wrong | True | True | False |
| qwen_coder1_5b | carry_sum_tag_hia | 2 | observable_wrong | True | True | True |
| qwen_coder1_5b | carry_sum_tag_rust | 1 | observable_wrong | True | True | False |
| qwen_coder1_5b | carry_sum_tag_rust | 2 | observable_wrong | True | True | True |
| qwen_coder1_5b | absolute_gap_bias_rust | 1 | observable_wrong | True | True | False |
| qwen_coder1_5b | absolute_gap_bias_rust | 2 | observable_wrong | True | True | True |
| qwen_coder1_5b | absolute_gap_bias_hia | 1 | observable_wrong | True | True | False |
| qwen_coder1_5b | absolute_gap_bias_hia | 2 | observable_wrong | True | True | True |
| qwen_coder1_5b | wide_product_tag_hia | 1 | response_rejected | True | False | False |
| qwen_coder1_5b | wide_product_tag_hia | 2 | budget_timeout | None | None | None |
| qwen_coder1_5b | wide_product_tag_rust | 1 | compile_rejected | True | False | False |
| qwen_coder1_5b | wide_product_tag_rust | 2 | compile_rejected | True | False | False |
| qwen_coder1_5b | rounded_tiles_v2_rust | 1 | response_rejected | True | False | False |
| qwen_coder1_5b | rounded_tiles_v2_rust | 2 | response_rejected | True | False | True |
| qwen_coder1_5b | rounded_tiles_v2_hia | 1 | response_rejected | True | True | False |
| qwen_coder1_5b | rounded_tiles_v2_hia | 2 | response_rejected | True | True | False |
| granite2b | carry_sum_tag_rust | 1 | observable_wrong | True | True | False |
| granite2b | carry_sum_tag_rust | 2 | observable_wrong | True | True | True |
| granite2b | carry_sum_tag_hia | 1 | budget_timeout | None | None | None |
| granite2b | absolute_gap_bias_hia | 1 | response_rejected | True | True | False |
| granite2b | absolute_gap_bias_hia | 2 | budget_timeout | None | None | None |
| granite2b | absolute_gap_bias_rust | 1 | response_rejected | True | False | False |
| granite2b | absolute_gap_bias_rust | 2 | response_rejected | True | False | True |
| granite2b | wide_product_tag_rust | 1 | observable_wrong | True | False | False |
| granite2b | wide_product_tag_rust | 2 | observable_wrong | True | False | True |
| granite2b | wide_product_tag_hia | 1 | budget_timeout | None | None | None |
| granite2b | rounded_tiles_v2_hia | 1 | response_rejected | True | False | False |
| granite2b | rounded_tiles_v2_hia | 2 | response_rejected | True | False | True |
| granite2b | rounded_tiles_v2_rust | 1 | observable_wrong | True | False | False |
| granite2b | rounded_tiles_v2_rust | 2 | observable_wrong | True | False | True |

Rust prompt describes standard primitive integer methods broadly, but the reused closed admission whitelist excludes some methods (e.g. div_ceil). A method-profile refusal does not establish that the method is valid Rust or that the arithmetic is correct or incorrect; preserve the observed name and raw code. Frozen prompts/whitelist/results were not altered after model requests began.

The envelope-only schema does not encode a repair. Its success can remove a transport-format failure while leaving the original semantic bug or interface unchanged. This finite descriptive observation does not establish a general Agent productivity advantage.
