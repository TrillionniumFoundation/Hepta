# V10 capacity rows

| Registered cell | Reference passed | Initial tokens | Complete reference tokens | Max observed repair + output | Registered allocation + output |
|---|---|---:|---:|---:|---:|
| calibration/json_scalar_reasoning/calibration | True | 1392 | 55 | 3725 | 5872 |
| calibration/two_file_signature_repair/calibration | True | 1762 | 109 | 3770 | 6242 |
| calibration/owner_flow_repair/calibration | True | 2242 | 65 | 4663 | 6722 |
| main/saturating_score/hia_full | True | 1201 | 661 | 3892 | 5681 |
| main/saturating_score/hia_node | True | 1533 | 259 | 3822 | 6013 |
| main/saturating_score/rust_full | True | 770 | 94 | 3080 | 5250 |
| main/saturating_score/rust_node | True | 1701 | 48 | 3957 | 6181 |
| main/wide_span_upgrade/hia_node | True | 1899 | 292 | 4100 | 6379 |
| main/wide_span_upgrade/rust_full | True | 842 | 94 | 2844 | 5322 |
| main/wide_span_upgrade/rust_node | True | 2112 | 145 | 4168 | 6592 |
| main/wide_span_upgrade/hia_full | True | 1438 | 587 | 3983 | 5918 |
| main/owned_byte_return/rust_full | True | 857 | 145 | 3226 | 5337 |
| main/owned_byte_return/rust_node | True | 2577 | 44 | 4845 | 7057 |
| main/owned_byte_return/hia_full | True | 1769 | 1059 | 4868 | 6249 |
| main/owned_byte_return/hia_node | True | 2606 | 127 | 4773 | 7086 |
| main/owner_pair_replace/rust_node | True | 2783 | 44 | 5023 | 7263 |
| main/owner_pair_replace/hia_full | True | 1640 | 945 | 4581 | 6120 |
| main/owner_pair_replace/hia_node | True | 2373 | 109 | 4478 | 6853 |
| main/owner_pair_replace/rust_full | True | 852 | 157 | 3200 | 5332 |

All 19 controls are human references and generated 0 model responses. Each row has four exact rendered-request CLI checks and one exact reference-response CLI check. Per-request tokenization with full output reserve remains mandatory; allocation envelopes do not prove a bound for every possible BPE string.
