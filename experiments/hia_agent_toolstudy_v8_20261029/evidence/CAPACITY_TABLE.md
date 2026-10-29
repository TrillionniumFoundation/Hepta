# V8 actual capacity and reference controls

Source `33c46cdef12c60faf0c1dbef02ea20caa3ad7d56`; 19/19 real compiler/public/resource/terminal hidden reference controls passed; zero model-generation requests. References never establish model eligibility.

| Stage/task | Arm | Initial input | Complete correct reference output | Maximum observed repair +1536 output reserve | Allocated repair envelope +reserve |
| --- | --- | ---: | ---: | ---: | ---: |
| calibration/json_scalar_reasoning | calibration | 1367 | 55 | 3701 | 5847 |
| calibration/two_file_signature_repair | calibration | 1737 | 109 | 3745 | 6217 |
| calibration/owner_flow_repair | calibration | 2217 | 65 | 4642 | 6697 |
| main/saturating_score | hia_full | 1222 | 661 | 3913 | 5702 |
| main/saturating_score | hia_node | 1546 | 259 | 3835 | 6026 |
| main/saturating_score | rust_full | 791 | 94 | 3102 | 5271 |
| main/saturating_score | rust_node | 1676 | 48 | 3929 | 6156 |
| main/wide_span_upgrade | hia_node | 1912 | 292 | 4113 | 6392 |
| main/wide_span_upgrade | rust_full | 863 | 94 | 2865 | 5343 |
| main/wide_span_upgrade | rust_node | 2087 | 145 | 4143 | 6567 |
| main/wide_span_upgrade | hia_full | 1459 | 587 | 4004 | 5939 |
| main/owned_byte_return | rust_full | 878 | 145 | 3249 | 5358 |
| main/owned_byte_return | rust_node | 2552 | 44 | 4824 | 7032 |
| main/owned_byte_return | hia_full | 1790 | 1059 | 4889 | 6270 |
| main/owned_byte_return | hia_node | 2619 | 127 | 4786 | 7099 |
| main/owner_pair_replace | rust_node | 2758 | 44 | 5001 | 7238 |
| main/owner_pair_replace | hia_full | 1661 | 945 | 4602 | 6141 |
| main/owner_pair_replace | hia_node | 2386 | 109 | 4491 | 6866 |
| main/owner_pair_replace | rust_full | 873 | 157 | 3229 | 5353 |

The allocation column uses initial input +1664 complete previous-response allowance +1024 public feedback allowance +256 framing allowance +1536 reserved output. It is not a universal BPE theorem; every actual rendered generation request is separately tokenized and checked. Up to three submissions are allowed, but an over-budget complete response or irreducible public feedback ends the cell without truncating code.

The actual server template was checked against its exact retained rendered form, and every complete reference response was independently tokenized by the pinned CLI; all token ID sequences matched. Actual request receipts and reference native artifacts are separately hash-bound in the raw manifest.
