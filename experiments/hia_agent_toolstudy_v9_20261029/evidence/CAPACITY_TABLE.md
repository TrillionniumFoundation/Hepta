# V9 fresh exact capacity and native references

Frozen source `ef9fbafabe9db52a5e59220f1738d5842ac164cc`; all 19 native/public/resource/terminal hidden references passed. Model generation requests: 0.

| Stage/task | Arm | Initial input | Complete correct reference output | Maximum actual repair +1536 output reserve | Allocation +reserve |
| --- | --- | ---: | ---: | ---: | ---: |
| calibration/json_scalar_reasoning | calibration | 1413 | 55 | 3738 | 5893 |
| calibration/two_file_signature_repair | calibration | 1783 | 109 | 3791 | 6263 |
| calibration/owner_flow_repair | calibration | 2263 | 65 | 4692 | 6743 |
| main/saturating_score | hia_full | 1222 | 661 | 3913 | 5702 |
| main/saturating_score | hia_node | 1554 | 259 | 3843 | 6034 |
| main/saturating_score | rust_full | 791 | 94 | 3093 | 5271 |
| main/saturating_score | rust_node | 1722 | 48 | 3980 | 6202 |
| main/wide_span_upgrade | hia_node | 1920 | 292 | 4121 | 6400 |
| main/wide_span_upgrade | rust_full | 863 | 94 | 2865 | 5343 |
| main/wide_span_upgrade | rust_node | 2133 | 145 | 4189 | 6613 |
| main/wide_span_upgrade | hia_full | 1459 | 587 | 4004 | 5939 |
| main/owned_byte_return | rust_full | 878 | 145 | 3240 | 5358 |
| main/owned_byte_return | rust_node | 2598 | 44 | 4864 | 7078 |
| main/owned_byte_return | hia_full | 1790 | 1059 | 4889 | 6270 |
| main/owned_byte_return | hia_node | 2627 | 127 | 4794 | 7107 |
| main/owner_pair_replace | rust_node | 2804 | 44 | 5044 | 7284 |
| main/owner_pair_replace | hia_full | 1661 | 945 | 4602 | 6141 |
| main/owner_pair_replace | hia_node | 2394 | 109 | 4499 | 6874 |
| main/owner_pair_replace | rust_full | 873 | 157 | 3221 | 5353 |

The allocation is initial +1664 previous response +1024 public feedback +256 framing +1536 reserved output, not a universal BPE bound. Every actual generation request is independently rendered/tokenized and checked. Up to three submissions are allowed; complete previous-response or irreducible public-feedback overflow ends a cell without code truncation.

The V9 initial prompts differ from V8 only by the registered generic node-contract strings; full prompts, query catalogues and reference answers are unchanged. Compiler diagnostic paths belong to the new run and can alter repair token counts. All complete request/reference tokens were measured again; no V8 capacity or qualification is inherited.
