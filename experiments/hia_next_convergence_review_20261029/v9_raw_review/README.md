# V9 independent raw accounting and source review

The completed V9 calibration is attributed to `ef9fbafabe9db52a5e59220f1738d5842ac164cc`; RESULT SHA256 is `3f8ff14bcfdd18cf627245626f8c3990c017acbe69898308145a99a716c6f473`. This is separate from later unified-source CI reference controls. The measured raw observations and their source identities remain unchanged.

## Actual costs and outcomes

- **9/9 actual requests and complete EOS responses**, **21,803 input + 3,479 output = 25,282 tokens**. Unknown usage and partial-output residuals are zero. Actual submitted prompt IDs, preparation messages, SSE concatenated output IDs/text, final timing/usage token counts, and cell response/usage records agree. All nine failed submissions remain in the denominator.
- **0/3 qualification tasks**, zero first-submission successes, zero public native executions, zero terminal hidden executions. The actual main invocation refused before engine construction: zero main cells and model requests. No HIA model arm or between-language efficiency comparison occurred.

| Recorded clock boundary | Seconds |
|---|---:|
| Sum of HTTP/SSE transports | 2199.867711180 |
| Sum of generation wrapper calls | 2200.104980079 |
| Complete qualification experiment | 2261.307883468 |
| Separate tokenizer/reference capacity phase | 76.953562987 |
| Separate actual main-refusal invocation | 12.242381912 |
| Sum of the three separate experiment/capacity/refusal phases | 2350.503828367 |

Transport, wrapper and qualification durations are nested and must not be added together. The last row sums only the three separate retained phases, not all project development labor, acquisition history or outer-process costs. Clocks are producer observations whose arithmetic is independently reconciled; they were not independently recreated.

## Observed rejection boundaries

Scalar produced three different answers (84, 96 and 92 output tokens). All three actual retained BUILD records equal their evaluation records and bind the pinned rustc identity; each returned code 1 with `E0277` and `E0308`. No scalar native program was built or executed.

API produced exactly the same 2,401-byte / 977-token answer on all three attempts, SHA256 `10b4dfba8e675eab4c1e387335d90a309ab1f5b0c4df02eb75aaaf0971a92684`. Its actual error is `E_STRUCTURED_RUST: only disclosed scalar/Vec<u8> types`.

Owner produced exactly the same 256-byte / 92-token answer on all three attempts, SHA256 `8e08e629d8d1eb6b84196816b4532225c7afc70d256c4b06292832f417a10ee9`. Its actual combined gate is `E_STRUCTURED_EDIT: duplicate, unknown or unauthorized node`. Both selected IDs are preserved: `api.rs/touch/n4` exists, while `api.rs/touch/n21` is absent from the original 48-node captured query. The query's outer and nested canonical digests were independently recomputed. No later syntax, native or resource outcome is inferred. These are observed rejections, not a counterfactual claim that a human-repaired answer would pass.

## Identity, capacity and feedback checks

All **172 source snapshot files** match their declared hashes and were additionally compared directly to **172 immutable Git blobs at ef9fbaf**, without lazy fetching. All 39 retained runtime companion identity records and the model before/after records agree; each cell boundary reports stable source/model/tools. This does not represent a new multi-gigabyte model hash or independent historical process monitoring.

The completed engine records `exited=true`. The producer's additional owned-process absence receipt SHA256 `7dbab8316b27d8f1a182fe11d66120d1a02248adec6517a48340a8932d8de013` binds the exact original identity file and PID 336841. That historical absence remains attributed to its producer.

The separate capacity receipt retains 19/19 human controls and zero generation requests. Its maxima are initial input 2,804 tokens, complete reference output 1,059, observed repair-plus-reserve 5,044, and allocated envelope-plus-reserve 7,284 of 8,192. Every actual generation request independently passed its exact recorded context/reserve check. Control success does not count as model qualification.

Repair messages contain the unchanged initial message and complete immediately previous answer. All predecessors were public rejections, no hidden files exist, and every new task resets the conversation. No hidden feedback request was inserted.

## Audit execution and preserved development attempt

The parameterized standard-library raw audit was prepared before the final V9 RESULT was read, and passed on its first completed V9 run. It invokes no experiment runner, tokenizer, model, native executable, compiler or tests. `REVIEW.json` SHA256 is `6e4499bd58a9bef8829e7cb60cac75d84ed71ade823bf8857c9b2d20de951ddb`.

The source/exit supplement initially stopped because it assumed a pre-build rejection stores explicit null `build`/`public` fields; the legitimate record omits them. `SUPPLEMENT_DEVELOPMENT_01.py` and its raw failure log are preserved. The final supplement reads the optional fields correctly, changes no producer record or gate, and passes. The original raw accounting receipt was not rewritten.

All results remain confined to this adaptively selected protocol/model/host. No general Agent productivity, language superiority, Rust/C/C++ migration safety, or NDU/performance gate is upgraded.
