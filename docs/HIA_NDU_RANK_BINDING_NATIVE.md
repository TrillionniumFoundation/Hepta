# Native NDU response and fresh-proof bindings

The actual 269584-byte HIA flat is SHA-256 d8b8b223bbace19a922d15eb6b150c1e27a0f6453161e8e2de7ee90a33702cbd. It passed 394 cases: 14 actual sealed HIA evaluator calls, 70 Python numeric-equality boundaries, 201 response mutations, one large unknown response field, 97 fresh-proof bindings and 11 atomic frame refusals. One genuinely fresh sealed unified public proof was used; all eleven evaluator source-closure files were checked against the actual build receipt.

The unchanged original response-check statements are the external oracle. Their only contract migration is the honest HIA response schema and entry point, plus the required reference entry point. Original field priority, digest validation, recommendation availability, hard-violation handling and unhashable list/dict exception text are preserved. Native false flags retain original Python equality semantics (including exact numeric zero); integer and binary64 generation comparisons are exact. The later scalar selection still applies its own stricter types.

## Private ABI

Fixed six-word entry. HIANBD01/256 has mode at 8, first JSON/arena lengths at 16/24, second JSON/arena lengths at 32/40, generation at 48 and function-name length at 56. Tail order is name, first JSON/arena, second JSON/arena. All arenas are the owner's own fresh decodes.

Mode 0 consumes a fresh proof as the first pair; the second pair and generation are zero. Bytes 64/96/128/160 hold the actual before/after Core and before/after input SHA-256 values. The function is bounded by the original 128-byte HIA identifier domain. The role checks the original schema, profile, proved status, scope, function and all four digests. It cannot substitute for executing a fresh proof.

Mode 1 consumes the actual request as the first pair and actual response as the second pair. Name is empty; generation comes from the admitted request, and bytes 64..95 contain the exact request-byte SHA-256. Other digest slots and reserved words are zero. Only the native owner may establish executable custody and produce these inputs.

Work covers at least 131072 plus the larger node count. Output is HIANBDR1/128 with status at 8 (0 ordinary, 1 OptimizationRejected, 2 TypeError), admitted/proved at 16, error number at 24 and error JSON length at 32. Error JSON follows at 128. Private malformed frames and short output do not write output.

The reusable qualifier accepts flat, decoder, evaluator, evaluator-receipt, proof, baseline and output paths. Mutation fixtures are explicitly distinct from real evaluator outputs. This component does not claim full native identity/process ownership, complete rank orchestration or production activation. Exact source, flat, oracle-fragment and evidence hashes are in the companion JSON.
