# Frozen R5 token timeline: diagnostic only

This scope contains one authorized execution of the frozen R5 semantic checker on the original `root-v8-cross-target-loans` input. It adds observation in a subclass of the original VM and does not replace `tick`, `operation`, the HIA program, a helper, an opcode, a native image, or any input byte. The observer calls the original `invoke` once with its original arguments and depth, returns its result unchanged, and propagates the original exception.

The original limits are 10,000,000 VM steps, a 1,048,576-byte workspace, call depth 128, and the original 180-second process owner plus 3-second cleanup. There was no new generation, compilation, native entry, current-cold execution, or product candidate. The one observed execution remains **FAIL** at step 10,000,001. The complete source, output and workspace buffers, as well as the complete VM report, equal the original R5 failure and the earlier R5 cost diagnostic. All source files and the frozen 552,050-byte development image are unchanged.

## Observation protocol

`TIMELINE.jsonl` records entry and normal return for `compile`, `next_token`, `identifier`, `read_value_name`, `discover_blocks`, `check_graph` and `parse_function`. It would also record any `vxget`/`vxput` call using a slot of 8192 or greater. Each event contains the original function symbol, definition name, depth, actual step counter and selected raw state bytes. Entry records preserve the caller stack and scalar arguments. Returned values are copied only into the log; the real returned list is passed back unchanged.

The state ranges are `[0,40)`, `[40,48)`, `[48,56)`, `[64,80)`, `[120,128)`, `[432,440)`, `[456,488)` and `[1024,1040)`. They cover the token, error, phase, function, prior cursor, signature-pass flag, identifier, value-name count and function/block-parameter counters. The final exception unwinds two watched calls; those calls have entries without invented normal returns. `UNWOUND-CALLS.json` records that distinction. Actual full F/O/W buffers are saved in `finally`, independently of later report assertions.

The result contains 30,388 events for 15,195 watched entries. All 11,316 `next_token` calls and all 2,066 `identifier` calls in the observed prefix returned normally. The maximum observed `read_value_name` slot was 25. This is an observation of this input, not a proof that high SSA slots are absent from the admitted source domain.

## Offline dense replay model

The model has one initial 4-byte key plus contiguous 33-byte records containing the actual post-token bytes `[0,33)`. The key of each later record is the preceding record's post-token cursor. Capacity is `floor((196608 - 4) / 33) = 5957`. It learns only from actual successful normal returns. It does not pre-lex future input, insert an out-of-order record, store an unstated per-record key or gap index, or cache EOF/error returns. A noncontiguous unseen key falls back to the original lexical path.

For early collection during the first signature pass, the actual prefix produces 5,245 records using 173,089 bytes. There are 544 noncontiguous-key fallbacks in that first pass. The second phase-0 prefix can reuse 5,525 calls: 5,025 sequential hits and 500 binary-seek hits, with 6,235 binary comparisons. Those original calls consumed 2,314,398 inclusive VM steps. This number is a **zero-new-cost upper bound**, not a measured speedup. It excludes every guard, lookup, append, copy, metadata and cleanup cost of a prospective HIA implementation. No identifier cost is credited to this token-only layout.

If collection starts only after the first signature pass, the same observed prefix produces only 35 hits and an original-cost ceiling of 16,170 steps. The delayed-start design therefore loses the useful second-pass replay in the measured prefix.

For reference only, an explicit-key dictionary oracle would replace 6,069 calls and 2,591,987 original steps. That oracle has a different storage/lookup contract and is not the 33-byte implicit-key design. It must not be substituted for the dense result.

## Limits of the result

The observed prefix ends in phase 0, signature flag 0, function 35 of 38. No phase-1 execution was observed. The total remaining work, a candidate's runtime costs and its machine image size are unknown. The current combined ELF has only 4096 bytes of spare image space. These observations do not prove completion within 10M steps or fit within that space.

An implementation still needs complete proofs and controls for high-SSA retirement before every overlapping use, cache metadata initialization and restoration on dirty/early-return paths, complete-source overflow fallback, original error order and partial-error state, and all normal-return buffers. Successful repeated cursor states in this single valid prefix do not establish those domains. No candidate was authored or compiled here.

The complete timeline, per-call simulation decisions, retained record bytes, all initial/final buffers, frozen HIA/expanded source/runtime context, process receipts, and analysis code are preserved in the accompanying deterministic archive. The original R1–R7 failures and qualifications are unchanged.
