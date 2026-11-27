# R11: exact scalar ASCII predicates in the private checker

This is an authored successor of the actual R10 checker. It changes two pure scalar instruction slices, after their original byte loads and casts. It is not generated, compiled, executed, admitted as current cold, or selected by a public/default path.

## Exact change

The new generator is `tools/generate_hia_file_render_checker_word64_ascii.py`; its private output is `examples/hia_bootstrap/file_render_checker_word64_ascii.hepta`. The complete R10 generator and its actual 397,114-byte HIA are preserved as before images. The R8 dense replay, R9 word-width, and R10 byte-I/O transformations remain byte-for-byte intact and run first. The last new projection admits only the exact actual R10 rendered bytes and counts.

Only `f16/next_token_original`, block `b7`, after its two load/cast operations, and `f79/identifier`, block `b4`, after its address/load/cast operations, change. The first predicate drops from 35 pure operations to 14; the second drops from 26 to 18. The proposed inventory is 107 functions, 1,456 blocks, and 6,270 operations, compared with actual R10's 6,299 operations. Every function signature, block parameter, edge argument, and terminator is retained. The other 105 functions are completely unchanged.

All source/workspace reads, their order and address arithmetic, casts, writes, hash arithmetic, calls, range checks, failure bodies, and first-error handling remain in their original locations. No field is narrowed, no source scan is omitted, and no cache or workspace invariant is added. The new slices contain no reads, writes, calls, allocation, or provider access. They compute the same final boolean that the original edge consumes.

## Whole 64-bit domain proof

The delimiter predicate represents exactly `{10,40,41,44,45,58,61,62,91,93,123,125}` using two 64-bit constants. It selects the lower table for `c < 64`, uses `c & 63` as its sole right-shift count, tests the selected low bit, and requires `c < 128`. Therefore the checked shift is always in `[0,63]`, including for every non-ASCII `usize` value. All `c >= 128` return false; all 128 smaller values are exhaustively checked. The source byte was already loaded and cast before this slice, but the proof does not need to assume that range.

The identifier predicate replaces the two letter intervals with `((c | 32) - 97) mod 2**64 < 26`. For `c >= 128`, the folded value is at least 128, so the result is at least 31 and cannot satisfy the comparison. For smaller values, underflow below 97 wraps to the top of the 64-bit range; the admitted interval is exactly folded values 97 through 122, corresponding to the original uppercase and lowercase ASCII letters. The independent underscore equality is preserved algebraically. The wrapped digit interval `(c - 48) mod 2**64 < 10` is true exactly for 48 through 57. It is still conditioned on the unchanged loop index being nonzero. The original failure edge consumes the negation of this union. The proof covers both zero and every nonzero index class; it does not assume an index bound.

The scalar certificate evaluates both actual original operation slices and the authored replacement slices for all 256 bytes and explicit unsigned boundary values, including `2**32`, `2**63`, and `2**64-1`. It also records the above symbolic reduction of the remaining unbounded classes. This is static author logic, not a HIA VM or a product qualification. The complete original Core verifier and whole-document inverse run only during the future authorized generation.

## Traps, intermediate state, and finite fuel

A short source or workspace still traps at the same retained first byte access, before these predicates if applicable. No extra address increment is introduced before or after an access. The new checked shift cannot trap because its count is explicitly masked; wrap subtraction cannot trap. Consequently the same boolean reaches the same original success/error branch and the same subsequent workspace writes. Native size and all actual six-buffer comparisons remain execution obligations.

Removing total scalar instructions intentionally changes finite fuel consumption. A candidate stopped at 10,000,001 ticks need not have the same partial workspace as R10 stopped at that tick; every retained group continues to use its original full Native oracle and original limit. A diagnostic of R10, including its original failed partial, remains immutable. No old failure is relabeled PASS and no historical qualification is inherited.

## Actual cost and distance to completion

The frozen R10 diagnostic has an exact exclusive sum of 10,000,001 ticks and faithfully reproduces its original failed buffers. `f79` consumed 793,131 exclusive ticks, `f16` 1,091,631. The identifier path arithmetic is `793131 = 32*2457 + 40*17663 + 7*1141`; the full-loop-equivalent saving is 141,304 ticks. The counter did not retain an instruction/block trace, so an interrupted predicate suffix is not presented as a directly observed complete block. Delimiter savings are 21 ticks per actual visit to `f16/b7`; that block's dynamic count is not available. The packet preserves this distinction instead of inventing an exact total.

The original failed header is phase 1, current function index 13 of 38, cursor 6,183 of 19,089, token newline at 6,182. Its `parse_function` count is 90, consistent with 38 initial, 38 phase-0 and 14 phase-1 entries. At least 24 function entries and trailing checks remain. A few hundred thousand saved ticks do not establish that this case will finish within 10 million. No final step estimate is asserted.

## Gates and identity

`CONTROL-PLAN.json` preserves the complete original eight-phase matrix, 162 Native order, semantic-six order, kernel-130 order, budgets, failure-stop rule, and old maximum-call declarations. Those paths/pins are retained as the before matrix, never reused as actual R11 inputs. Generation/check must produce the R11 bytes and both earlier proofs plus the new scalar proof; the original size/pack gate then binds actual R11 source/image/ELF. Only after an independent terminal readback may a successor binding select those actual bytes for the original eight groups.

An appended predicate boundary group must compare real R10 and R11 Core fragments and full lexer/identifier functions under the original 180+3 owner and original 10M/1MiB/depth128 limits. It must save inputs, full buffer preimages/postimages, return/trap/resource data and cleanup before assertions. It cannot substitute a host predicate, mocked owner, or fallback for its positive HIA calls. Its exact implementation/actual binding remain separate pending authoring, and it cannot remove any original group.

The ordinary compiler, its default source, the public R5 profile, old 210-resource closure, current-cold records, old tests and every original failure stay unchanged. There is no product execution authorization in this packet.
