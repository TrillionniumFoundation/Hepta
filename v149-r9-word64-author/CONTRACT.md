# Private R9 word64 representation candidate — authored only

This is a new generator and a future new asset. The frozen R8 generator/source/image, ordinary compiler, public R5 component pins, VM implementation and original test bodies stay unchanged. No project generator, compiler, Native entry or VM has been invoked for this candidate.

## Actual blocker and scope

R4 retained Native162 and the same-image edge Native passed. The original six VM controls remain five PASS and one FAIL: `root-v8-cross-target-loans` stops at 10,000,001 steps under the unchanged 10,000,000 limit. Its actual source/output match; workspace and return do not. The saved failure is in second phase0, current function35 of38, error word0, cache5197 records below5956 capacity. This identifies the saved stop location, not a per-function cost profile for that input.

The current real semantic image is549866 B; the current real ELF is1044480 B under a1048576 B limit. The4096 B ELF margin is binding. New code size, pack fit and fuel success are unknown. The old edge call-count arithmetic439960 does not measure cross-target improvement.

## Exact change

`tools/generate_hia_file_render_checker_word64.py` is independently named. Its original compact/cache author construction remains the frozen R8 body. Before the new projection, rendering must reproduce all395910 original R8 bytes with SHA25683953e66677fa0cd7f63f3b1742276d954537df71487c3cd4a6eef9486e3e4de.

Only private integer declarations `u64` become `usize`. Fixed Core defines both as unsigned64 with the identical inclusive range0..18446744073709551615. The source must expose both widths as64. Exactly317 existing `int.cast` operations with `{mode:wrap}` and source/result type pair `{u64,usize}` are total identities. The projection removes those actual operations and redirects each use to its already available source. It does not merely retag a result while leaving hidden casts. The other278 casts remain, including all conversions to/from byte/u32 types.

All107 functions,1456 blocks, function order/names, entries, call attrs, branches, loop edges, returns and resource declarations are retained. External `f0(readbuf,mutbuf,mutbuf)->u32` is exactly the same declaration. The expected6347 op count is arithmetic, not a measured generated result. Every attr, including user syntax/type-code numeric constants, is unchanged.

The projector logs every set/removal with its exact prior value. Reversing that ordered edit log from the actual result must recover the entire original Core document. The complete unchanged Core verifier then runs on the new document. The inverse log does not grant verified authority. The generated report includes the full edit log and removed operations. Existing compact/cache helpers remain unchanged.

## Semantic boundary

`SEMANTIC-REVIEW.json` lists all25 opcodes in the exact old asset and pins complete copies of the actual Core/runtime/selfhost source used for review. Word wraps use the same64-bit mask, comparisons remain unsigned, and checked shifts use the same width and exception text. There are no checked arithmetic operations or checked casts whose error text could contain the changed type spelling. The projector refuses such an unreviewed site.

Every buffer length/load/store/fill_range/move_within, effectful call and error decision remains in its original relative operation order, with equal scalar inputs. There is no buffer cache, initialization assumption, skipped write or weakened bounds check. Ordinary-return and corresponding program-trap F/O/W behavior must still be independently checked against the old reference. Private Core serialization and machine identity change. Compiling different source files does not promise identical compiler scratch.

Removing instructions intentionally reduces VM ticks. A fixed fuel interruption can occur later and show different partial buffers. This is not universal stop equivalence. The original10M cap stays, all historical partial failures stay, and candidate qualification requires return within that cap plus complete actual Native-frame equality. No existing PASS transfers.

Private helper nominal signatures change, so this does not claim source-level compatibility for external direct callers of f1..f106. The resident entry is f0 only. No public opcode, integer width or CPU ISA is added or changed. No current-cold/default/whole qualification is granted.

## Required gates

Original limits remain: compiler128functions/1536blocks/8192ops,20seconds/10CPU/1MiB; owner180+3; semanticVM10M/1MiB/128 depth; final ELF1MiB. The complete original162 inputs, six VM controls,130 kernel controls, seven pipeline VM outcomes with six actual kernel full-frame comparisons, and two last-byte fault controls remain. Actual size/pack must pass first. Original ordered lists are retained in `CONTROL-PLAN.json`.

Surface owns the successor execution binding package. Future source/image/receipt pins remain null until real outputs exist. This packet is ready for review, not permission to execute. Full buffers must be preserved before assertion; failures stop downstream qualification. No shared compiler, public component-pins guard or source checker is relaxed for this candidate.

## Draft provenance

The first candidate remains intact in sibling `candidate/`. R2 adds only the fixed-width assertion and explicit complete projected-Core verification/proof flag. One readonly search guessed two nonexistent source paths and returned rc2; it executed no project code or mutation. Namespace development remains paused and unrelated to this qualification.
