# Seven exact ASCII-reader candidates

Status: source only. HIA assembly/Core parsing, B3 compilation, VM and native execution have not run for this revision. Performance improvement is not yet measured. The whole HIA rewrite remains OPEN.

The preceding seven inline images failed the original complete impact gate: 327 of 329 cases completed. The independent FOLLOW53 reader recovered both failed actual process records: returncode -9, no stdout, no stderr, timed_out false, intervals 90,018,738,413 and 90,020,514,796 ns. There is no terminal frame to compare. These failures stay failures; no per-role timing or signal source is inferred.

This candidate changes only one decoded-character call target in each current decode_string function and appends one 4-block, 23-operation HIA function. It directly returns the original packed position/codepoint for bytes 32..127 except quote34 and backslash92. All other bytes delegate to the complete exact original Unicode reader. An out-of-bounds position delegates before any buffer load. The fallback may repeat one immutable byte read, with no intervening mutation. Every original mutable-buffer write and cursor read/write remains in its original order; there is no bulk access or cross-scalar cursor cache. Arbitrary VM fuel/step equivalence is not claimed.

All seven complete source inverses were actually checked in JavaScript. This text transformation does not execute HIA. The independent source review is Git blob 7ed928ed8b6de6a1443b50ce40bed43dd82aaacf. It covers the helper and exact seven-source change only, not the later builder/CI.

The new builder first reproduces the original 63-source/image table and ELF, including six fresh original B3 compilations and the original HIA packer call. It then reconstructs each entire preceding inline source by removing the added helper and reversing its single call target. The unchanged prior inline checker proves the complete inverse back to the recovered actual original, including role27's existing bijective SSA renaming. Seven new candidate sources must pass actual HIA canonical roundtrip, exact textual-to-Core profile equality and fresh B3; the actual unchanged HIA packer builds the new ELF. Total new builds remain 13 and packer calls 2.

The semantic test differs from the preceding full original test only in its output directory. The original 13 groups/329 case inputs, reference oracles, entire outputs and error text, error ordering, full source/image before/after checks, CAS, original 90 CPU /180 wall /1 GiB process-tree limits and B3 10 CPU /20 wall /256 MiB /1 MiB limits are unchanged. The previous 327 completions are not inherited. Public 1024-function cases remain distinct from the bootstrap 128-function limit.

There is no per-block 128-operation gate. Maximum textual profile among these candidates remains within all original bounds; role27 has79 functions/1445blocks/6901operations/maxSSA2000. Actual HIA/Core/B3 checks remain mandatory.

No original production implementation is activated, replaced or deleted by this candidate.
