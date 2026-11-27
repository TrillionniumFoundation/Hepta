# Independent private `emit` VM comparison

The original exact 4925/bc276 selfhost HIA program and the candidate in `v83-selfhost-emit-development-r1` were both admitted as complete programs by the retained ordinary Core verifier. Each has 125 functions and 1,459 blocks. The original has 8,104 operations and the candidate 8,152. Their function dictionaries differ only at `f25`; all other 124 complete functions are equal.

The direct comparison invoked that actual `f25(output, workspace, x)` in the ordinary `_Machine`, using the original runtime bytes (SHA-256 `50eff2e57b65ef1680f985027338cf92f513f44df06abc9e3a7cbae271eb2db9`). It did not substitute a Python model of emit. The diagnostic subclass only records real `buffer.load`/`buffer.store` attempts and outcomes around the original operation implementation.

## Result

All **11,412 pairs matched** in the complete initial and final output/workspace bytes, ordered memory accesses including the failing access, return values or exact error type/code/message, ownership liveness and resource counters. There were 8,004 matching bounds traps and 3,408 matching normal returns. The original process supervisor completed with return code zero, no timeout and complete process-group cleanup.

The matrix comprises 7,200 pairs with separate buffers, 4,200 pairs using two actual mutable views of the same owner, and 12 additional successful writes at cursors 255 and 65,535 with sufficiently sized output buffers. It covers phases 0/1/2/3/255; workspace lengths 0/48/49/55/56/57/58/59/60/64; original requested cursors 0/1/7/255/65,535/2^32−1; values 0/1/255/256/2^63/2^64−1; and output lengths 0/1/8/64. The alias cases also cover cursors 48, 55, 56, 57, 58, 59, 60 and 63, including writes overlapping the phase or cursor bytes. An unrepresentable field in a short workspace is retained as a requested case parameter; the complete initial workspace bytes show exactly which bytes were present.

An independently changed HIA negative control deliberately writes the advanced cursor before a phase-two output store. With an empty output, the candidate and this mutant raise the same original output-bounds error, but the mutant has already changed the workspace. The complete comparison detects that difference. This confirms that matching error text alone cannot make the observed result pass.

## Ordering findings

The observed phase-zero path reads only byte 48 and does not touch the cursor. Positive phases read cursor bytes 56–59 in order before any output access. Phase two performs the output store before each cursor store, so a short-output trap leaves all cursor bytes untouched. Other positive phases retain the cursor update without writing output. The original four low-to-high cursor stores, value truncation, cached cursor value under same-owner overlap and 32-bit stored wrap at 2^32−1 are preserved in the matrix.

Both complete 3,324-file source manifests were verified before and after the observation. The original and candidate source trees were not changed. The complete scripts were frozen and Git-read back before execution; all input HIA and generator bytes, full raw observations, the negative-control program, source manifests and the authoritative process receipt are included.

## Scope

This is a CPython 3.12.14 development observation through the ordinary Core VM. It performs no native compilation, native compiler test, performance comparison or cold run. Root owns the separate actual-machine full-buffer controls.

The matrix uses a 10,000-step allowance per direct invocation and a call-depth allowance of 32; no budget stop occurred. The original observed step counts range from 4 to 85, while the candidate ranges from 4 to 72. Those actual step counts are retained and intentionally not treated as equal: internal-call elimination changes finite-VM resource use, so this report does not claim equivalence for every artificial step or call-depth budget. The complete function map is reused between cases; each case has fresh external owners/views, the step count is reset, and all allocation and other resource counters remain unchanged at zero.

Same-owner mutable-view cases test physical alias ordering. They do not extend the public verifier's unique-borrow admission rules. The full observations are losslessly stored as gzip JSONL, with a verified gzip CRC and every record decoded and checked again after completion.
