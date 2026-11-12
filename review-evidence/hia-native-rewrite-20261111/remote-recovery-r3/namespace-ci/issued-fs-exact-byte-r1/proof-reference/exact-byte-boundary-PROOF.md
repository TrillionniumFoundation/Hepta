# Exact eight-byte helper expansion: proof obligations and new boundary gate

## Status and scope

This is an unexecuted development candidate. No active namespace author, interpreter, compiler or qualification has been changed. The new gate will compile the original and expanded helper probes afresh and compare the original VM, expanded VM, original native image and expanded native image.

The motivating observation is confined to the eighteen selected returned windows from the original FOLLOW46 diagnostic. They executed 1,451,479 steps in one unprofiled pass, with 3.631170283 seconds of invoke CPU. The profiled pass has 7.574093403 seconds of summed self time including profiling overhead. Those are samples, not a measurement of the interrupted whole 900-second suite. The second decode cost was only 0.175736005 seconds. There is no whole-suite speedup claim.

## Exact source boundary

The transformation accepts exactly one byte-for-byte copy of the original read64/get/put definitions from the pinned namespace VALUES author (Git 3d45466a68eca7a88d2352879ea1979848318f63). The original 519-byte helper literal has SHA-256 ce28fa53dae1e10cf3328a535e6911a5f72afe99e18783393b0b20ef539b3708. The expanded 1,432-byte literal has SHA-256 94fdc970665a613c1b441806815dae784e37a3f53235bc5dd56aeed0712c90f7.

It refuses a changed, absent, duplicated or already expanded helper block. Reversing the unique replacement must recover every original source byte. The parsed function inventory, order, signatures, non-helper ASTs and original total-scalar classification must agree. This is not a broad optimization of arbitrary caller programs.

For future DMS integration, the existing exact original DSL guard/origin proof must run on the original pinned DSL first. Only then may the exact helper block be expanded. The existing guard is not changed into a multi-hash allowlist. This delivery does not yet change DMS or any six-role author.

## Arithmetic and access proof

The exact 0ef Builder is Git 540de9366827900d0b82b4893922ffd383c44fef. Its binary Add and Multiply operators emit wrapping integer operations using the left operand type; integer literals here are u64. Its shift operators are checked shifts. The exact interpreter is Git dd24880949eef55aa7516ddafe9e023c09ec48d6 (SHA-256 ce39be78627f253447f1d4e4b3272ba6689c594c31b22e3be204b1fcfea2ca56). The opcode contract is Git dafe100fdc3ffe7edf0f60b97079066ca070803b.

For the original loop, i starts at zero. At iteration k, 0 <= k < 8, i is exactly k; its increment cannot overflow before reaching 8. Multiplication i*8 is exactly one of 0,8,16,24,32,40,48,56, all below 64. Thus replacing those known induction values with literals introduces no checked-shift overflow. The checked left shift wraps its u64 result; it does not reject high result bits when the shift count is valid. The new source still emits the same checked shift operation for each byte.

Every access still computes index+k as a separate u64 wrapping addition. In particular, the new source retains index+0 and does not precompute index+8 or add a whole-range check. This preserves modulo-2^64 address arithmetic, even where an addition would wrap. Each byte load/store retains the original per-byte bounds check. No wider load/store, unsafe pointer cast, bulk copy, native-endian read or speculative later byte access is introduced.

For read64 and get, let A_k be the accumulator after k successful loads. Initially A_0=0. Both versions perform the same load at (index+k) modulo 2^64, shift that byte by 8k and OR it into A_k. By induction the accumulator after every successful prefix is equal. If byte k is out of range, both trap on that same byte after the same earlier reads, with no buffer mutation. If all eight loads succeed, both return the same little-endian u64.

For put, let V_k be the value before store k. Both versions store V_k & 255 at the same wrapping address and then replace V_k with V_k >> 8. The new source keeps that right shift after every successful store, including the eighth. It does not replace it with one checked shift by 64. By induction the stored byte sequence and remaining value after each prefix are equal. If byte k is out of range, the same earlier bytes have already been written, and all later bytes remain untouched. A whole-range precheck would change this partial-write behavior and is expressly excluded.

The removed instructions are the fixed induction variable, loop comparisons, increments and loop edges. Under typed live-buffer preconditions these operations cannot cause program overflow or buffer effects. The function call graph and signatures are unchanged. The full Core verifier, exact compiler and generated profile gates still run.

## What the proof does not claim

VM step counts intentionally change. The original _Machine, tick accounting, step limit, call-depth limit and heap limit are untouched. The transformation does not claim identical stop points for every arbitrarily chosen fuel value. Both programs must actually complete or reach the same specified program trap under the original 4,000,000-step / 32 MiB / depth-64 test limits. Their distinct measured steps are preserved in every original result.

The proof is about these three helper algorithms. It does not prove an ordinary Store transaction, external lease authority, database migration or the complete 42-case physical suite. Those gates remain necessary and their old failures remain unchanged.

## New full boundary corpus

The pinned new corpus has 564 cases. This number is coincidental and is not inherited from the earlier DMS proof.

It covers read64/get/put on short buffers and every successful write prefix from 0 through 8 bytes; offsets at either side of the eight-byte boundary; each of the eight top u64 indices; 4,096-byte buffers; eight representative full u64 values; 48 deterministic nontrivial cases; and three unsupported probe-operation controls. Values and offsets are stored as canonical decimal strings so a JavaScript or JSON binary64 parser cannot round them.

The mathematical fixture oracle uses little-endian scalar conversion and the independently determined successful prefix. The retained original VM and expanded VM must agree on the complete return or exact trap code/text, all three complete operand buffers and resource counters. Steps are recorded separately and the expanded steps may not exceed the original for this corpus.

Every old/new native probe runs in a fresh actual child process. Its actual limit receipt and wait4 outcome are retained. Operand mappings use MAP_SHARED specifically so that bytes written before a native bounds trap remain visible to the parent after the child aborts. The input mapping is read-only. Prefix/suffix canaries and guard pages remain mandatory. A specified bounds trap requires actual SIGILL, not a guessed error value or an arbitrary crash signal. The full source/output/workspace bytes are compared after either return or trap, with no masks.

The required new observations are 564 old VM, 564 expanded VM, 564 original native and 564 expanded native entries: 185 returning cases and 379 trapping cases per revision. They are requirements until execution. Both images are fresh B3 compiles; no image or previous test count is inherited.

## Limits and evidence

Both compiles retain 10 CPU seconds, 20 wall seconds, 256 MiB address space and 1 MiB output/workspace. The complete leaf retains 90 CPU seconds for the reaped process tree, 180 wall seconds, 1 GiB address space and zero core size. The original profile gates remain 128 functions / 1,536 blocks / 8,192 operations / 256 blocks per function / 16 block parameters. The enclosing CI also checks the full common.run CPU and wall receipts.

Canonical HIA source, generated Core, compiler requests/receipts, images, the full corpus, each original before/after operand, VM counters, child ready/return bytes, stdout/stderr, wait4 status and source before/after identities are retained. A partial run is a failure, with the last flushed frontier labelled only as an observation boundary.

A later six-role candidate may be formed only after this exact boundary gate succeeds. It must recompile the actual owners, preserve their source proof preconditions and pass the complete original physical and packer suites at their original limits. This delivery does not activate that later candidate.
