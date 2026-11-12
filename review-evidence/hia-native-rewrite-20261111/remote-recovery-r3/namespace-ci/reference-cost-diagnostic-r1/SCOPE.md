# Recorded reference cost diagnosis

Status at delivery: new source only; no AST, VM, B3 or native execution has occurred for this diagnostic.

The existing FOLLOW42 qualification failed at its unchanged 900 second aggregate limit. Its complete original archive records 47 native processes which all exited with their expected status, 46 completed replay summaries with 4,817 matching native and returned VM entries, and an incomplete final replay following the successful test 39 native process. This experiment does not alter that result. It does not identify the first unrecorded VM entry as the call in flight.

## What the experiment executes

The original FOLLOW42 archive and index are copied before semantic parsing, fully verified with the already published immutable reader helper, and preserved. All 4,272 regular members, 323,619,640 raw bytes, sizes, modes, and SHA-256 values must match. The helper retains its complete path and symlink checks. The original ZIP digest comes from GitHub metadata; a directory downloaded by Actions does not provide the ZIP bytes.

Six exact original HIA source and image identities come from the pinned original build report. All sources are assembled with the exact retained 0ef reference. No original image is entered or recompiled. All six original source/image pairs, all canonical documents, loaded reference Python module pins, and before/after checks are recorded.

The script scans original native trace records. In each role it selects the first complete window, the last complete window, and the window with the largest total logical input/output/workspace size. Duplicate windows are counted once. There are between six and eighteen windows. Pending records with no completed native result remain in the original archive and are not used as expected execution results.

Each selected window is run twice through the unchanged retained CoreVM: once with CPU/wall stage measurements and once with cProfile. Every invocation creates fresh owners, views and _Machine state. Both invocations retain the original 4,000,000 step, 32 MiB arena and depth 64 limits. Full input bytes, complete output bytes, complete workspace bytes, return, VM steps and resource counters must agree. There are no masked bytes, cached VM results, reused machine state or substituted instruction implementations. The original native bytes are comparison inputs and are not counted as new native execution.

## Measured boundaries

The timed run separates owner/view byte copies, fresh _Machine construction including its first as_dict, the second as_dict which selects the entry, the actual retained invoke, full-buffer checks, full hex/JSON construction, and gzip cost. Gzip subfields overlap the enclosing full gzip measurement and must not be added twice. The per-window gzip experiment uses level 9 and an explicit flush. FOLLOW42 uses a shared stream without a per-entry flush; its whole-run compression time cannot be inferred from this isolated measurement.

cProfile has a complete binary stats file and an untruncated list of all functions. It is reported separately from the unprofiled timings. No whole-suite performance extrapolation or root-cause assertion is built into the script.

## Limits and custody

One new diagnostic child, including extraction, assembly and every selected window, is held to 90 CPU seconds, 180 wall seconds, 1 GiB AS and zero core size. The exact common controller also has an external 180 second timeout, process-group kill and wait. The child sets PDEATHSIG and checks the parent race. The original qualification's 900 second gate is neither invoked nor replaced.

The child writes an initial summary and a frontier before each actual invocation. Every complete original selected pre/post frame, generated ledger and full profile remains in evidence. The original pinned archive and member index are preserved before parsing, so a later semantic or timeout failure does not lose the original input. The common controller verifies reference/source identities before and after and seals all new evidence. Expanded duplicate originals are in a separate task directory; the complete original archive is sufficient to recover them and is included in the new evidence.

This is a performance diagnosis, not qualification of the Store, namespace, native runtime, or the still failing 900 second suites. A subsequent optimization must retain the entire original test set, every reference and native comparison and the original aggregate budget, and must then execute those gates in full.
