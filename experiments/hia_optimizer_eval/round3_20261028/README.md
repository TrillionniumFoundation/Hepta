# Guarded modular narrowing: independent third study

This directory contains a new protocol and native driver. Previous registrations,
samples, model trials and negative findings are unchanged.

The single registered run has now completed: **112/112 samples, 1,344/1,344
finite native correctness observations, all fourteen joint noninferiority
comparisons and all ten strong-baseline comparisons passed.** No sample was
removed or retried. Full results and all preparation costs are in
[`benchmark-results.md`](benchmark-results.md), with byte-identical raw output
in `benchmark-results.json` and a lossless 275-member archive. The candidate's
time ratios to Rust were 0.787363 and 0.556401 for the two registered kernels.
This does not establish a general language ranking. In particular, reported
but nongated **batch p99 regressed on several full_lifecycle comparisons**;
the registered batch p95 and individual-request p95/p99 gates passed.

The planned comparison includes original HIA, guarded HIA, guarded plus narrowed
HIA, Rust O3/fat LTO, C/C++ O3/full LTO and newly trained C/C++ PGO/LTO. It uses a
new fixed size/seed distribution, seven paired groups and all 112 scheduled
samples. The five strong baselines form a separate ten-comparison subset; the
full gate includes all fourteen comparisons to the candidate.

Besides bulk and batch timing, each sample records 257 individual call latencies
and 65 clock-overhead observations. All raw values remain. Request p95 and p99
are finite empirical observations, not service tail guarantees or population
confidence bounds. No timing correction is subtracted.

The driver consumes an inherited sealed memfd and checks its seals plus the
actual called symbol's executable mapping, device, inode and file extent.
Each process loads just one measured backend. Every candidate must obtain its
fresh independent proof and final native receipt before sampling. Real PGO uses
training inputs only and creates new profraw/profdata files.

`tools/qualify_hia_narrowing_bench.py --register FILE` freezes source, protocol,
driver, explicit tools, solver and relevant compiler/loader environment; it
does not compile or execute a workload. `--run NEW_DIRECTORY --registration
FILE` refuses registration drift. Both modes require explicit compiler,
Rust, profile-tool and linker paths. A new directory is mandatory, and failed
samples are retained rather than retried.

The complete proposal/proof/emission/build/publication intervals are recorded
for each HIA arm; all instrumentation, training and rebuild costs are charged
to the PGO arm. Parent experiment intervals are not added again to nested
command intervals. Installed-tool acquisition, manual engineering time and the
full transitive sysroot dependency closure remain separate limitations.

`tests/test_hia_narrowing_bench.py` contains six control tests. Its synthetic
metrics are only gate controls, never performance evidence. Three native
controls use the driver's **case-only** mode to test actual sealed-image
execution, refusal of an unsealed file, and immunity to mutation of the original
path after snapshot. They make no bulk, tail or PGO training requests.

At protocol drafting time, no registered performance sample or training request
had been made. Actual registration and run results, when present, are separate
evidence files and must not be inferred from these controls.
