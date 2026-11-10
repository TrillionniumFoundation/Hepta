# Native compiler private header words — scoped acceptance only

Qualified implementation `79b53adaab0dd8d6869f6682e4a30810fc501156`. All 411 cold payloads equal both its Git blobs
and this review tree. Profile v46-native-scanner-words. Only review metadata is
added after the fixed-source run; the preceding parent review custody is retained.

## Exact results

**28 stages PASS, 706.006s**, source clean before/after:
153 source controls; cold 11/11 plus 5,049 native checks in
100.937s under the original 180+3 s limits;
1,242 language witnesses plus 10 outer controls; 193 components; 332 restored Core
controls with zero errors/skips/expected failures; 30 process-hardening controls;
194 prior failed-repository controls;72 x86/AArch64-QEMU ABI calls and original
negative bounds/wrong-result/removed-free controls; four fresh archived-ELF
mutations; default/selected Agent 56 each; real wheel, isolated installed worker,
native profiles and actual current-B3 installed graph/filter all PASS.

This changes only 15 zero-initialized private compiler header words to four-byte
reads/writes. Generic 64-bit get/put, numeric literal word 16, SSA/table/public
values, all input/output/workspace ceilings, two workers and original witnesses
remain. Independent Core VM checks 150 value/offset cases and cleanup. Scoped
symbolic obligations prove helper equivalence for arbitrary other caller bytes
under the explicit zero-high-byte/u32-domain preconditions; two actual SAT
counterexamples retain the limits of that claim. Private invariant reachability,
native ISA refinement and whole compiler correctness are NOT proved.

Four alternating 326-check native development phase pairs all passed. Native
median 5.416→4.955s and supervised phase 8.623→8.289s are observations from reused
compiler/reference diagnostics, NOT fresh cold, remote or general speed guarantees.

## Original failures and open acceptance

Earlier same-source formal01 remains FAIL: the external archived-ELF helper
attempted a previously used evidence filename and exclusive creation refused it.
No old file was overwritten. The corrected02 run is an entirely fresh complete
run in a new directory, not a resumed or relabelled checkpoint.

Parent 17bb's exact whole-repository 389-module/3,590-test PASS remains scoped to
that source. This 79b implementation has no whole-repository terminal result yet.
Parent remote runs 42825541295 and 42829230613 remain FAIL at the unchanged 180 s
cold deadline (source PASS, cold 6/11, 34 phases complete/four unfinished, cleanup
complete; later tests SKIPPED). Both source-specific artifact inventories were
independently checked. No remote deadline fix is claimed for this new source.

Lossless archive: 50,174,223 bytes SHA256 `ec82f634ca6511e373a65205cfcaec45ec7ea198884d17434ce4989f1906b48a`;
all 2,584 regular files/362,733,824
uncompressed bytes compared, modes checked, originals retained externally.
The archive does not silently incorporate old raw files or prerequisite binaries.

Package still has 129 Python files. Host admission,
wire/query/patch/hash/SQLite/build dependencies remain. All nine whole-native
Core/Agent obligations OPEN. QEMU is not physical-device acceptance. No main,
default service, Mac, BIOS or production activation. New word-emission work is
separate and is NOT admitted by this candidate's results.
