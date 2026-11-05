# Native dynamic-cache baseline evidence (2026-11-05)

Source `f48ae07eb86db1cc41acabfe22449634b897df31`, tree `ec6537ff93f67b0af0907616909ddad172bb3e64`; unchanged upstream NDU
`8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d`. This is a native Rust experiment, not
HIA-compiled workload qualification. The earlier HIA 0/3 result is preserved.

One formally registered campaign completed all 432 episodes and 10,368
workload execution requests (47,520 kernel loop calls). Its allow-skip NDU
policy won against every control in 0/24 cohorts. NDU actually participated in
12 cohorts/36 episodes/618 requests, and won 0/12 of those cohorts. The other
36 episodes never started a planner. NDU was faster than the same-image beam
in 8/24 cohort medians and slower in 16/24. Each beam arm had 15 proposals with
no unanimous first action; they were not counted as exact successes.

See `NDU_DYNAMIC_REPORT_ZH.md`, `ANALYSIS.json`, and `COHORTS.csv` for every arm,
every cohort, independent exact gaps, disjoint cost phases, amortization and
limitations. Alternative arm allocations overlap and must not be added as
actual machine cost. No additional NDU ranking benefit was established.

## Archive contents and omissions

The parts restore 1093 complete original files (583006306 bytes),
including the 250,586,461-byte RESULT, every episode/JSONL exchange, original
stdout/stderr, both registrations (r1 had zero formal executions), build
receipts and original Cargo streams, all recorded preparation/control
receipts, source change history/bundle, and derived audits. Every byte is
listed and SHA256-bound in `ORIGINAL_FILE_INVENTORY.json`. `VERIFICATION.json`
records an actual full restoration and an unchanged-originals check.

The original build's upstream source snapshots and large Cargo products are
not copied into the public archive; `OMITTED_BUILD_INVENTORY.json` retains
their exact paths, sizes and SHA256. Original remote evidence remains intact.
The external Cargo cache is not distributed or claimed fully inventoried.
This package includes source/tool identities, not the whole toolchain or a
standalone executable environment. Original timestamps, ownership and inode
numbers are inventory only; file bytes and ordinary modes are restored.

## Verified evidence restore

From a directory containing all package files, use a new output directory:

```sh
python3 RESTORE.py --package . --output /absolute/path/to/new-restored-evidence
```

The script verifies every ordered compressed part, the complete gzip hash,
the exact member set, every restored file size/SHA256 and ordinary mode. It
rejects symlinks, hardlink members, traversal and overwriting. It never runs
any restored source, native binary, test or evaluator.

The ordered compressed byte parts are pieces of ONE archive; a part is not
individually extractable. The ordered whole archive hash is
`8120a4e37fdc16f993ebcd590f0800241bc641c045a7dfbab614ff225d88c99f` and its compressed size is
37630978 bytes. `PARTS.sha256` lists the parts.

`source/SOURCE.bundle` contains the five source commits above original base
`3707b871ecbe563233ee9a3b69299fc627408936`. It requires that base commit/tree already be present;
`source/bundle-verify.*` retain the actual successful verification in the
source repository. `source/CHANGESET.patch` and `SOURCE_COMMITS.json` expose
the exact change and original identities. Evidence restoration does not
promise that a new machine rebuilds the same binary or repeats the timing.
Fresh rebuilding/measurement needs a new registration; never edit the old
registration or replace these observed results.
