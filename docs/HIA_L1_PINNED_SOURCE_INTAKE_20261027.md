# P3/P4 HIA L1: bounded and source-pinned compiler input

Parent: P7 bounded release/native publication commit
`ba859e788886e5aa7b9f4b4198f14f55a9825ed8` (#292).

`hepta.hia_migrate` previously invoked `Path.read_bytes()` before checking
its stated 256 KB C/C++ source and 1 MB candidate Hepta bounds, and
reopened source/native paths multiple times. A sparse oversized input could
be allocated before rejection, while a regular-to-FIFO path replacement
could block an actual migration pipeline.

The existing L1 migration wrapper now uses one `_read_snapshot` admission
helper on every source, candidate and compiled artifact read. It requires
regular files, nonempty exact bounded extents, `O_NOFOLLOW|O_NONBLOCK`,
and stable fd/path inode identities and timestamps before/after reading.
Budgets are 256,000 bytes for original C/C++, 1,000,000 for generated
Hepta, and 64 MiB for a native HIA object/shared library. Source is
rechecked after migration and before costly native compilation.

The existing Clang migration authority, independently pinned Rust reference
validation, Core/LLVM backend, native-receipt scrutiny and atomic three-file
publication remain unchanged. This narrows the intake to the documented
strict L1 profile; it does not certify arbitrary C/C++ L2/L3 conversions.

New tests check regular source, final symlink rejection, sparse oversized
source no-open, FIFO swap lstat/open refusal and oversized generated Hepta
candidate rejection before native build. FIFO tests assert flags before
opening, so a regression fails instead of hanging a test process.

```sh
python -m unittest tests.test_hia_migration_file_intake tests.test_hia_migrate -v
python -m unittest tests.test_hia_l1_receipt tests.test_c_migrate tests.test_cpp2hepta_l1 -v
```

Execution evidence: the independent Linux OS control reproduced blocking
versus nonblocking FIFO behavior. The complete exact-head Hepta test and
pinned native Rust/Clang/C++ differential suites were NOT RUN in this
environment. This does not close whole-project P0-P7:
`whole_project_blockers_closed=false`.
