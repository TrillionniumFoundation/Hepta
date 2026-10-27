# P0 compiler source digest: stable raw bytes

Base PR #294 exact `c5b4d2ee4cb34b766022cb9ededfee070da669de`.
The compiler's `compiler_hash()` previously used whole-file
`Path.read_bytes()`, allowing symlink traversal, FIFO-swap blocking, and
unbounded source materialization after directory enumeration.

The existing `hepta.native_tool_identity` now exposes one bounded,
no-follow/nonblocking `update_stable_regular_hash` helper. Both the existing
`digest_executable` and `pipeline.compiler_hash` consume it. Source files
are limited to 64 MiB individually and may be empty; native compiler binaries
retain their original 1-GiB ceiling and nonempty requirement.

**Critical compatibility invariant:** source identity still hashes exact
`filename + NUL + original raw bytes + NUL` for each module, in sorted
order. It is NOT silently changed to a hash-of-hashes or text-normalized
format. Nonregular or changed source refuses; nothing is skipped.

Dedicated regression module `tests.test_compiler_hash_identity` covers
historical byte semantics, ordinary/empty source, symlink, FIFO, swapped
FIFO, sparse overlimit and existing compiler binary SHA-256. The isolated
Linux filesystem controls have been checked independently, but the full
repository/Cargo exact-head tests remain NOT RUN in this restricted
container. No claim of full P0–P7 closure, native refinement, production
toolchain trust, or C/C++ migration is made.

```sh
python -m unittest tests.test_compiler_hash_identity -v
python -m unittest tests.test_toolchain_selection \
  tests.test_release_snapshot_identity -v
```

`whole_project_blockers_closed=false`.
