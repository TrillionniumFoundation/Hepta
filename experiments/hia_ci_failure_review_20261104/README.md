# Retained failure from the previous source

This is a failed CI run on publication `9435f04` (original source `98bdbe9`, exact tree `514b607`). The correction on `3707b87` / `e3b380b` is qualified separately.

The full native regression ran **1,777 tests with 0 assertion failures, 1 error and 0 skips**. Its sole error is the same legacy checked-source receipt mismatch found independently by the 562-test six-outcome workflow. The later captured-application step failed after its clean-worktree preparation was skipped. Neither failure counts as a pass.

The complete original GitHub ZIP was downloaded into memory and verified against its 10,858,438-byte size and SHA256 `0f1cd9be8ff24ebe525b0b452449ea5d8fe05f74dc0323a3101664e26af1efe7`. This package retains the complete 429,480-byte result and 333,200-byte test log, with original member hashes and an archive read-back check. `MANIFEST.json` records the original artifact ID and public API URL; it contains no temporary download URL.

The correction preserves strict receipt fields and requires `entry_layout` to equal the independent canonical emitter. Applying that correction later does not change this failed run's outcome.

Original workflow: https://github.com/TrillionniumFoundation/Hepta/actions/runs/41774368131
