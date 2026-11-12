# HIA P0 — exact-source, executed-test and receipt-location hardening

## Source provenance / true failure

A source-exact qualification must bind both the repository being tested and
the actual executed tests. At the frozen base #467
`11e4ccfedf273de1d47fe9910c776591ed466626`, `tools/qualify_hia_three_lane.py` set `ROOT` from its own file
but called `git(...)` with the *invoker's working directory*, not `cwd=ROOT`.
Calling the module from another Git checkout could therefore publish an
unrelated repository SHA and worktree-clean claim alongside Hepta unit tests.

The original receipt also compared the discovered test count only to
`unittest.Result.testsRun`, not to the ordered identities of actual tests
started and stopped. A substituted test with the same count could pass the
test-count gate. Finally, writing `--output` inside the source worktree
creates an untracked receipt *after* the post-run cleanliness scan while still
claiming that checkout was clean.

## Narrow repair, strict nonclaims

- Git calls now set `cwd=ROOT` and are independent of invoker location.
- Strict gate has a `unittest.TextTestResult` subclass recording each
  started/stopped test ID in order. Both actual sequences must equal the
  independently discovered sequence, with exact counts and the existing
  no-skip/no-expected-failure/no-error/no-failure invariants.
- Immutable receipt gains separate planned/started/finished SHA256 digests
  and `actual_test_identity_drift`, preserving existing fields for readers.
- `--output` must be absolute and resolve outside the source worktree,
  with file creation still using no-clobber mode. This is checked before tests.
- Adversarial tests cover foreign CWD, substituted/duplicated/missing IDs,
  mismatched stop order, actual recorder fidelity and in-worktree refusal.

This is scoped to source-bound **qualification evidence**. It does not
establish formal source/Core/native refinement, all Rust/LLVM correctness,
hardware performance, NDU net benefit or Agent productivity. It never
allows deployment: every receipt retains authority `DENY_ALL`.

## Qualification commands

```sh
python -B -m tools.qualify_hia_three_lane --suite gate --output /tmp/hia-p0-test-identity.json
python -B -m tools.qualify_hia_three_lane --suite core --output /tmp/hia-p0-core-identity.json
python -B -m tools.qualify_hia_three_lane --suite native --output /tmp/hia-p0-native-identity.json
```

All eight P0–P7 production blockers remain OPEN, pending independent
final integrated SHA reviews and their separate acceptance requirements.
