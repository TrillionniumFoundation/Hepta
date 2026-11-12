# HIA strict qualification self-audit after verified source/native host matrix

Research-only, stacked on #465 commit `5b100d33c7e57e3b4dffd18c32b01db1bbcd1110`. This revision does **not**
change HIA Core, Rust/LLVM native byte semantics, target ABI, C/C++ translators
or NDU controller behavior. It hardens the independent multi-lane test-receipt
gate itself, which otherwise could silently grant `passed=true` on a suite
with `unittest.expectedFailure`, duplicated test identifiers, fewer executed
cases than discovered, or a changed source checkout.

## Exact new admission invariants

- Frozen planned test IDs are collected before unittest executes; no duplicate
  IDs or absent test cases, and `testsRun == len(planned_ids) > 0` is required.
- Zero errors, failures, skipped tests, expected failures, and unexpected
  successes; a test expected to fail is NOT qualifying evidence.
- Original HEAD SHA and Git tree SHA must not change before/after tests.
- Both tracked changes and untracked worktree files are refused; ignored build
  artifacts are outside this narrow check, and external toolchain artifacts
  are independently scoped.
- The actual ordered planned-test-ID SHA-256 and all refusals are retained in an
  exclusive no-overwrite report with `DENY_ALL` authority.
- Standalone synthetic independent tests falsify each condition; the gate's own
  tests run under that same gate and cannot approve production.

## Qualification

```sh
python -B -m tools.qualify_hia_three_lane --suite gate --output /tmp/hia-test-gate-receipt.json
```

This hardening is not a claim of full soundness, hardware safety, global NDU
optimality or closure of any P0–P7 production stage. Prior source-exact green
numbers remain valid only for their historical commits, not this new SHA.
