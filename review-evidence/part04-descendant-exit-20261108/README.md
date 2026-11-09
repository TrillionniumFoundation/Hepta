# Part04 descendant exit observation review — 2026-11-08

This patch changes one test in `tests/test_core_seven_part04_capture.py`. It does not change `tools/core_seven_part04_capture.py`, the 60-second production computation limit, the 2-second production cleanup limit, diagnostic acceptance, or replay semantics. The base under review is `1be1f075dab01a56d43ceca286668946dbc9037b`; exact file hashes are recorded in `summary.json`.

## Preserved failure

`original-unittest.log` and `original-execution.json` are unchanged copies of the integrated 108-test run at `4689f80a833b48d9615d0400cb6c993990d1d4f5`: one assertion observed a descendant in state `R` rather than `Z` immediately after capture returned. The independent external-file inode-change error is also retained; this patch does not resolve or conceal it. A frozen integrated rerun is needed for that error. The copied log hash matches the original execution receipt.

## Review and narrow correction

The collector preserves the leader PID/PGID with `waitid(..., WNOWAIT)`, signals that process group with SIGKILL, drains its descriptors, and waits for the leader. It records leader reaping and descriptor drainage; these observations do not attest to every descendant's final kernel state. In particular, descriptor closure and successful signalling do not make an immediate `/proc` read an atomic observation of the descendant's zombie transition.

The test fixture now reports both its child's PID and `/proc` start time. The test waits for that same identity to become `Z` or disappear, including replacement by a different start time, within the original `started + 1.5 seconds` whole-test deadline. It never restarts the deadline or grants the collector extra time. A still-running original identity at the deadline fails. Checking the start time also avoids treating a recycled PID as the original child.

## Evidence

Before editing the collector (which remains byte-identical), 24 sequential harmless Python fixtures were observed. Each parent forked one child that slept for 10 seconds, printed the child's PID and start time, and exited. The existing test adapter ran the real collector with its existing 1-second test computation and cleanup limits. After return, the same child identity was sampled at approximately 2-millisecond intervals until absent or `Z`, always under the original whole-test deadline. `observations.json` retains each sample, group signal result, leader reap result, and descriptor drain result.

The initial states were 21 absent, 1 zombie, and 2 running. Both initially running identities disappeared on the next sample; the latest final sample was 2,238,599 nanoseconds after return. All 24 runs met the unchanged deadline. This reproduces an asynchronous terminal-state observation on this host and supports a bounded eventual observation in the test. It does not establish a general kernel or descendant containment theorem. The fake programs intentionally omit valid Lean markers, so their recorded `diagnostic_infrastructure_failed` status is expected and has not been turned into an acceptance result.

After the test correction, `tests.test_core_seven_part04_capture` and `tests.test_core_seven_part04_deadlines` passed all 49 tests in 1.942 seconds. `collector-tests.log` is the raw output. These bounded fake-process and deadline regressions are separate from the integrated 108-test run and must not be counted as an integrated green result.
