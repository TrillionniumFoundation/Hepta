# Retained formal analysis regression

`failed_formal_analysis_f7cc8721.json` is a 189,179-byte projection of the
first complete formal execution at source
`f7cc87218a101b4b2c715e3fdd2e9d42a7f7fd8b`. Its original 2,932,746-byte
`RESULT.json` has SHA-256
`411a8eabb85adbee5334afe0c684b42de39367f2b74ae3caa515ec7674465ae9`.
The original run remains failed: its live cost ledger included the running
`post-policy.analysis` row before that row had a `wall_ns`. The subsequent
failure finalizer retained its actual 145,660 ns cost.

The projection retains the original protocol, every outer cost row, all 20
complete episodes, all 184 delivery observations, calibration, all 32 native
decision models/selections, preparation call counts, original failure and
pre-analysis wall boundary. It removes repeated native request/response wire
payloads and unrelated source/tool/capture snapshots. Retained values are
unchanged. Its raw SHA-256 is
`b9d6d605c42c7d2462e88acead3098092e02f4038f8d76b4a4e312d79513526f`.

The regression uses the real `measured` wrapper around a snapshot of these
actual costs. It also rejects missing, unknown, negative or running costs,
missing preparation, duplicate arms, and changed delivery/calibration
denominators. It checks the complete deterministic cost result, including all
three negative net-value gates. Pure offline analysis never updates the
original result's failed qualification or counts as another native run.
