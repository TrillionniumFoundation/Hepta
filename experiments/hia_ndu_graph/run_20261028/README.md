# 2026-10-28 recorded graph run

The complete raw run is preserved in `../run_20261028.tar.xz`. Its archive index
and per-member hashes are the adjacent `run_20261028.archive.json` and
`run_20261028.members.json`. Extract into an empty directory; the original
relative file layout appears under `run_20261028/`.

- `RESULT_SUMMARY.json` contains every aggregate finding and an index of all 18
  episodes. Complete per-episode ledgers, native recursion receipts and proofs
  remain in the archived `RESULT.json` and individual episode reports.
- `BANK_SUMMARY.json` lists actual candidate proof status, machine-code/source
  identity, setup cost and median calibration latency. The archived bank also
  contains every raw calibration sample and its full proof receipt.
- `PROTOCOL.json`, `SOURCE_IDENTITY.json`, `NATIVE_BUILD_IDENTITY.json` and
  `HOST.json` bind the registered experiment, actual sources, compiler/native
  executable and execution environment.
- `FAULTS.json` retains actual deadline, snapshot-drift and artifact-digest
  refusal evidence. The unprotected fast-body rejection is in the full bank.
- `NDU_REGRESSION.log` records 32 final native/compiler tests, all passed with
  no skips. `BRIDGE_CI.json` records the actual successful dedicated private CI;
  the full remote log and five-test local Rust log are inside the archive.

Reported episode costs include each arm's actual evidence serialization/write.
The earlier raw per-episode report necessarily records admission before its own
write; the aggregate result adds the externally measured return/write interval
to that arm. Shared setup is charged once per standalone strategy, and the
43.243376181-second empty-target native build is charged only to NDU.

All 18 episodes and all 72 workload outputs passed. Six guarded transitions
were actually compiled and executed by fixed-candidate arms. Native NDU, the
optimal fixed plan and the complete lightweight DP all chose to stop optimizing
because candidate setup did not amortize. NDU did not establish a net advantage
over either strong control. This result is retained without selecting a faster
rerun or dropping unsuccessful optimization costs.
