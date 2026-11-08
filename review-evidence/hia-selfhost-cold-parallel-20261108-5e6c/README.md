# Cold qualification fix: exact source and retained evidence

This delivery contains the local qualification of the two-worker host harness
and Linux process owner, based on exact source commit
`14b2c03c35f0d8d4f3b77133cf3deecde92a2f40`.

The main result is 1,183/1,183; fresh cold replay is 11/11 with its own fresh
1,183/1,183 nested qualification; fresh language coverage is 910/910. All bind
the same 252-file source manifest. The compiler source and all 212 Python files
under `hepta/` are unchanged. Integrated-commit CI and installation/deployment
remain separate gates.

`summary.json` records the exact results, limits, source changes, archive
identities, original CI failure and successful control, finite input comparison,
host-linked image differences and remaining scope. `source-freeze.json` is the
original source-freeze checkpoint and intentionally retains its then-pending
qualification status. Its exact manifest is the one checked by all final runs.

## Complete new raw evidence

- `raw-main.tar.xz` contains the complete fresh main report and evidence folder.
- `raw-cold.tar.xz` contains the complete fresh source export, nested main report,
  native evidence, actual process-owner requests/receipts/logs, and outer report.
- `raw-language.tar.xz` contains the separate fresh language report and evidence.
- `raw-support.tar.xz` contains original selected CI members, full arithmetic and
  byte-comparison records, exact source snapshot, development checkpoint,
  static review, all local setup-failure/test logs, import-time probes and the
  complete finite input/behavior comparisons.

Every archive contains its per-file byte count and SHA-256 index. Every indexed
member was reread independently from the finished archive. For large expanded
directories, every live file was also compared with that index after Git blob
persistence and before removal. Retention receipts name exactly what was
removed and what was kept.

The complete main and cold qualifications each contain the same 1,699 logical
native invocation subjects as the original successful CI, and the same 1,183
boolean check map. Comparison ignores explicit directory spellings and timing;
it preserves substantive request fields and separately records all 279 differing
host-linked shared-object hashes. All B1/B2/B3/M1/M2/M3 compiler-produced flat
image hashes match the original CI. This finite observation is not a general
compiler-correctness or cross-toolchain equivalence proof.

## Original CI selection

The two complete original CI ZIPs are identified by run, artifact, byte count
and SHA-256. `raw-support.tar.xz` retains 6,317 exact selected request/receipt
members, the original failed cold controls and successful reports. Each selected
member was compared directly with its original ZIP member. All 250 source
members were also read from both original ZIPs and compared byte for byte.

This selection does not claim to contain every large buffer from those two
original ZIPs. It preserves the actual failure, unfinished last request, timing
statistics and their complete selected-record basis. No successful historical
run is used to erase the failed run, and no missing original process-cleanup
observation is invented.

The first local source test invocation retained 38 passes and one missing
supplementary release-fixture error. Restoring the exact existing fixture and
rerunning only that failed test completed the same 39 distinct test methods.
No production source, qualification subject, limit or test expectation was
relaxed for that local checkout correction.
