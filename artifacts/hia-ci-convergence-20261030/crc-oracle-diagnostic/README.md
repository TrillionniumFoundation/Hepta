# CRC CI oracle normalization diagnosis and minimal fix

Base source: `000acac3c357430ca062957ba288756a8d89e147`.
Failed GitHub run/job/artifact: `41036215289` / `123997568542` / `12967539012`.
The original failure remains a failure; no complete CRC study was rerun locally.

## Actual failure evidence

The retained CI artifact reports 121.031788701 s against the unchanged 120 s deadline, 1,640 attempted contexts, and 121 completed observations plus a partial 122nd of the required 210. Actual source identities remained unchanged and cleanup completed. Across attempted samples, native outer lifetimes total 22.380185314 s, trace preparation totals 84.326066569 s, and cold setup totals 9.475389880 s. The artifact records 7,937,024 completed CRC calls.

Source inspection identifies one redundant operation on every integer step result: `_observation` constructs a fresh canonical dictionary/list, validates that known shape, serializes it with JSON, then parses it back into another fresh dictionary/list. `_expected` invokes this for every oracle call. No result cache is involved.

## Development diagnostic

`profile_oracle.py` uses four artificial 4,096-byte requests, independent of the registered phase corpora. Each old/proposed path calls the original CRC Python oracle 16,384 times in precisely the same order, with identical argument-sequence and returned-tuple SHA-256 hashes. A separate first-trap control preserves the same two calls and trap prefix. Twenty-three valid/invalid observations have equal values or equal exception type/message, and the dictionary/list alias controls show fresh output snapshots in both paths.

The old path called `json.dumps` 16,384 times and `json.loads` 16,384 times; the proposed exact-integer path calls neither. One cProfile diagnostic pass measured 248.697442 ms for old and 46.496103 ms for proposed. These times include profiler overhead, have no replication or order control, and are not used to predict CI wall time or change any economic result. The mechanism and identical call/output evidence are the reason for the patch.

## Applied change

Only `hepta/hia_finite_context.py::_observation` changes in production: exact `int` values retain the same inclusive u32 bounds and return a fresh canonical dictionary with a fresh one-element list directly. Invalid integers retain the same diagnostic. Boolean/int-subclass rejection, dictionary normalization, trap validation and copying remain on the original path. There is no memoization, skipped oracle call, changed native context, weakened proof, altered failure classification or adjusted timer.

Two tests in `tests/test_hia_finite_context.py` cover exact types/bounds, fresh aliases, unchanged dictionary/trap rejection, absence of the redundant integer JSON round trip, repeated oracle calls, and first-trap behavior. The patched finite-context and frozen CRC-control modules passed 31 tests in 2.003 s, with zero skips, failures or errors, including the real native finite-context control. The initial sandbox attempt retained one existing `/proc/PID/fd` visibility failure; the normal-host run used the original sealed-identity checks unchanged. Both logs are retained.

The sparse-checkout protocol fixture was restored byte-for-byte from the CI artifact only after matching both the Git index blob and registered SHA-256. Protocol, CRC runner and kernel have no Git diff. Frozen candidates, 210 observations, 2,856 contexts, information permissions, cost ledgers, 120-second budget and all admission gates remain unchanged.

No local complete CRC study was executed, and no successful new CRC CI is claimed. A new source CI must independently finish the unchanged study. The registered e223 NDU/Agent/Ring experiments and their negative results remain untouched.

## Files

- `RESULT.json`: old CI aggregates, development profile and semantic comparison.
- `old-profile.log`, `proposed-profile.log`, `old.pstats`, `proposed.pstats`: complete old/proposed profiles.
- `finite-context-tests.log`: retained initial sandbox environment failure.
- `finite-crc-tests-native-host.log`: 31 passing controls, including native execution.
- `minimal-fix.patch`: exact two-file patch.
- `APPLIED_VALIDATION.json`: artifact/source hashes, test result and preserved boundaries.
