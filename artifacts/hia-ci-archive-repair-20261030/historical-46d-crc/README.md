# Final CRC CI — source 46d88bd

GitHub API confirms [workflow run 41039944804](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41039944804), job `124010002605`, completed successfully on **46d88bd18b1b3dadb246e92eb22c49fe44ec2d72**. This is a separate final-source cohort; the earlier c4fe success is not substituted for it.

## Actual frozen study result

| Field | Result |
| --- | ---: |
| Observations | 210 / 210 |
| Complete contexts, with each receipt hash checked | 2,856 / 2,856 |
| Native requests in retained context receipts | 13,440 |
| CRC calls in retained context receipts | 13,762,560 |
| Unchanged registered budget | 120.000000000 s |
| Actual complete-study wall | **92.733215298 s** |
| Cold setup | 8.867431299 s |
| Trace preparation over all observations | 37.380763266 s |
| Native outer lifetimes over all contexts | 38.755648448 s |
| Qualification | `qualified_no_cold_opportunity` |
| Qualified | true |
| Economic gate | **false** |
| Controls | **54 tests, 9.947 s, 0 skips, 0 failures, 0 errors** |

The artifact metadata, source-sha file, expected source and before/after clean source state all bind the exact final 46d88 commit. The frozen protocol matches the earlier public preregistration byte-for-byte, with SHA-256 `75f5f0bef5b5c49020b14b83c7c1f9257f989c5f2f0b3a365f5b7ba858329948`. The schedule, sample counts, context limits and 120-second budget were not changed.

The check validates all context-receipt hashes, completion flags and confirmed child cleanup, reconciles their request/call counts and native costs with all samples, and independently recomputes the six economic rows. Every guarded incremental lower envelope is negative in this run. CI success therefore does not establish cold net benefit or NDU contribution.

As requested, this check does not repeat the earlier full independent bytewise CRC recomputation. The c4fe audit remains evidence for c4fe only. Here the retained original runner's result checks and the final artifact's complete/hash-bound receipts are verified, with economic arithmetic recomputed independently.

## Original artifact and retained verification

Artifact ID: **12969263746**. Original ZIP: **15,228,624 bytes**.
GitHub official SHA-256, matched after download:

`0325b2fd83ff1490c47c4ffcb11381c6f637db63a81c69fe8e3a74b8e224a387`

- `API_STATUS.json`: actual final job and artifact metadata, including head SHA.
- `hia-crc-context-41039944804.zip`: original complete artifact.
- `RESULT.json`, `study-summary.json`, `controls.log`: unchanged selected artifact entries.
- `VERIFICATION.json`, `verify_artifact.py`, `verification.log`: final-source receipt/gate checks and their exact scope.

Tracking downloaded/read the artifact and wrote only this scratch directory. It made **zero repository edits, zero native/model executions and zero workflow rerun requests**. The 000ac failure, c4fe success and registered e223 NDU/Agent/Ring outcomes remain separate and unchanged.
