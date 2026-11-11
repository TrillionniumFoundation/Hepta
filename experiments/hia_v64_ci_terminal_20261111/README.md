# Exact v64 CI failures and source-inventory repair

These observations retain the original terminal results for published commit
`699451201f51fb4bdbd931568e64aa576143e807`, tree
`9be8bd2dbfca0dd5a552a26218f97711425e577d`. They do not qualify a later
source, activate a default native route or authorize retiring supported owners.

## Original Core CI terminals

Both Core runs completed with **failure**:

| Event | Run | Source job | Native job | Actual checkout |
| --- | --- | --- | --- | --- |
| Push | 42981052596 | 130391315377 | 130391315077 | `699451201f51fb4bdbd931568e64aa576143e807` |
| Pull request | 42981060503 | 130391339754 | 130391340059 | `17835ab6bc13b0814b753f8d6678531879d307ff` |

The PR checkout is GitHub's synthetic merge of main
`31d81594997cfb6cce5ab62ea5aaba3bb7757af1` and the published commit. Its
tree is exactly the same `9be8bd2...` tree. The original Git commit metadata,
run/job API observations and exact UTF-8 encodings of decoded job logs are
retained here. An API's `head_sha` alone is not used as checkout evidence.

Both source jobs reproduced all 44 HIA generators without changes and passed
the source-contract check. Regenerating the language inventory then exposed
one stale semantic-support hash. The generator changed
`41f36991474dde43c40132ea0b0ef0168b1a80e1adc86177789e061fa52c8ace`
to `1b5de936e2ee7c5772af66b5ab5ed2d357e0017d13d7e292c7288ff05e493526`.
The actual source suite was not reached by either failed CI job.

Both native jobs reached the unchanged 180-second cold deadline and returned
6/11 wrapper checks. The wrapper did not admit an unfinished nested report;
its empty generation lists do not independently establish a compiler fixed
point failure. The raw cold artifacts, process owner and phase receipts must
be used to distinguish timeout, completed work and cleanup.

| Event | Original artifact | Bytes | ZIP SHA-256 |
| --- | --- | ---: | --- |
| Push | 13838255146 | 48,247,435 | `dade37444cb1b96c05135e233a0eb25f5ac6faf30eff73c05a5d796a3452702f` |
| Pull request | 13837373187 | 48,270,174 | `92ae035b35791e54dee75fdc081966e6c92302b49c9cbf83a36b2a5781aec857` |

GitHub lists expiry on 2026-11-18. The independent custody observations retain
the original archive hashes and full original files separately; no failed run
is replaced by a reconstruction or a later rerun.

## Source-only repair and complete selected source suite

The repair regenerates the language inventory after the merged semantic
contract, then regenerates the contract's source pin for that inventory.
There are exactly two generated-file changes at this repair boundary. The
coverage file SHA-256 becomes
`669c0ffa24cfa4a2eae0cdecea55ccc033651293a75931e3aa168d040e2d43f8`;
the support contract becomes
`fcec5f0c8879add700ba6570d6717c50fb9fdce0425842751a61f1ad7d491dc8`.
The declared source set remains 611 files plus the contract itself.

`source-repair-controls.json` and its original log record all **317/317** tests
from the actual Core source-CI selection passing under Python 3.12.14 in
409.8943568930008 seconds. Every loaded test ID equals the corresponding
executed test ID; there are no errors, failures, skips, expected failures or
unexpected successes. Contract and language-inventory validation preceded
the suite. The report's observed Git HEAD is still `699451...`; these two
generated-file changes were in the working tree during that observation and
were then committed as the separate repair. This is not a Python 3.14 CI
rerun, native-application result or cold-qualification pass.

`r4-archived-copies-released.json` is storage custody only. It records exact
member/hash/metadata verification against the already published original r4
archive before removing 280 redundant unpacked files. The original archive,
audit, script and failed observations remain retained. No new journal
execution is claimed by that record.
