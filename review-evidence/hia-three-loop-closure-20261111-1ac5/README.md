# HIA three-loop candidate evidence — 2026-11-11

This branch retains observations for fixed source candidates. Its evidence commit is not the source commit that was tested. The complete original Hepta Core/native gates, both joint MCP runs, the finite compiler-extension qualification and Runtime's full push/PR gates have passed for the fixed pair below. These results qualify the recorded scopes; they do not close every item in the broader P0/P1/P2 roadmap.

## Frozen candidate pair

| Repository | Candidate commit | Tree |
| --- | --- | --- |
| Hepta | `8dae9d0b74f8520d1522548e0a04c0c077b3f074` | `b2d32f112431a7b0afd7a98fe41084996e0b818a` |
| hepta-runtime | `9a43021137b72316f5345ce660c7f3d00ea93c02` | `56784c9e064447acfc06e80a9cc235f98c8e91b2` |

The shared catalog SHA256 is `6ec74dddbffeef5270c5eebb0638c87a8f7a540f8f38b8703ef8e471af582393`.
The code changes are reviewed in [Hepta PR #890](https://github.com/TrillionniumFoundation/Hepta/pull/890) and [Runtime PR #118](https://github.com/TrillionniumFoundation/hepta-runtime/pull/118). Runtime is stacked on `fix/unbounded-concurrency-20261109`, whose fixed starting commit is `09464736e815940ee4c5bf91d36f6c84a3faee2c`.

## Final recorded results

- The exact Hepta candidate passed 146 binding/proof/worker controls with zero failures, errors or skips; independent catalog regeneration passed 79 checks. The actual source contract covers 634 files.
- Both original source-control jobs passed 307 tests. Both complete original native jobs passed all 14 groups, 581 tests each. Both cold reports passed 11 outer checks, 5049 nested checks and 38 phases under the unchanged 180+3-second budget; their actual wall times were 114.891022179 and 125.604975686 seconds. Language qualification passed 1242 checks plus 10 separate assertions in each run. All 635 exported files (634 contract sources plus the contract itself) were matched to the fixed Git tree.
- The original C0/C1 compiler extension qualified its registered finite domain: 2 old source images preserved byte for byte, 18 old native observations, 4 old refusal observations, 5 new-source admission deltas and 64 complete new-program observations. The 200 projection observations are separately counted.
- The local proof covers 25 typed-subject obligation instances, representing 8 distinct query hashes. Fresh replay does not increase that count. The original four-claim Agent gate remains HOLD.
- The same Runtime/Hepta pair completed both real stdio MCP/OpenSSH/systemd/native-helper/consumer runs. Their retained report has 10 successful checks, 39 scripted HIA calls covering 11 tools, and 4 MCP sessions. The complete 64,587,283-byte original push artifact is preserved as 16 exact raw parts in the [Runtime evidence branch](https://github.com/TrillionniumFoundation/hepta-runtime/tree/28340a7d1d818ea47d3269fab849c0480bbb2d4e/review-evidence/hia-common-candidate-20261111-1ac5), alongside both runs' complete original reports and audits.
- Runtime's complete [push](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43005206656), [PR exact-head and prospective-merge](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43005214787) jobs all succeeded on original attempt 1. Each job passed 2400 Rust tests with 40 existing skips in all-features, and 2371 with 28 existing skips in no-default-features. All three release builds and their 4/4 JavaScript cancellation/recovery gates passed. The exact-head jobs also passed REA parser/syscall-denial and independent ZIP-to-Rust structural checks. The unchanged search-worker Python suite separately had 16 passed / 1 skipped because the optional pypdf parser was unavailable. Full logs, original artifacts, skip inventories and exact merge-tree identity are retained in the Runtime evidence.
- The worker's JSON adapter, durable journal and service policy remain hosted Python. The selected helpers and generated consumer programs execute actual HIA machine code. There is no complete pure-native-worker, production-activation, fresh-model or net-performance-gain claim.

## Retained original observations

| Directory | Scope |
| --- | --- |
| [bindings](bindings/) | Original 139-test and successor 146-test complete job logs and exact GitHub artifact ZIPs. |
| [initial-2ccedfe5](initial-2ccedfe5/INDEX.json) | The first candidate's two real installed-worker fixture failures, successful cold/language stages, all four full job logs, process-owner records and losslessly compressed original reports. These results are not transferred to the successor. |
| [final-8dae9d0b](final-8dae9d0b/INDEX.json) | Both complete original Core/native runs, source and image byte audits, cold/language/owner reports and exact per-group counts. |
| [upgrade](upgrade/INDEX.json) | Complete original compiler-extension artifact, independent read-only audit, raw member manifest, source bindings, original qualification and domain reports. |
| [checker](checker/) | Recovered local checker/proof observations and explicit limits on unavailable early logs. |
| [local-overlay](local-overlay/) | Local 68-test run plus exact patched blob identities; source-qualified CI is recorded separately. |
| [old-remote-operation](old-remote-operation/) | Read-only recovery of the original ROG job and two unresolved ai395 clone/preflight requests. No operation was reissued. |

Files ending in `.json.gz` are lossless compression of the exact original report bytes. The adjacent index records both compressed and original SHA256 identities. The original cold budget is 180 seconds plus 3 seconds of cleanup; it was not changed.

The early local checker attempt's original three-failure log became unavailable after the executor reset; its availability limit is recorded explicitly, and no replacement log was fabricated. Later source-bound CI logs are retained in full.

The earlier ROG development job was eventually observed as succeeded with a complete durable output. Its output did not name the final source commit or test count and cannot qualify the frozen pair. The ai395 inventory observation failed, so the two earlier requests remain UNKNOWN.

See [SUMMARY.json](SUMMARY.json) for source identities and final recorded gate status, and [FILES.json](FILES.json) for retained Git blob identities.
