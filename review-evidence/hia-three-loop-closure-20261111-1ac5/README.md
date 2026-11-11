# HIA three-loop candidate evidence — 2026-11-11

This branch retains observations for fixed source candidates. Its evidence commit is not the source commit that was tested. The final full native and Runtime gates are still being observed at this checkpoint.

## Frozen candidate pair

| Repository | Candidate commit | Tree |
| --- | --- | --- |
| Hepta | `8dae9d0b74f8520d1522548e0a04c0c077b3f074` | `b2d32f112431a7b0afd7a98fe41084996e0b818a` |
| hepta-runtime | `9a43021137b72316f5345ce660c7f3d00ea93c02` | `56784c9e064447acfc06e80a9cc235f98c8e91b2` |

The shared catalog SHA256 is `6ec74dddbffeef5270c5eebb0638c87a8f7a540f8f38b8703ef8e471af582393`.
The code changes are reviewed in [Hepta PR #890](https://github.com/TrillionniumFoundation/Hepta/pull/890) and [Runtime PR #118](https://github.com/TrillionniumFoundation/hepta-runtime/pull/118). Runtime is stacked on `fix/unbounded-concurrency-20261109`, whose fixed starting commit is `09464736e815940ee4c5bf91d36f6c84a3faee2c`.

## Results already checked

- The exact Hepta candidate passed 146 binding/proof/worker controls with zero failures, errors or skips; independent catalog regeneration passed 79 checks. The actual source contract covers 634 files.
- Both original source-control jobs passed 307 tests. The current native groups remain separately observed until their original terminal results arrive.
- The original C0/C1 compiler extension qualified its registered finite domain: 2 old source images preserved byte for byte, 18 old native observations, 4 old refusal observations, 5 new-source admission deltas and 64 complete new-program observations. The 200 projection observations are separately counted.
- The local proof covers 25 typed-subject obligation instances, representing 8 distinct query hashes. Fresh replay does not increase that count. The original four-claim Agent gate remains HOLD.
- The same Runtime/Hepta pair completed both real stdio MCP/OpenSSH/systemd/native-helper/consumer runs. Their retained report has 10 successful checks, 39 scripted HIA calls covering 11 tools, and 4 MCP sessions. The complete Runtime evidence is being archived separately.
- The worker's JSON adapter, durable journal and service policy remain hosted Python. The selected helpers and generated consumer programs execute actual HIA machine code. There is no complete pure-native-worker, production-activation, fresh-model or net-performance-gain claim.

## Retained original observations

| Directory | Scope |
| --- | --- |
| [bindings](bindings/) | Original 139-test and successor 146-test complete job logs and exact GitHub artifact ZIPs. |
| [initial-2ccedfe5](initial-2ccedfe5/INDEX.json) | The first candidate's two real installed-worker fixture failures, successful cold/language stages, all four full job logs, process-owner records and losslessly compressed original reports. These results are not transferred to the successor. |
| [upgrade](upgrade/INDEX.json) | Complete original compiler-extension artifact, independent read-only audit, raw member manifest, source bindings, original qualification and domain reports. |
| [checker](checker/) | Recovered local checker/proof observations and explicit limits on unavailable early logs. |
| [local-overlay](local-overlay/) | Local 68-test run plus exact patched blob identities; source-qualified CI is recorded separately. |
| [old-remote-operation](old-remote-operation/) | Read-only recovery of the original ROG job and two unresolved ai395 clone/preflight requests. No operation was reissued. |

Files ending in `.json.gz` are lossless compression of the exact original report bytes. The adjacent index records both compressed and original SHA256 identities. The original cold budget is 180 seconds plus 3 seconds of cleanup; it was not changed.

The earlier ROG development job was eventually observed as succeeded with a complete durable output. Its output did not name the final source commit or test count and cannot qualify the frozen pair. The ai395 inventory observation failed, so the two earlier requests remain UNKNOWN.

See [SUMMARY.json](SUMMARY.json) for source identities and checkpoint status, and [FILES.json](FILES.json) for retained Git blob identities.
