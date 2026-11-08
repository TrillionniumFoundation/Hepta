# Persistent NDU: independent replay of exact-source CI

This immutable observation belongs to source commit
`aee4ed1f6bd478764b1f6684a3d51f346ffb05c6` and
[GitHub Actions run 42508527700](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42508527700),
job `128816335003`. It is not transferred to a later source revision.

The actual CI run completed all 164 Python tests with no failures, errors,
skips or expected failures. All 22 persistent-transport tests, including the
three required native integration tests, ran. The Rust framing suite completed
three tests with none ignored. The native executable SHA256 is
`494d198e94f533c8a894dc141a42be2890fa12bce14d9b4b2c849ee5fbf46cb5`.

## Registered mechanism comparison

Registration SHA256:
`367d19f24af8fd336b6213db5a2e79167efd2d5194b46817ca570402eeb90fea`.
All 72 registered cells completed with zero failed cells and zero automatic
retries. There were 1,020 native responses, 534 observed native process IDs,
and 510 ordinary calls. All 510 paired prepared/persistent response bodies
were byte-identical.

| Requests per session | Pairs | Ordinary median ms | Prepared median ms | Persistent median ms | Persistent wins over prepared | Aggregate saving over prepared |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 6 | 0.118756 | 7.228950 | 7.533987 | 3/6 | -1.22% |
| 4 | 6 | 0.487026 | 13.174124 | 10.896353 | 6/6 | 17.48% |
| 16 | 6 | 1.834430 | 38.673419 | 25.512081 | 6/6 | 39.05% |
| 64 | 6 | 7.109509 | 155.894828 | 81.653007 | 6/6 | 46.33% |

Aggregate savings use the registered sum-of-paired-cost arithmetic; they are
not ratios of the displayed medians. The stronger ordinary implementation is
faster in all 24 comparisons. P2 remains `HOLD`. These measurements establish
a transport mechanism result under the registered workload, not stable
application value, a general machine refinement proof or complete lifecycle
economics. Provider interactions and full costs are not invented.

## Original bytes and replay

The downloaded CI artifact is `13628908695`, original ZIP size 8,085,624 bytes,
SHA256 `e4fa95e32403f9c52662fbff7a2b8c74ce934dd6736a93f85be02b61d4849ac4`.
`raw.tar.xz` losslessly repacks all 475 original file members (37,742,128
uncompressed bytes); every extracted member was checked against its original
ZIP bytes. The archive has 1,271,768 bytes and SHA256
`d1a47722be24fab2a18f62e6f2e07a0038c0061f3e1c540bf229bd2ac17110d3`.
`inventory.json` records the original path, byte count and SHA256 of every
member. No failed, slow or negative cell was removed.

`root-replay.json` records a separate invocation of the standard-library-only
`tools/replay_hia_ndu_persistent_ranker.py` on the complete CI mechanism data.
It rehashed 14 source files and checked all registered cells, raw frame
identities, original response bodies, process/EOF/cleanup records and cost
arithmetic. It cannot independently authenticate elapsed timings and states
`timings_independently_authenticated: false`; its authority is `DENY_ALL`.
