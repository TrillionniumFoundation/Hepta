# Original NDU CI evidence for source 14b2c03c

This directory preserves the original [NDU scalar integration run](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42524208427) for source `14b2c03c35f0d8d4f3b77133cf3deecde92a2f40`. It does not rerun native work or substitute for the independently failed exact-source cold gate on that commit. Overall source promotion and P2 economic acceptance remain HOLD.

## Retained bytes and identities

The original GitHub artifact is `13634811481`, 8,086,290 bytes, with ZIP SHA-256 `53b8f91a9eaed9da95a98b07f94b7fcfa41f3a59cc9eaa59f88ec407366600b3`. All 475 original members (37,744,695 uncompressed bytes) were read from that verified ZIP, repacked, and independently reread against the per-file SHA-256 index in `manifest.json`. `original-members.tar.xz` is 1,267,560 bytes, SHA-256 `1eb2449737f6051afcdbbb480e0eb328186881d4e9e8dbe3f8c8f118282e7929`. Its member bytes are unchanged; its container format is not the original GitHub ZIP.

The original source-bound integration reports 172 successful Python tests and the separate Cargo receipt records all three required framing tests passing. The actual retained native executable is 2,345,848 bytes, SHA-256 `494d198e94f533c8a894dc141a42be2890fa12bce14d9b4b2c849ee5fbf46cb5`, unchanged after the suite. Its build receipt hash is `8e67657bfef5b989bd2e7c0ccffa5822e260d04adf8ffbf9e3bab6ac347ff6e8`. These identities describe this run only.

## Complete registered campaigns

Both prepared and persistent campaigns completed their 72 predeclared cells with zero failed or unstarted cells and no automatic retries. The prepared registration is `f7443fff0c8b12d09ab865ecbc73c8485a90963552f2508e7f994aae8f276ba0`; the persistent registration is `69ab7f5a0340176f7748cd3673b29b91864f4d299189d2967f9e98f03bef04c1`.

The prepared campaign retained 1,020 original native calls, 510 ordinary scalar calls and 510 byte-identical native-response pairs. Its independent replayer explicitly reports `reported_analysis_recomputed: true` and binds verifier SHA-256 `9f4fb093932821f81c454015187d66dc8b77898bd713899184bc15df95bdcbfb`.

The persistent campaign retained 1,020 native responses from 534 native processes (510 prepared and 24 persistent), 510 ordinary scalar calls and 510 byte-identical paired responses. Its independent replayer binds verifier SHA-256 `c0433f4acb1a03002f963e46309f40db09ab1d39013cb7b312691cb92be5ad09`.

| Horizon | Persistent lower cost than prepared | Aggregate saving against prepared | Ordinary scalar lower cost |
| --- | --- | --- | --- |
| 1 | 2/6 pairs | +1.077% | 6/6 pairs |
| 4 | 6/6 pairs | +15.668% | 6/6 pairs |
| 16 | 6/6 pairs | +33.425% | 6/6 pairs |
| 64 | 6/6 pairs | +43.626% | 6/6 pairs |

Prepared was lower cost than one-shot in 24/24 pairs, while ordinary scalar was lower cost than prepared in 24/24 pairs. Ordinary scalar also beat persistent in 24/24 pairs. The horizon-one aggregate differs from the earlier retained `50c1578b` run (negative aggregate, 1/6 persistent wins). Neither observation is replaced or selected as the sole answer.

These are observed mechanism costs with independently checked ledger arithmetic and source identities. Timings are not independently authenticated. No new provider calls are claimed, model cost remains null, full cost remains incomplete, machine refinement is not proved, and economic benefit is not established. All raw results retain P2 HOLD and DENY_ALL authority.

## Inspect and replay

Unpack into a new empty directory, verify the member hashes against `manifest.json`, and use each campaign's frozen replay source and exact registration digest. The archive includes original frame/call ledgers, source snapshots, build receipts, cell results, the native binary and both independent replay reports. `observed-results.json` is a root-generated extraction of selected fields; it does not replace the original reports.
