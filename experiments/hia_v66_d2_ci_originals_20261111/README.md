# Original d2 CI evidence, independent replay, and lossless custody

This directory preserves the original artifact from [workflow run 43024566228](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43024566228), head `d2c22d0c4caea145295a8213c6c718eb55546ec9`, artifact `13860171868`. GitHub's actual terminal conclusion is **failure**. The independent audit does not change that conclusion and does not run the product again.

## Verified original evidence

The 111,981,819-byte original ZIP has SHA256 `63f7ddd6c0857956e10cb03823836bb284eb2142bd269a98d124c4b5bf086a56`. Every one of its 5,306 entries was fully read to check CRC, and a complete SHA256 inventory is retained. Its 38 nested phase archives contain 42,623 original members, totalling 2,397,876,925 decoded bytes. Every member's SHA256 and permission mode was replayed through the exact d2 archive verifier; archive, manifest, phase report, and retention receipt identities all match.

All 662 cold source members match the canonical d2 Git tree `082ab925e16a1c89e2ada2ba9b6662e73dd60e00` by bytes, size, Git blob SHA1 and canonical mode. The cold export equals the original executed-source ZIP. Against the separately pinned e09 package, the only changed members are `docs/HIA_SELFHOST_CORE_SUPPORT.json` and `docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json`. The read-only cold-export mode 0400 is recorded separately from canonical source mode 0644.

The original cold report records 139.322747176 seconds under the unchanged 180-second bound, 11/11 outer checks, 5,051/5,051 nested checks, 38 complete phases, and natural process-owner cleanup with ECHILD. The actual retained B3 bytes match 23 leaf native manifests and their images/sources. The machine-plan and ordinary-wire retained builds additionally match the exact cold report and full source closure; their original compiler requests, input/output bytes, compile receipts and produced images were checked.

The original component results remain: native component tests 67 PASS, machine-plan selected callers 44 PASS, journal selected callers 94 PASS. Ordinary wire ran all 89 selected tests and failed exactly `test_native_timeout_is_incomplete_terminated_and_not_adoptable`: 7.074126838999746 seconds exceeded its existing 5-second bound. Its report retains all eleven Agent tools entering the selected wire, 77,319 ordinary calls, and 17,221,711 status-1 returns. The executed environment was Python 3.14.10. No default whole-stack or full retained-suite success is claimed.

## Exact original ZIP

`original-zip-parts/` contains the ordered 4 MiB parts of one lossless Zstandard stream. The complete compressed stream is 61,901,245 bytes with SHA256 `c2421313d67986bcdf6f15f484f156a4a874e7c80ca216268d45db2e94b3bc02`. Concatenate parts 000 through 014 in numeric order and decode with Zstandard to reconstruct the **exact original ZIP**, including all original container bytes. The compression run independently decoded the stream, compared every decoded byte with the original, rechecked the complete original SHA256 and size, and verified each part again. No source ZIP was deleted or modified.

`ORIGINAL-ZIP-PRESERVATION.json` is the unmodified local preservation receipt, so its historical `publication_completed: false` remains intact. `PUBLISHED-BLOBS.json` separately records every later successful immutable Git blob creation and its matching precomputed Git SHA1. Each file stays below GitHub's 100 MiB blob limit.

## Compact originals and audit program

`AUDIT-ORIGINALS.tar.xz` retains all 23 small original reports, complete outer/source inventories, exact canonical GitHub commit/tree/run responses, verifier source, logs and preservation records (3,281,967 unpacked bytes). Its manifest binds each member's size, SHA256, Git blob SHA1 and mode; all members were decoded and checked after creation. The main audit and build/phase binding reports are also exposed as ordinary JSON files.

The audit completed once in 8.000801360 seconds; lossless compression, independent decoding and part readback completed once in 3.009710959 seconds. Those are evidence handling times, not product qualification times. This publication preserves original success and failure evidence; it does not declare the whole HIA rewrite complete.
