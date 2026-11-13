# Source R3 terminal chunk transport

This is an evidence transport correction for the original Source R3 archive. It does not run or change a product, generator, test, budget, source snapshot, archive manifest, or archive byte.

## Exact mounted representation

The audit mounts `archive/chunk-000.bin` through `archive/chunk-073.bin` as 74 original binary files. The last logical chunk is mounted as `archive/chunk-074.base64.json`, an immutable UTF-8 wrapper (Git blob `8c43200601b343faab093975604091635f67ef91`). Strict base64 decoding recovers exactly 57,298 bytes, original Git blob `ebdcd775af1e64a8d647f0d8463f5717cde38d9e`, SHA-256 `ac1a4d90baa773970038483fbfe2f44cf1647e78aacc306f192643f35b30b7c1`.

The original `EVIDENCE-MANIFEST.json`, Source observations and five historical recipes are unchanged. In particular, `recipes/source-r3.json` records the original all-binary layout; its final binary reference is now supplied by this wrapper and the explicit transport mapping in `TRANSPORT.json`. This audit does not claim that all 75 raw binary files are mounted.

## Standalone reconstruction

From an audit checkout, run:

```sh
python -B source-r3-d79-v87/transport/reconstruct_source_r3.py --root source-r3-d79-v87 --archive-output /new/path/FROZEN-SOURCE-EVIDENCE.tar.gz --report /new/path/READBACK.json
```

The output paths must not exist. The script checks the fixed original manifest identity, all 75 ordered chunk identities and offsets, canonical wrapper encoding, the exact gzip SHA-256, gzip CRC/ISIZE, and every one of the 3,554 ordinary 0644 tar members against its original size, SHA-256 and Git blob identity. It writes original compressed bytes without recompressing them. It imports no product module. Unchanged source reconstruction dependencies remain those recorded by the original source archive; this transport does not make a previously external Git dependency self-contained.

## Actual validation and limits

The successor readback used the original retained outer ZIP for the 74 binary inputs and checked their recorded original CI full-GET receipts. The wrapper was created and fully read back through the Git connector, then decoded and combined with those exact original binary inputs. The resulting 38,854,610-byte gzip equals the original archive; all 3,554 members (178,076,592 logical bytes) also equal the original ZIP raw members. The outer ZIP identity was checked, and the corresponding member reads checked their CRCs. The previously completed whole-outer CRC verification remains a separately retained original report.

The generic Git connector accepts UTF-8 text and did not provide fresh binary GET bytes in this successor. The original CI/root binary readback receipts are therefore explicitly inherited, not relabelled as a new connector read. The terminal raw chunk's isolated ref update had an unknown result reported by the parent; no approval/security denial was reported and this successor did not retry that raw ref update. The new UTF-8 representation preserves the original data and exposes an independently checkable recovery path.

`READBACK.json`, `TRANSPORT.json`, and `ORIGINAL-CI-READBACKS.json` preserve these precise boundaries. No Native, cold, default or whole-product qualification is added. The original CORE-JOBS-SNAPSHOT remains a historical snapshot at its recorded capture time, not a claim about current run status.
