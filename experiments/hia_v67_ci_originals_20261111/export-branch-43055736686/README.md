# Original v67 export-branch cold failure, preserved without rerun

This checkpoint is evidence custody only. The original workflow remains **FAILURE**.
It does not qualify the native delivery, alter the frozen 608 source, or authorize
removal of any retained Python/Rust owner.

## Exact original execution

- Source commit: `608157e52b0b94e0d294f6b99c4e809869f183aa`.
- Source tree: `e7c29a60796a1a78946a2c667aa80df86529e532`.
- Run: `43055736686`, attempt 1, push of the exact source custody branch.
- Source job `130644564091`: 354 original tests PASS in 317.882 seconds.
- Native job `130644564588`: the original cold step FAILED; subsequent native steps were skipped.
- Cold elapsed: 180.178098861 seconds under the unchanged 180-second limit.
- Original checks: 6/11. Completed phases: 34/38, zero phase exceptions.
- The unfinished phase records are original/modified `names` and original/modified `exports`.
- Original process status is `QUALIFICATION_TIMEOUT`, return code -9. Cleanup completed,
  observed ECHILD, and retained no direct children. Cleanup is not a product PASS.

The other original push and same-tree PR runs are separate observations. They are
not substitutions for this failed run and are not asserted complete by this checkpoint.
The PR-head-branch push source job log retained here independently records 354 PASS
in 547.839 seconds; this timing difference does not change either denominator.

## Complete original bytes

The official artifact `13872740157` is 57,817,163 bytes, SHA256
`78a0f267de0569aa84f6c1fc8c1f8ba597e1839dfd24288fcdf53f0e6083d1d5`.
Every one of its 6,285 members was read and CRC/SHA checked: 434,334,786 decoded bytes.
All 34 completed-stage ZIP archives were also fully read against their original
retention receipts: 36,669 files, 2,121,701,060 decoded bytes, exact member hashes,
lengths and modes. The partially executed final stages remain in the outer ZIP.
All 682 cold source files were bound to the exact frozen Git leaf bytes and IDs.
The original cold-export mode 0400 is recorded separately from canonical Git mode.

The original ZIP is retained losslessly as 12 numbered zstandard parts.
The combined compressed data is 47,467,983 bytes, SHA256
`062c02d30a2fc0bc8034b9656b0e21b6d3cb1df94bc08b174ef44745a7882b57`.
Every part has a SHA256, length and Git blob SHA1 in `ORIGINAL-ZIP-PRESERVATION.json`.
`restore_original_zip.py NEW_DIRECTORY` independently checks the parts and restores
and rereads the exact original ZIP. An actual restoration was completed and recorded
in `RESTORATION.json`. zstandard 0.25.0 was used for preservation.

## Auxiliary audit history

The first integrity-audit script incorrectly required the embedded cold owner to
be literally equal to the standalone owner receipt. The actual producer appends
`receipt_sha256` and `supervisor_returncode`; all original fields were identical.
That auxiliary HOLD, its exact script, output and partial member inventory are retained.
The second audit checks the exact two-key extension, every original owner field and
the standalone receipt hash, and completed as `ORIGINAL_EVIDENCE_INTEGRITY_VERIFIED`.
No product test, cold process or workflow was rerun for either audit.

The two audit runs, complete nested/outer inventories, API observations, complete
original job logs, preservation/restoration scripts and outputs are in
`audit-originals.tar.xz`, with typed metadata and member hashes in `AUDIT-ORIGINALS.json`.
`AUDIT.json` is the final integrity report; its original cold status is still FAIL.
