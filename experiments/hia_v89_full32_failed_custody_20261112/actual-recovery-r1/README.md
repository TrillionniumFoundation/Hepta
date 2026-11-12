# Failed full32 supply: exact original custody and diagnosis

Original operation: run 43283027193, artifact 13974465966, **HOLD**.
Receiver: run 43286445040, attempt 1, workflow ffa984c803c1f7c06649ed16262ee378d8cc48f3, control b43a354a91c7b2bb858edab40ffe4c8cb1fc24ca.

The three official artifacts were downloaded once each and reassembled into exactly 818,594,350 bytes, SHA-256 `9da285831263db03d5e24e26e427f867763f39d1d607ccf34f21ef519163785d`. The independent receiver audit checked the full bound 900/3 lifecycle, natural exit 0, ECHILD, identical FINAL bytes and all eleven original controls across the three parts.

The complete original ZIP has 48 bodies (818,584,840 expanded bytes). The nested 785,234,691-byte gzip/tar was streamed and hashed without extracting source, wheels or package payloads. All 4,797 archive members and 863,570,811 original regular-file bytes match the typed catalog. All 4,076 actual product source bodies match the original source-before snapshot.

## Actual failure

`SUPPLY.json` records a `PermissionError: [Errno 1] Operation not permitted` at `workflow_process.py:33`, the `os.killpg(process.pid, 0)` probe following `process.wait`. The call was made from `supply_v87.py` during the ninth command, `apt-install`. That command has an exact frozen request and complete stdout/stderr, but no completed receipt. Its stdout contains package installation and setup output; its stderr includes an `_apt` access warning. These are insufficient to assert an apt nonzero return code.

The supplier returned 2, its outer driver returned 1, and the original 10800/3 owner naturally closed with ECHILD and no remaining children. No full qualification report was produced. The separate 1800/3 custody owner returned 0 and preserved the partial result.

Custody remains incomplete: `supply/apt-cache/lock` was unreadable (uid/gid 0/0, mode 0660, EACCES), and `supply/apt-cache/partial` could not be traversed (uid 42, gid 0, mode 0700, EACCES). No missing content is invented.

## Durable evidence scope

Each `raw-evidence.tar.gz.part-*.base64` is strict base64 text followed by one newline. Decoding the six files in the order in `ARCHIVE-PARTS.json` and concatenating their bytes reconstructs into a 1,343,859-byte gzip archive (SHA-256 `6c30534dde98ecd209bd32a8d0ebe9009d17497ca3767362f6db25b72dbd4036`) containing all 209 selected small originals, SDK observations, independent readers, complete archive inventories and their readback results: 7,630,429 bytes. `RAW-MANIFEST.json` binds every file byte, mode, SHA-256 and Git blob. Important originals and readers are also exposed separately.

The 818 MB original ZIP and the three official part ZIPs remain preserved locally and provider-pinned; this small evidence archive does not include those large payload bodies. This checkpoint reports custody and exact failure only. It does not rerun or qualify the supplier, full32, native code, retained 5400-second harness, or any new product. No execution ref is written.
