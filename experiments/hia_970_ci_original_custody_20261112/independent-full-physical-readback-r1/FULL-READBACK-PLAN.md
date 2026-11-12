# Exact 970 original physical readback

This is an independent read-only evidence audit. It imports no Hepta module, invokes no compiler or executable, and does not rerun any original product case. Its results must not be described as a new qualification or as execution of the full 5,400-second retained suite.

## Already observed transport

The one create run 43171286581, attempt 1, at workflow commit 75d8de12f462bbeab29364577d3575c30fc12626 succeeded. Its two provider artifacts are 13921918024 (314,648,599 bytes, SHA-256 4be52f18e29956996c88674e638f96fd24dcc137cd72fc771bd15e8d754244ba) and 13922162652 (284,930,266 bytes, SHA-256 f41a9aa57ed55bc040856655fab14c4d80c663d6e9bd243be27c3f18654c29c7). Each was downloaded once through its official file reference, then independently reread in full locally. Both exact provider seals matched. Signed transport URLs remain private.

The two scripts in this checkpoint have only been parsed. Their reconstruction and physical evidence predicates have not yet executed. The Actions worker's original success is separate from these pending local audits.

## Reconstruction

`reconstruct_full_original.py` reads the two fixed local provider ZIPs. It requires exactly 14 regular members in each, equal FINAL bytes and all 11 original controls, original range identities, the reviewed A/B and policy identities, the natural 900/3 guardian and closed ECHILD, and complete control/input joins. It concatenates only the two fixed `slice.bin` members, with lengths 314,572,800 and 284,854,451 and adjacent offsets 0 and 314,572,800. It then independently hashes the full created ZIP.

The full output must be 599,427,251 bytes with SHA-256 40e81308484173d36153f6a3014293a78705aa28e8f8f7718dcdd3d87c03f580, exactly original artifact 13911977275 from CI run 43140734709 at source 9704596acc4470bd0042838586602e26bac7b3d1. It does not download the original large artifact again. A failure preserves the local audit report and every original provider ZIP.

Exact command from `/workspace/scratch/e26ed3e2edcf/cold`:

```sh
python3 reconstruct_full_original.py
```

## Physical evidence audit

`full_original_physical_audit.py` receives that reconstructed original ZIP and independently pinned DIRECTORY, SELECTED, and previous semantic-readback originals. It verifies the full external seal before and after all reads, the exact complete 19,100-member central directory, and all 1,649,066,402 uncompressed outer bytes with CRC32, SHA-256, and length. It compares the prior 354 selected member identities directly with the originals in this full ZIP.

The 1,025 previously unselected file references split into 1,024 original temporary-directory member paths and one original worktree source path: `tools/hia_selfhost_process_owner.py`. The latter has a retained cold source-only copy. The audit verifies its same-content SHA and size while explicitly declining to recreate the original worktree inode. All 787 declared cold source bytes also exist in the original ZIP and will be checked against the original source map. This is an explicit copied-source binding, not an invented original path.

The 38 phase archives are separate from those 1,025 records. Their existing receipts declare 66,295,061 packed bytes, 42,623 original files, and 2,397,882,660 unpacked bytes. The audit reads every phase archive, original ARCHIVED receipt, original manifest, and every retained member's full CRC, SHA, size, and mode. It binds original requests, actual input/image/output bytes, native observer binary frames, emitted image prefixes, and embedded phase observations to the archived receipts. No archive member is extracted as executable code or invoked.

The audit also joins the 87 root receipts (B0 plus 86 calls), both emitted observers, and the complete 12 original/native ELF gzip payloads for the six successful boundary cases. Five error cases remain the original recorded errors. Original source and metadata are checked again before a success result is saved.

Exact command from the same directory, only after reconstruction succeeds:

```sh
python3 full_original_physical_audit.py --archive full-zip-two-parts-r1/actual-local-readback-r1/artifact-13911977275.original.zip --selected-root container-readback-r1/inner-originals --semantic-report semantic-readback-r2/SEMANTIC-READBACK.json --output full-physical-readback-r1
```

Historical acffa failures, original large-observation CUSTODY_HOLD, earlier framing HOLD, cancellation, and all UNKNOWN observations remain unchanged. The new reader's size bounds apply only to evidence access; no product 4 MiB, 180/3, 3/5-second, 2-worker, 38-phase, or 5,400-second requirement is changed.
