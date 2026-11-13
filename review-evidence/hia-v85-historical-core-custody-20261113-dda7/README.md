# Historical Core R2/R3 original-byte custody

This packet completes Git custody of a pre-existing 43,711,416-byte, Git-base-dependent archive. All 84 existing UTF-8 chunk wrappers received immutable blob acknowledgements and complete equal readbacks. The exact wrapper sequence was independently checked against the protected original archive; restore_archive.py then actually reconstructed the complete archive and matched its SHA256 and computed Git object identity. Only that newly generated verification copy was reclaimed.

The archived INDEX describes 13,385 logical files (605,784,846 logical bytes) and 4,672 unique objects. 1,654 objects are embedded; 3,018 require the exact 4b19af89a766593f7d5f1cc2db256e81aba7afcb Git base, tree 1bc7c90996e1910ad66ba771b0bfee1d5bfa655c. This packet is therefore not self-contained. The archive's INDEX, BASE-METADATA, original modes and restoration instructions remain byte-identical. The original R1 archive and protected R2/R3 archive are retained locally.

Only UTF-8 wrapper blobs are uploaded; the archive's computed raw Git identity is not a claim that its binary Git object was uploaded. ORIGINAL-PUBLICATION-PLAN.json is the old frozen partial-publication record and remains unchanged. INDEX.json and ACKS.json record the newly completed publication, so the old false publication flag is not overwritten.

Restore the archive with:

    python restore_archive.py --index INDEX.json --wrappers chunks --output restored-originals.tar.xz

Then follow ORIGINAL-RESTORE-README.txt and the archived INDEX to reconstruct the logical files against the immutable Git base. The helper does not extract or execute archive contents.

These are historical development and failure originals. This archival action runs no product/native/compiler test, changes no qualification, moves no production ref and authorizes no production legacy deletion. Current whole-native qualification remains false.

