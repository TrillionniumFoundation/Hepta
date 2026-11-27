This is a lossless, Git-base-dependent derivative of the preserved R1 archive.
It is NOT self-contained. No test outcome or source qualification is changed.
All 13,385 logical paths, original modes, mtimes and object identities remain in INDEX.json.
Each regular path's object SHA resolves through object_catalog: embedded members contain
the original bytes; git_blob entries require the exact repository/commit/tree/path/blob,
size/SHA256/Git mode recorded in that entry. Mutable refs are never authoritative.
BASE-METADATA.json contains all 3,153 published base entries and the root verification identity.
All referenced contents were additionally freshly read and verified by this builder.
To reconstruct, materialize the exact 4b19af89a766593f7d5f1cc2db256e81aba7afcb base,
verify its tree 1bc7c90996e1910ad66ba771b0bfee1d5bfa655c and the referenced contents,
then create each logical path from its catalog content, applying the logical original mode
and mtime (not the referenced base path's mode). Symlink targets, if any, are literal metadata.
Refuse unsafe paths, unexpected object identities, missing objects or size/hash/mode mismatch.
The original R1 archive and all original raw files remain untouched.
