# R5 formal failure and R6 local development: complete originals custody

This is a lossless, byte-preserving custody package of the completed scopes frozen in INPUTS-FROZEN.json. It contains 10,686 original logical files (581,718,301 bytes) and 3,021 original directories, with per-file SHA256, computed Git blob identity, type and mode. Deduplication changes storage only: 4,658 unique content objects preserve every original path. The deterministic gzip is 143,754,197 bytes, SHA256 da28f0bf38041900615f2bf249ac6d3f8b25e33a3195b45a86ef554f39193363.

## Original results remain separate

- R5 formal CPython 3.14.4 run 43415454682 / job 131852076482 completed 1,224 actual Source methods: 1,214 passed, 10 failed, zero errors and zero skips. The original Source status remains FAIL. Its evidence-integrity report says PASS because the original artifact and source were completely recovered and verified; that is not a test PASS. Its 3,024-file candidate tree is d7e35e1e0b2907a5375bdbdb75c8547e3fa8cd42.
- R6 local CPython 3.12.14 completed 113 generators twice and 1,466 AST parses, plus a separate 140-method Source control group. These local outcomes passed. Its 3,024-file local tree is d3ae0278979b79a570f753b1afbd2d63ecba8a8e. The formal R6 run 43422327653 was still in progress when these inputs were frozen; no later result is included or inferred.
- The prior 541-entry audit ROOT-READBACK is included as an independent original receipt.

No product code, test, build or semantic control was executed to create this custody package. No source, product, audit or PR ref is moved. whole_native remains false.

## What is included

Every file under R5 artifact/ (2,568 actual local files: the original 2,564 outer members and four derived records), the full R5 candidate-ci314 tree, and all R5 top-level .py/.json/.log originals; all R6 local-generation and registration-controls evidence, the complete R6 local-source tree excluding .git, all R6 top-level .py/.json/.log originals, and both actual local harness directories. All original failures, logs, raw buffers, inner compressed containers and source snapshots in those scopes are retained. The local harness authoring data includes its full 10.3-MB normalized authoring input.

Two local published-harness copies contain one additional final LF compared with the exact publication strings bound in Root's actual Git receipt. Both local originals and that original receipt are retained unchanged. HARNESS-COPY-BOUNDARY.json records the exact difference. The local directory is not claimed to be byte-identical to the actual published commit a6026cdb141c79f657b1b097e97f4de34e634974. Root's separate future reconciliation is not included.

The original R5 outer ZIP is deliberately not duplicated into this Git package. Its exact 109,945,006-byte identity (SHA256 533a25c8f61c3412ef50137fb4be2a8c4ee9ac59c3972acd3c6959a1539e3e4e), local mode, original Actions metadata and Root's complete CRC/readback report are retained. Its bytes remain in the original local ZIP and Actions retention; a rebuilt ZIP from members is not claimed to equal that original byte container. Root's separately owned older R5 local 5,397-member / 81-wrapper scope and the in-progress formal R6 outputs are excluded.

## Transport and restoration

Each of the 275 data wrappers is literal canonical base64 UTF-8 with no LF. Its Git blob stores that text, not a binary Git object. Decoded byte identities are explicitly computed identities. Concatenating the decoded wrappers in TRANSPORT.json order recovers the complete original gzip. The archive contains all logical data through its CAS manifest plus complete freezing metadata and packaging scripts; it does not rely on an index in place of the original bytes.

The full 2,886,332-byte metadata capsule is also available through six exact UTF-8 text fragments. METADATA-FRAGMENTS.json binds their order and complete reconstructed capsule identity. The capsule contains all original manifests and metadata as exact text; it supplements the archive.

Use the supplied restore.py with TRANSPORT.json, EXTRA-MEMBERS.json, a directory holding the downloaded data wrappers, and a nonexistent target whose parent exists. The helper checks every wrapper identity, canonical base64, the entire gzip SHA/CRC/ISIZE, exact tar membership, every original SHA/Git identity, and all restored file and directory modes. A local full restore has already completed for all 10,686 originals. Git custody becomes complete only when the final Git readback receipt confirms all actual wrapper GETs and the reconstructed archive/member identities; that receipt is separate from these original test outcomes.
