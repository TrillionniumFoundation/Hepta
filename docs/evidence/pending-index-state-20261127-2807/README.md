# Bounded pending-index state checkpoint

Source 4176b2f48d84eaaf5e705354c25a9f6cd105eea7, tree 227d16256bb7376ce7d058eae2c63829783b77c2, parent d43726be01fa7d2adb40a74c0201d49aca81691d.

The native state helpers retain two independent 8192-entry cohorts inside the existing 32 MiB owner. The cap bounds pending publications, never retained archive cardinality. They preserve the original 4096/128 watermarks, 256-entry large write prefix, 128-entry read-only watched tail, generation wrap, in-flight custody and immutable record transitions.

The four independently pinned native roots compiled the actual helper and its observer. The corrected layout passes 41 controls and preserves all eight metadata response buffers. The first layout was unsafe: a separate actual native probe observed 384 bytes of overlap. Its original 40-control report and full inputs remain beside that negative result; its earlier PASS did not test the output overlap and is not accepted as a safe layout.

The independently compiled original Linux Rust production functions generated 49,949 observations in a new test-only observer. The test preserves every original production byte and all original test assertions. The finite worker completion block is copied verbatim with an exact SHA, rather than rewritten as an oracle. This run selected one new observer and filtered the previously qualified 447 tests; it does not claim to have rerun that original suite.

Actual native replay made 83,491 calls and compared 33,152 complete 384-byte retained record/stamp representations. Its first run found three state mismatches: the native completion helper left requested set after the exact generation and pending tail were fully applied. The corrected helper matches every observation from the unchanged original reference. Both complete native runs, the original raw corpus, exact original execution, and all failure evidence are retained.

The native construction archive has 46 regular files and contains the four roots, generated source, executable profiles, native images, construction receipts and complete raw controls. The separate 52-file construction input kit preserves the exact local rendering/import/profile sources used. This independent diagnostic kit is explicit; an integrated current-head reconstruction remains a later gate.

No disk index, native background cache I/O, complete original-reader pair, public integration, whole cold, Runtime or installed Worker qualification is claimed here. This is a continuation checkpoint for the real disk and public implementation.

## Archives

- native-construction-and-controls.tar.gz: 2,583,785 bytes, SHA256 b0a3d5ad93b5ab79c2d75e259ef6baf2bdf65dd77e9933b7a30e21e1ef95969c.
- original-observations.jsonl.gz: 1,541,316 bytes, SHA256 fd8651036f81f4ee330ce282d225db9c2b9b6f31d798a17a49c25ef778036b8e. Uncompressed: 47,409,364 bytes, SHA256 5f7481f4648aac53e536fb2bb919601f329655d1957e8574a638a5ec0a4f17be.
- construction-inputs.tar.gz: 228,680 bytes, SHA256 e9037417094b73b95a09584d9cbd5b0094546ebcd6f5f451a939e91428c6daff.

All archives contain retained control data. They do not install or activate a worker.
