# Recover the original failed R1 source snapshot

This independent evidence helper restores the exact 3039-file terminal worktree from original run 43379129114, whose first checker pre-generation command failed. It verifies the fixed 0803f01c manifest, all 49 binary Git chunks, the complete gzip stream and all 1178 original tar members. The original failure is retained.

The original archive stores 235 source files and references 2804 exact Git blobs in four fixed original commits. This helper fetches only those four commits into a separate bare repository, independently reconstructs their trees, validates every dependency and restores all 3039 files (97,733,589 bytes). It then produces a self-contained RECOVERED-SOURCE.tar.gz and verifies every member again, including mode, Git blob and SHA-256.

The workflow has contents:read only. It never imports or executes product code, runs a generator or test, changes a product or audit ref, or uploads source Git objects. Success describes evidence restoration only. The computed source tree is an identity of restored bytes, not a published candidate commit or a qualification.
