# Original source history and independent AOT raw evidence

All original archives and source checkouts remain unchanged. The files in this directory are lossless transport parts, at most768KiB each. MANIFEST.json records every part and the exact original/encoded identities. SOURCE_HISTORY.json records verified bundle refs, the f2b76 prerequisite, strict Git pack validation and the distinction between original commits and tree-identical API publication.

The source-through-3707 bundle retains the local integration history through3707b871ecbe563233ee9a3b69299fc627408936. The separate small AOT source bundle retains the independently measured8ce43b8d8f4bf415387ebf4c52435939cd4ad6d2 source and its4aedbdfc029e9d77dcf319626e8cc332207c0ff0 evidence commit. The AOT measurement must not be relabeled as the later integration or API commit.

The original AOT TAR is39,475,200bytes with SHA256 ae47856d8672670fe6a4cd3f10d341ba8d4df172b5813a067ef8c484bef97310. It is compressed with deterministic gzip and split. AOT_MEMBERS.json inventories all members and every ordinary payload hash. No member is dropped, redacted or rewritten. PUBLIC_SAFETY_SCREEN.json states the bounded screening scope and findings; it is not a general absence-of-secrets proof.

## Restore exact files

Run with Python3 in a new output directory:

    python3 RESTORE.py --output /tmp/hepta-retained-20261104

The script verifies every part, reassembles each encoded payload, decodes gzip where applicable, enforces original sizes and verifies all original SHA256 values. It does not extract the TAR or execute any restored code. The packaging process ran this restoration and compared the exact resulting bytes.

Both Git bundles require f2b76f5741c83822be2e12cf5a50b50a8d27b96a and its reachable objects. In an existing clone containing that prerequisite:

    git bundle verify /tmp/hepta-retained-20261104/original-sources-through-3707.bundle
    git fetch /tmp/hepta-retained-20261104/original-sources-through-3707.bundle HEAD:refs/heads/review/original-3707
    git bundle verify /tmp/hepta-retained-20261104/independent-aot-original-source-history.bundle
    git fetch /tmp/hepta-retained-20261104/independent-aot-original-source-history.bundle HEAD:refs/heads/review/aot-original

Inspect the TAR member manifest before any manual extraction. The preserved AOT campaign includes failures and69 missed strict Rust comparisons; successful artifact restoration does not turn those results into a universal performance or safety claim.
