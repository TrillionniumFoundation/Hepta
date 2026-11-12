# Lossless original-startup evidence

The original 17,207,232-byte archive is published as ordered binary parts. Its 476-member manifest and every original failure remain unchanged. Concatenation restores the exact original `.tar.xz`; no original source, log or binary was removed from the archive.

From the repository root:

```sh
cat experiments/hia_optimizer_eval/next_20261028/archive-parts/agent-startup-oom-final-01/part-* > experiments/hia_optimizer_eval/next_20261028/agent-startup-oom-final-01.tar.xz
sha256sum experiments/hia_optimizer_eval/next_20261028/agent-startup-oom-final-01.tar.xz
```

Required SHA-256: `274524f823d0f8b2d3fc9b79a202cab6d7430934bd1612cad66011f0110d3ada`. `INDEX.json` binds each ordered part by byte count, SHA-256 and Git blob identity. The original member manifest remains alongside the reconstructed archive.
