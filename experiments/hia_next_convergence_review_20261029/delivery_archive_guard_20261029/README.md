# Delivery archive preflight repair

The installed script `/tmp/hepta-next-build-delivery-archive.py` has SHA256 `b7ce40151486d247658efb600418146292739e125dbbb20f1f22b4595d6d6a90`; its original SHA256 `efa3dac7b74da3a5c27fd7390d16680196611665eae7511cea31be75eefa2123` and full original bytes are retained. No existing ZIP or producer observation was changed.

## Closed implementation findings

1. Fixed, glob-selected and explicit extra directories all use one directory admission/walk. Root and descendant `.git` markers, worktree `.git` files, symlinks (including ancestor and descendant components), and nonregular files are rejected. An explicitly selected evidence subdirectory inside a project remains allowed; the enclosing live checkout is not recursively copied.
2. The before-v8 phase excludes v7, v8, v9 and v10 receipt/raw-directory path components, including extra-path routes.
3. Every collected candidate is preflighted before the first ZIP constructor. Known GGUF/GGML/safetensors names and temporary variants, disguised GGUF magic, the configured Qwen3 model root, downloader request JSON names/structures, and signed/bearer URLs in candidate text are refusal categories. Errors disclose paths/categories without matching values. Source evidence is neither redacted nor deleted. All included candidates are read again and checked against the preflight content/file identity before writing.

Reads reject nonregular files before blocking, use nonblocking/no-follow descriptor flags where available, and enforce a 128 MiB per-file review budget. The budget is a conservative archive admission limit; a larger legitimate artifact requires explicit review of this bound, not silent omission.

Model `transport-*.request.json` messages and public acquisition outcome receipts remain eligible. Malformed historical failure evidence remains intact; its complete quoted strings and raw text receive URL classification. Known binary/nested archive formats remain subject to separate content review rather than a claim about arbitrary binary secrecy.

## Verification and limits

Final source passed **36/36 tiny synthetic guard checks** plus an AST check that preflight precedes ZIP construction. The fixtures cover root/descendant Git markers, all symlink positions, weight names and magic, configured protected roots, bounded reads, FIFO refusal, downloader structures, JSON/percent/HTML URL escaping, value nondisclosure, positive ordinary evidence, old-phase exclusion, candidate change after preflight, and admissibility of the packer source itself. They import only this standalone packer and standard library.

Packer `main` was never invoked. ZIP constructor calls, new archives, transfers, native/model/tokenizer/compiler executions were all zero. The earlier successful development fixture run is retained with its own source hash; the final fixture run covers the added extra-path phase check. No complete real archive was generated, and no historical observation is retagged.

The earlier automatic approval rejection for Library transfer remains in effect. This engineering repair does not approve an upload, prove arbitrary opaque bytes nonsensitive, or replace independent review of nested ZIP/tar/Git bundles. Filesystem checks assume a cooperative task workspace; this is not a hostile-host proof.
