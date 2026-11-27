# Fixed textual merge rehearsal

This is an evidence-only harness. It does not run, import, compile or test Hepta product code.

The driver fetches only the histories of the two fixed commits using `--filter=blob:none --no-tags`. It verifies their full tree inventories and the one fixed merge base, checks out the fixed main commit detached in a new temporary repository, and runs exactly:

```
git merge --no-commit --no-ff a733926a2786a3d4a37304bd2d18ebb2eac57ac9
```

The result is `TEXTUAL_MERGE_REHEARSAL_NOT_QUALIFICATION`. A conflict exit code of 1 is an expected observation only when the unmerged index records real conflicts. It is never a semantic or product qualification pass. An unexpected Git failure, timeout, missing identity, or evidence-integrity failure fails the harness.

## Fixed inputs

- Main: `51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8`, tree `578a72d9bd6dadf0375bed33e3d1aa5341c8f452`, 2579 files.
- Other side: `a733926a2786a3d4a37304bd2d18ebb2eac57ac9`, tree `1c5ba7e1217f46f2b95512640d08f19e2cc8b1fd`, 3324 files.
- Merge base: `93d66bcc3acb88212c9b153d7852ba22eeab24c8`.

## Evidence

The artifact preserves original command stdout/stderr and return codes, complete source tree inventories and commit bytes, all stage-0 and conflict stage-1/2/3 entries, each conflict-stage object, conflict worktree bytes and symlink targets, changed non-conflict stage-0 objects, complete worktree inventory, staged/unstaged/combined binary patches and raw index/status bytes. Git's `AUTO_MERGE` tree is inventoried when present.

A lossless archive is verified and split into immutable JSON/base64 Git blobs. Every blob is independently read back and hashed. Artifacts upload with `always()` also retains the archive, raw files and partial failure receipts if upload or validation fails. Exact original outer Actions ZIP identity becomes available after GitHub finishes uploading it; the driver does not claim that ZIP digest in advance.

## Isolation and permissions

The four-file harness tree contains no product workflows. The API requires a real commit parent, so this tree uses the existing diagnostic harness `76310d3af95fb7a9852a1d9ed593530ac8b7e732` as its only parent. Neither product branch nor any PR/audit branch is updated.

Git runs with isolated global/system configuration, no hooks, no external merge/filter commands, disabled rerere/autostash and `core.autocrlf=false`. Credentials are an ephemeral GitHub-only HTTP header and the fixed repository Git-blob API token; they are never included in URLs, command records, copied configuration or logs. `contents: write` is used only because immutable create/read blob calls require it; the driver has no commit/ref/PR mutation endpoint.

No product CI is rerun, no conflict is resolved, no merge commit is created, and no original test limit is changed. The harness's own bounded setup/observation time is unrelated to product budgets.
