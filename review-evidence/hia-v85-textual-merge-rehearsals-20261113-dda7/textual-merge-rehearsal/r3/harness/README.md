# Fixed textual merge rehearsal

This is an evidence-only harness. It does not run, import, compile or test Hepta product code.

The driver fetches only the histories of the two fixed commits using `--filter=blob:none --no-tags`. It verifies their full tree inventories and the fixed pair of best merge bases, checks out the fixed main commit detached in a new temporary repository, and runs exactly:

```
git merge --no-commit --no-ff a733926a2786a3d4a37304bd2d18ebb2eac57ac9
```

The result is `TEXTUAL_MERGE_REHEARSAL_NOT_QUALIFICATION`. A conflict exit code of 1 is an expected observation only when the unmerged index records real conflicts. It is never a semantic or product qualification pass. An unexpected Git failure, timeout, missing identity, or evidence-integrity failure fails the harness.

## Fixed inputs

- Main: `51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8`, tree `578a72d9bd6dadf0375bed33e3d1aa5341c8f452`, 2579 files.
- Other side: `a733926a2786a3d4a37304bd2d18ebb2eac57ac9`, tree `1c5ba7e1217f46f2b95512640d08f19e2cc8b1fd`, 3324 files.
- Best merge bases: `5831f52fada45e076f8f68f198a15c0585e6104f` and `93d66bcc3acb88212c9b153d7852ba22eeab24c8`.

## Evidence

The artifact preserves original command stdout/stderr and return codes, complete source tree inventories and commit bytes, all stage-0 and conflict stage-1/2/3 entries, each conflict-stage object, conflict worktree bytes and symlink targets, changed non-conflict stage-0 objects, complete worktree inventory, staged/unstaged/combined binary patches and raw index/status bytes. Git's `AUTO_MERGE` tree is inventoried when present.

A lossless archive is verified and split into immutable JSON/base64 Git blobs. Every blob is independently read back and hashed. Artifacts upload with `always()` also retains the archive, raw files and partial failure receipts if upload or validation fails. Exact original outer Actions ZIP identity becomes available after GitHub finishes uploading it; the driver does not claim that ZIP digest in advance.

## Isolation and permissions

The four-file harness tree contains no product workflows. The API requires a real commit parent, so this tree uses the existing diagnostic harness `76310d3af95fb7a9852a1d9ed593530ac8b7e732` as its only parent. Neither product branch nor any PR/audit branch is updated.

Git runs with isolated global/system configuration, no hooks, no external merge/filter commands, disabled rerere/autostash and `core.autocrlf=false`. Credentials are an ephemeral GitHub-only HTTP header and the fixed repository Git-blob API token; they are never included in URLs, command records, copied configuration or logs. `contents: write` is used only because immutable create/read blob calls require it; the driver has no commit/ref/PR mutation endpoint.

No product CI is rerun, no conflict is resolved, no merge commit is created, and no original test limit is changed. The harness's own bounded setup/observation time is unrelated to product budgets.

## Exact main recovery export

Before merging, the runner exports commit `51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8` with `git archive`. It verifies every member against the complete original Git tree, including file mode and raw Git blob, plus every member's byte count and SHA-256. The fixed export has 2,579 files and 72,234,761 raw file bytes. A lossless gzip stream and its per-member manifest are retained in the same 90-day Actions artifact as `MAIN-51BC-SOURCE.tar.gz`.

This separate source archive is not claimed to be included in the Git-chunked `COMPLETE-REHEARSAL.tar.gz`. Its exact archive identity and all member bindings are included in that rehearsal evidence. Original source Git objects, the source archive, and the actual raw merge artifacts retain distinct custody records.

The driver verifies that its checkout is the triggering commit, has the sole approved parent, and contains exactly the four ordinary harness files. It also preserves worktree bytes that differ from their stage-zero index object, including conflict markers and untracked merge outputs. A timeout, unexpected merge failure, capture error, or incomplete evidence upload remains a failed harness run. Expected textual conflicts are an observed result, not a semantic test failure or pass.

## Preserved first observation

Run `43363034253`, head `6b94cbce7c3c039ea518d75cd40a7737a33f0d02`, failed its strict single-base assertion before running any merge or source export. Its complete failure evidence remains immutable at custody index `aae539b3f78c7345cf351b22d95da752703ec323`. This successor binds both actually observed best ancestors and records both raw commits and complete trees. The merge command stays unchanged so Git handles its multiple-base semantics normally; no base is selected manually. Conflict stage 1 may therefore contain Git-created virtual-base content, which is preserved verbatim with all other stages.

## Explicit input-tree materialization

Run `43363498126` reached the real merge once, which returned 128 while lazy-fetching a missing blob from the promisor remote. Its complete failure, index, stdout/stderr and verified main source export remain preserved at custody index `f4736df9b40bd6ad5dff65b1d1a36ec60a567c59`.

This successor first checks local availability of exactly the unique blobs named by the two fixed head trees and two fixed ancestor trees, with lazy fetching disabled for that check. It requests only the missing, already tree-bound object IDs in one explicit fetch and requires all of them to be locally available with blob type and size before merging. It does not fetch every historical blob, expand to arbitrary history, retry an unknown merge or change the merge command. Any remaining preparation or merge failure stays a failed observation.
