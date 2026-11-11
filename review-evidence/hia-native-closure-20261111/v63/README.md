# Exact v63 qualification observations and recovery boundary

This evidence belongs to product commit `93d66bcc3acb88212c9b153d7852ba22eeab24c8`, tree `0a67bf07951505a50e9aeb888f1c2c448d1eb816`, with profile `selfhost-core-linux-x86_64-v63-native-request-release-signatures-helpers` and contract SHA-256 `80ed89ca6806136d8fae8c179992fa3ea72228e75a0f8d4e2439ab29b2b2af1e`. The support closure contains 583 source files plus the contract. The local pre-publication commit `697866d` has exactly the same tree; its different commit metadata does not change source bytes.

## Completed observations

- All 42 HIA source generators reproduced every tracked byte exactly.
- Local cold under CPython 3.14.10 completed in 148.166989520 seconds: 11/11 wrapper checks, 38/38 phases and 5,049/5,049 qualification checks. The original 180-second deadline and two oracle workers were retained.
- The independent local audit actually read every member of all 38 phase archives: 42,623 payload members plus 38 manifests, 2,403,380,490 decoded bytes. All source, actual compiler, process and archive identities were checked. Payload UID/GID were never stored by the archive format and are explicitly not independently verified; existing retained-file ownership was checked.
- Local source controls: 298/298, CPython 3.14.10, 375.714398188 seconds including preparation; before/after source maps identical.
- Local worker plus independent review: 18/18, CPython 3.14.10, strict current cold selection.
- Local types, origins, signatures, helpers and joint native composition: 58/58, CPython 3.12.14, strict current cold selection. The combined selection prohibits retained owners and checks ordinary bytes, diagnostics and 24 VM lifecycle paths.
- Local language coverage: 1,242/1,242 native checks and 10/10 assertions, 103.440506563 seconds for the coverage run.
- Current native builds reproduce worker image `a206d5e0a54fa67a30655461ff970e1810e38070a86972d7b0f3d631b6b6e1dd` and installer executable `3b089aa5c54fc93bf3b0eb0b11018f2dba0b49142e53be78086b5cf9193196d0`.
- Both GitHub Core-only runs completed successfully: push [42965207061](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42965207061) and pull request [42965213564](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42965213564). Each ran 298 source tests and 17 native groups totaling 555 unittest cases. The 555 already includes the 10 language assertions. Repeated runs are not additional unique coverage. The pull-request checkout is synthetic merge `d36fcb90c7b0b46fe9b5dfe391f18e57603e92dd`, whose tree is exactly the same `0a67bf...`; raw metadata retains that distinction.

## Environment interruption and available evidence

The cloud executor disconnected and was temporarily unavailable. After recovery, the project workspace and these reports survived, while the `/tmp` and `/home/agent` transient contents did not. `environment-recovery-observation.json` records the observed state without asserting an unproved failure cause.

The original local v63 cold directory and its phase ZIP payloads are now unavailable. The original outer report, full compressed 53,015,723-byte qualification report and the independent audit remain. Four previously relocated historical cold archives also lost their transient targets; their old custody receipts describe the earlier completed archival operation and do not establish present availability. No replacement payload has been invented or labelled as the original.

The first independent PR artifact audit read its inputs but failed while writing compact reports with `Errno 28`; its original failed report and script are retained under `github-ci/`. Subsequent SIGKILL attempts never produced a completed audit and their temporary files did not survive. The cause is unknown. These are not successful independent GitHub payload audits and do not alter GitHub's separately retained successful CI results. The original GitHub artifacts remain available under their official identities and a seven-day retention period; preservation on the user's machine is separate ongoing work.

An uncommitted request-journal development candidate in the transient worktree was also lost. Reconstructed source is being versioned independently on `codex/hia-native-state-owner-20261111-e26e`; its source identities and tests must be new. Its earlier development observations do not qualify reconstructed bytes and are not part of this v63 product tree.

## Still open

The separately supervised exact93 complete retained regression on ROG is still running at this evidence snapshot. Neither its full pass nor whole-native delivery is claimed here. The NDU research workflow was queued at the retained API observation; a queued run is neither a pass nor a failure. No production cutover, default native installation, state migration or old-stack retirement occurred. The durable service, remaining lowering/build/runtime owners and release lifecycle still require implementation and qualification.

`evidence-files.json` indexes exact bytes in this directory except itself. Original observation files are retained unchanged. Compressed JSON files use XZ and can be decoded without project code.
