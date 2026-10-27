# Four native-host receipts for source d8e1b676

[Host workflow 40438827770](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40438827770)
completed successfully on all four hosts for
[`d8e1b676665093c416a3484c3d7d7e0ceffe3207`](https://github.com/TrillionniumFoundation/Hepta/commit/d8e1b676665093c416a3484c3d7d7e0ceffe3207).
The four original ZIPs matched their provider SHA-256 digests. All four original
reports then passed a pure-data replay using exact d8e1b676 source exports.
The provider observation was captured at **2026-10-27 02:31:39 UTC**.

| Host | Provider job | Original artifact | Exact-source replay |
| --- | --- | --- | --- |
| Linux x86_64 | [121973953838](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40438827770/job/121973953838) | [12705766058](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40438827770/artifacts/12705766058) | Passed, LF |
| Linux aarch64 | [121973953733](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40438827770/job/121973953733) | [12705556004](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40438827770/artifacts/12705556004) | Passed, LF |
| macOS aarch64 | [121973953852](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40438827770/job/121973953852) | [12705341253](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40438827770/artifacts/12705341253) | Passed, LF |
| Windows x86_64 | [121973953736](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40438827770/job/121973953736) | [12705566479](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40438827770/artifacts/12705566479) | Passed, CRLF |

Each original receipt records 181 foreign calls at `-O0` and 181 at `-O2`,
successful layout checks, and rejection of a compiled wrong C echo control.
These are finite native C ABI checks through the supported Rust-backed frontend.
They do not establish every ABI shape, physical-board or GPU qualification,
four-platform independent owned LLVM support, or complete release success.

## Commit binding and original bytes

The original `native-host.json` reports have no `git_commit`, `gitcommit`, or
`source_git_commit` field. No field was added to the original bytes. Their source
binding is the provider artifact's `workflow_run.head_sha`, its workflow run ID,
and the exact export selected for validation. All identify the d8e1b676 commit.

`provider-observation.json` retains the public provider metadata;
`source-replay.json` records this binding and the observed absence of a report
commit field. `hosts/` contains byte-identical original JSON, including Windows
CRLF. The provider ZIPs contain reports only. They record executable hashes but
do not supply those native binaries.

## Exact shared-source relationship

`source-relationship.json` independently binds every one of the **183 Python
files** under `hepta/` and `tools/`, plus the native-host workflow, across:

1. The immutable 8dcb0d0d Git objects and their already sealed source archive.
2. The immutable 7ef57d1b Git objects.
3. The immutable d8e1b676 Git objects.
4. A fresh `git archive d8e1b676665093c416a3484c3d7d7e0ceffe3207 hepta tools` export.

All selected file bytes and Git blob identities agree. The source tree is
`ad5dcb9118c392ef35cc8621916580eed474621c`. This establishes identity of the
selected host validator and compiler source subset, not of the complete commits;
the full qualification workflow and tests have changed. The new archive refers
to `hosts_8dcb0d0d` by its manifest and encoded/decoded archive hashes instead of
duplicating its 183 source files.

Each report was replayed in a fresh Python process against the exact new export.
Linux/macOS used LF files; Windows used CRLF checkout bytes. The replay helper
blocks native process audit events and verifies source/report bytes before and
after invoking the exact `validate_report` implementation. This is validation
of existing evidence, not repetition of the original native execution.

| Source profile | Actual and original-report compiler SHA-256 |
| --- | --- |
| LF | `baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7` |
| CRLF | `e7a8bc04baaf6b4ae590f5303cdb6af29d09b20547c44b4e7a1873a25131db6f` |

## Archive and data verification

`host-zips.tar.gz.base64` preserves the four original provider ZIPs, totaling
25,571 uncompressed member bytes. Its gzip payload is **24,219 bytes** and the
base64 file is **32,717 ASCII bytes**. Decoded archive SHA-256:

`fb91e7654cc2b54b552e7494d1c51ea8e3c2193c321279f79706d142e0cabacf`

`MANIFEST.json` binds these four new members and the unchanged prior source
archive. `zip-identities.json` retains all provider sizes, digests and public
URLs. No prior archive was modified, no native program was rerun, and no signed
download URL is persisted.

The portable verifier checks both archives, all selected source/Git blob
identities, LF/CRLF replay inventories, provider commit linkage, and original
ZIP/report equality. It extracts no files and executes no archived source:

```sh
python evidence/ci_prerequisites_20261026/hosts_d8e1b676/verify_bundle.py
```

`archive-verification.json` records the result. Full workflow
[40438827706](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40438827706)
is separate; this host appendix does not assert its outcome or use host success
as a substitute for full source and HIA qualification.
