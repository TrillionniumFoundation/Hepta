# Four native-host receipts for source 7ef57d1b

[Host workflow 40435880354](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435880354)
completed successfully on all four hosts for
[`7ef57d1b380e73269f592fa26fe95f9636c88586`](https://github.com/TrillionniumFoundation/Hepta/commit/7ef57d1b380e73269f592fa26fe95f9636c88586).
The four original ZIPs were downloaded, matched to provider digests and
replayed successfully using exact `7ef57d1b` source exports. The provider
observation was captured at **2026-10-27 02:07:49 UTC**.

| Host | Provider job | Original artifact | Exact-source replay |
| --- | --- | --- | --- |
| Linux x86_64 | [121964313616](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435880354/job/121964313616) | [12704147378](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435880354/artifacts/12704147378) | Passed, LF |
| Linux aarch64 | [121964313404](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435880354/job/121964313404) | [12704436246](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435880354/artifacts/12704436246) | Passed, LF |
| macOS aarch64 | [121964313620](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435880354/job/121964313620) | [12704237162](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435880354/artifacts/12704237162) | Passed, LF |
| Windows x86_64 | [121964313627](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435880354/job/121964313627) | [12704147422](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435880354/artifacts/12704147422) | Passed, CRLF |

Each receipt records 181 foreign calls at `-O0` and 181 at `-O2`, successful
layout checks and rejection of a compiled wrong C echo control. These are
finite native C ABI checks through the supported Rust-backed frontend.
They do not establish all ABI shapes, physical-board or GPU qualification,
four-platform independent owned LLVM support, or complete release success.

## Actual commit binding

The original `native-host.json` documents do **not** have a `git_commit`,
`gitcommit` or `source_git_commit` field. No such field was inserted into them.
The source commit is bound by the original provider artifact's
`workflow_run.head_sha`, the corresponding workflow run, and the exact source
profile used for replay. These all identify `7ef57d1b380e73269f592fa26fe95f9636c88586`.

`provider-observation.json` preserves that public provider metadata;
`source-replay.json` explicitly records the binding and the observed absence
of a commit field in the original JSON. `hosts/` contains byte-identical
copies of the ZIP reports, including Windows CRLF bytes. The host ZIPs
contain only the reports; executable hashes are retained in the reports,
but these ZIPs did not supply native binaries.

## Reusing identical source bytes

`source-relationship.json` records a per-file check of all **183 Python files**
under `hepta/` and `tools/`, plus the native-host workflow. For every Python
file, all four byte identities agree:

1. The `8dcb0d0d` Git object.
2. The `7ef57d1b` Git object.
3. The bytes in the already sealed `hosts_8dcb0d0d` source archive.
4. A fresh `git archive 7ef57d1b380e73269f592fa26fe95f9636c88586 hepta tools` export.

The native-host workflow is likewise byte-identical. This establishes the
shared host-validation source subset, not identity of the whole repositories.
The full commits differ. The new appendix references the prior archive by
its manifest and encoded/decoded archive hashes instead of copying 183
source files again.

Each report nevertheless ran through a fresh Python process using the exact
new commit's isolated export. LF bytes were used for Linux/macOS; Windows
used `data.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')`. The replay helper
blocks native process audit events and checks source/report bytes before
and after invoking the exact validator. No native program was compiled or
executed again.

| Source profile | Actual and original-report compiler SHA-256 |
| --- | --- |
| LF | `baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7` |
| CRLF | `e7a8bc04baaf6b4ae590f5303cdb6af29d09b20547c44b4e7a1873a25131db6f` |

## Small independent ZIP archive

`host-zips.tar.gz.base64` contains only the four new provider ZIPs, totaling
25,608 uncompressed member bytes. The gzip file is **24,521 bytes**, and the
base64 file **33,127 bytes**. Decoded archive SHA-256:

`b9bdd9f65cb9cbc8458d533d7ffc4a29cfaa659894c169f21f9bd5cbccf74d43`

`MANIFEST.json` binds the four new members and the unchanged prior source
archive. `zip-identities.json` retains provider sizes, digests and public
URLs. Previous reports and archives remain unchanged. No signed download
URL is persisted.

The verifier checks both archives, every shared source/Git blob identity,
LF/CRLF replay inventories, provider commit linkage and original ZIP/report
equality. It extracts no files and executes no archived source:

```sh
python evidence/ci_prerequisites_20261026/hosts_7ef57d1b/verify_bundle.py
```

`archive-verification.json` records the result. Full workflow
[40435880235](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435880235)
is separate; this host appendix does not assert its outcome or use host
success to replace complete release qualification.
