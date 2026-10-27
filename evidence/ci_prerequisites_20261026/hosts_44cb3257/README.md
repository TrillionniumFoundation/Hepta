# Four native-host receipts for source 44cb3257

[Host workflow 40439677146](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40439677146)
completed successfully on all four hosts for
[`44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314`](https://github.com/TrillionniumFoundation/Hepta/commit/44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314).
The four newly retrieved original ZIPs match their provider SHA-256 digests.
All four reports passed a new pure-data replay using exact 44cb3257 source exports.
The provider observation was captured at **2026-10-27 02:42:21 UTC**.

| Host | Provider job | Original artifact | Exact-source replay |
| --- | --- | --- | --- |
| Linux x86_64 | [121976747581](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40439677146/job/121976747581) | [12704972909](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40439677146/artifacts/12704972909) | Passed, LF |
| Linux aarch64 | [121976747842](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40439677146/job/121976747842) | [12706185947](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40439677146/artifacts/12706185947) | Passed, LF |
| macOS aarch64 | [121976747828](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40439677146/job/121976747828) | [12705197458](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40439677146/artifacts/12705197458) | Passed, LF |
| Windows x86_64 | [121976747923](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40439677146/job/121976747923) | [12704972943](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40439677146/artifacts/12704972943) | Passed, CRLF |

Each original receipt records 181 foreign calls at `-O0` and 181 at `-O2`,
successful layout checks, and rejection of a compiled wrong C echo control.
These are finite native C ABI checks through the supported Rust-backed frontend.
They do not establish every ABI shape, physical-board or GPU qualification,
four-platform independent owned LLVM support, or complete release success.
The original native calls were performed by the provider jobs; this review ran
no native program or performance measurement.

## Commit binding and original bytes

The original `native-host.json` reports contain no `git_commit`, `gitcommit`,
or `source_git_commit` field. Their original bytes were preserved without adding
fields. Source binding comes from each provider artifact's
`workflow_run.head_sha`, the exact run ID, and the source export used for replay.
All identify `44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314`.

`provider-observation.json` retains the public run, job and artifact metadata.
`source-replay.json` records the provider commit binding, job identities, and
the observed absence of original report commit fields. `hosts/` contains the
byte-identical original JSON, including Windows CRLF. Each original ZIP contains
only `native-host.json`: native executable identities are recorded, but those
executables are not present in these four ZIPs.

## Exact shared-source relationship

`source-relationship.json` independently binds every one of the **183 Python
files** under `hepta/` and `tools/`, plus the native-host workflow, across:

1. Immutable 8dcb0d0d Git objects and their already sealed source archive.
2. Immutable d8e1b676 Git objects.
3. Immutable 44cb3257 Git objects.
4. A fresh `git archive --format=tar 44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314 hepta tools` export.

All selected bytes and Git blob identities agree. The exact 44cb source tree is
`b8cf0ef7d1a7b8a367308bbb28c4b0fcf0786157`. This establishes identity of the
selected host-validator/compiler source subset and host workflow. It does not
claim that the complete commits or other qualification paths are identical.
The new archive refers to `hosts_8dcb0d0d` by manifest and encoded/decoded archive
hashes rather than duplicating its source files. The prior archive was not modified.

Each of the four 44cb reports was replayed in a fresh Python process against
the new source export. Linux/macOS used LF files; Windows used CRLF checkout
bytes. The replay helper blocks native-process audit events and verifies the
source and report inventories before and after invoking the exact
`validate_report` implementation. This validates existing evidence; it does not
repeat the original native execution. No d8e report result substitutes for a
44cb report or its new replay.

| Source profile | Actual and original-report compiler SHA-256 |
| --- | --- |
| LF | `baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7` |
| CRLF | `e7a8bc04baaf6b4ae590f5303cdb6af29d09b20547c44b4e7a1873a25131db6f` |

## Archive and data verification

`host-zips.tar.gz.base64` preserves the four original provider ZIPs, totaling
**25,597 bytes**. Its small gzip payload is **24,373 bytes**;
the base64 file is **32,928 ASCII bytes**. Decoded archive SHA-256:

`94898851cf6be0cb4a14fb5e5b5963acd74f2e5b897c069b0908f8f651e71710`

`MANIFEST.json` binds the four ZIP members, metadata and verifier sidecars, and
the unchanged prior source archive. `zip-identities.json` records all original
provider sizes, digests and public URLs. No signed download URL is persisted.

The portable verifier checks both archives, selected source/Git blob identities,
LF/CRLF replay inventories, exact provider commit/run/tree linkage, sidecar
hashes, and original ZIP/report equality. It extracts no files to disk and
executes no archived source:

```sh
python evidence/ci_prerequisites_20261026/hosts_44cb3257/verify_bundle.py
```

`archive-verification.json` records its result. The result file is the verifier's
output and is not included in the manifest's input-sidecar hash list. Full-source
and HIA qualification are separate; this appendix makes no assertion about their
outcomes and does not substitute host success for complete release qualification.
