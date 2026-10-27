# CI prerequisite recovery and exact-source host receipt replay

This archive retains the four successful native-host receipts for candidate
`3a424e427b378400802c9e3c2fef558c0a352756`, the four successful receipts for the
earlier CI-fix source `19299c82aa2e326ee323030715c54468da3c73eb`, and the original
failed full-CI artifacts for `a04ae789b2348504089e2c3484178998a6f332ba`.
All eight host receipts passed their own source version's strict validator in
isolated Python source exports. This audit replayed data validation; it did not
compile or execute native programs again.

The current-host provider snapshot was taken at **2026-10-27 01:36:22 UTC**.
The directory date follows the ongoing 2026-10-26 review session. Reports and
provider timestamps are retained unchanged.

## Current candidate: four native hosts

Source: [3a424e427b378400802c9e3c2fef558c0a352756](https://github.com/TrillionniumFoundation/Hepta/commit/3a424e427b378400802c9e3c2fef558c0a352756).
All four jobs in [host workflow 40433338784](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40433338784)
were complete and successful in the captured provider observation.

| Host | Job | Original artifact | Exact-source replay |
| --- | --- | --- | --- |
| Linux x86_64 | [121956047569](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40433338784/job/121956047569) | [12702133878](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40433338784/artifacts/12702133878) | Passed, LF |
| Linux aarch64 | [121956047350](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40433338784/job/121956047350) | [12702133875](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40433338784/artifacts/12702133875) | Passed, LF |
| macOS aarch64 | [121956047645](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40433338784/job/121956047645) | [12703445072](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40433338784/artifacts/12703445072) | Passed, LF |
| Windows x86_64 | [121956047793](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40433338784/job/121956047793) | [12702837870](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40433338784/artifacts/12702837870) | Passed, CRLF |

Each original receipt records **181 foreign calls at `-O0` and 181 at `-O2`**,
successful layout checks, and rejection of a compiled wrong C echo control.
The wrong control's actual return code is `-6` on Linux/macOS and `3221226505`
on Windows. These are finite native C ABI checks through the supported
Rust-backed frontend path. They do not qualify the independent owned LLVM
backend on all four hosts, physical boards, GPUs, every C/C++ ABI shape, or the
whole project's production requirements.

The eight original host ZIPs contain `native-host.json` only. Those receipts
retain command traces and native binary hashes; **the host ZIPs do not contain
the native binaries themselves**. `hosts/` contains byte-identical JSON copies.

## Earlier CI-fix source: four distinct receipts

Source: [19299c82aa2e326ee323030715c54468da3c73eb](https://github.com/TrillionniumFoundation/Hepta/commit/19299c82aa2e326ee323030715c54468da3c73eb).
All four jobs in [host workflow 40432186709](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40432186709)
were complete and successful. Their same finite call/layout/control coverage
is recorded independently of the current candidate.

| Host | Original artifact | Exact-source replay |
| --- | --- | --- |
| Linux x86_64 | [12702062330](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40432186709/artifacts/12702062330) | Passed, LF |
| Linux aarch64 | [12702267258](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40432186709/artifacts/12702267258) | Passed, LF |
| macOS aarch64 | [12701804519](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40432186709/artifacts/12701804519) | Passed, LF |
| Windows x86_64 | [12702552998](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40432186709/artifacts/12702552998) | Passed, CRLF |

## Source identity and replay method

The replay used `git archive <exact-commit> hepta tools` and retained all Python
files from each export. LF bytes are archived in `source/<commit-prefix>/`.
Windows profiles were reconstructed using the explicit byte transformation
`data.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')`; each transformed file's
digest is retained too. No receipt or compiler hash was changed to fit another
source version.

| Exact source | Checkout bytes | Actual and reported compiler SHA-256 |
| --- | --- | --- |
| `19299c82aa2e326ee323030715c54468da3c73eb` | LF | `b826d3a0c8336fdcde3c589795c4c8409dc137a082e4a1e7d0933fa31626e81f` |
| `19299c82aa2e326ee323030715c54468da3c73eb` | CRLF | `ed06ab0cbe5aa76e21bc0d1d13e1d37aacb22aaf8f98acc0759ff3dc20551471` |
| `3a424e427b378400802c9e3c2fef558c0a352756` | LF | `baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7` |
| `3a424e427b378400802c9e3c2fef558c0a352756` | CRLF | `e7a8bc04baaf6b4ae590f5303cdb6af29d09b20547c44b4e7a1873a25131db6f` |

The exact Git trees, validator and imported Python file hashes, input hashes,
return codes, stderr and replay outcomes are in `source-replay.json`.
`replay_host_report.py` imports the specified export's
`tools.validate_native_host.validate_report`, checks source and receipt bytes
before/after validation, and blocks Python audit events for `subprocess.Popen`,
`os.system`, `os.posix_spawn` and `os.exec`. Each receipt used a fresh Python
process. This prevents the validator's native process paths from being used
during this recorded replay; it is not a claim of hostile-Python sandboxing.

To repeat a receipt validation after reconstructing an isolated source export:

```sh
python evidence/ci_prerequisites_20261026/replay_host_report.py \
  /path/to/exact/source-export \
  evidence/ci_prerequisites_20261026/hosts/3a424e42/12702133878.json
```

Use the corresponding CRLF export for Windows. The included eight replay
results are successful validations of prior host execution receipts, and are
not eight new host executions.

## Old failed full CI: original failures preserved

[Full workflow 40219053582](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40219053582)
failed on source `a04ae789b2348504089e2c3484178998a6f332ba`.
[Artifact 12618342700](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40219053582/artifacts/12618342700)
was downloaded and its original ZIP SHA-256 matched the provider digest:
`7c33580eff0b0aeb8ac5f09ec46a4b9f2b7ca677e11e25ec46185fb0ef38ba65`.

The actual run is `artifacts/candidate/release-validation.json`, started at
23:34 UTC on 2026-10-25. The ZIP also contains an older
`artifacts/release-validation.json`; that older result was not counted as the
current run. `artifacts/workflow-source.json` records the expected and checked
out source commit; its event SHA is a different workflow event identity.

Recomputed from the actual candidate report and raw logs:

| Observation | Original result |
| --- | --- |
| Planned/completed gates | 46 / 46 |
| Passed/failed gates | 2 / 44 |
| Passing gates | `formal_core`, `provenance_and_type_core` |
| Unit terminal result | 1,292 tests; 192 failures; 112 errors; 0 skips; 139.115 seconds |
| Toolchain identity diagnostics in unit log | 232 occurrences of `E_TOOLCHAIN_IDENTITY` |
| Reported executable identity | `rustup 1.29.1`, where pinned `rustc 1.90.0` was required |
| Namespace prerequisite | `environment_blocked`; startup failed, other nine checks `not_run` |
| Scalar and owned LLVM performance | Both `blocked` at `build`; both `raw_samples: []` |

The namespace startup error is preserved verbatim:
`bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted` (return code 1).
This establishes the startup failure. It does not by itself prove AppArmor
was its cause. The observed Rust manager identity establishes a prerequisite
identity failure, and the selected Rust path reaching the manager is the
diagnostic inference. No timing comparison can be drawn from empty samples.

The failed run's source snapshot was unchanged. Its compiler hash was
`0bc527cfc5aec67c6bf9b41929dec267abe5eda0704aa12bc63256817374b6b9`.
`old-full-diagnosis.json` keeps the complete gate names and bounded conclusions.
Three primary JSON originals are also provided uncompressed in
`old-full-original/`; the raw logs and remaining originals are in the bundle.

## Retention and integrity

`ci-records.tar.xz.base64` encodes **543 files, 13,221,124 uncompressed bytes**:

- All 177 `artifacts/` members of the old failed full-CI ZIP, byte-for-byte.
- All eight original host ZIP files, each checked against its provider digest.
- The 175 Python source files for `19299c82` and 183 for `3a424e42` used to
  construct the exact-source replay exports.

The old ZIP's 1,511 historical `evidence/` members (67,659,075 bytes) are
intentionally excluded to avoid copying previous evidence into this new
archive. Their count and the original whole-ZIP identity are retained.
All 177 retained `artifacts/` members remain unmodified; only 80 are under
`artifacts/candidate/`, so preservation does not imply that every retained
artifact was produced by the old candidate run.

The decoded archive is **1,103,480 bytes**, SHA-256
`8dd1dc3c8325d9b393f88d6fdaebd3232ddfeb1ce27e5cbb42d6a710d2a006ed`.
The base64 file is 1,490,668 bytes. `MANIFEST.json` identifies every retained
member, byte size, digest and origin; `zip-identities.json` binds all nine
downloaded ZIPs to public provider URLs and hashes. Provider observations
are in `github-observation.json` and `current-host-observation.json`.
No signed download URL is persisted. Directory-scoped Git attributes preserve
JSON and base64 bytes across checkouts, including original Windows CRLF reports.

Run the following to check archive/member hashes, original host ZIP/report
identity, LF/CRLF source inventories, recorded compiler-hash linkage, original
failed-run copies and recomputed gate/unit counts. It extracts no files,
imports no archived source and executes no native program:

```sh
python evidence/ci_prerequisites_20261026/verify_bundle.py
```

`archive-verification.json` records that check. Neither this evidence-only
archive nor four-host success certifies the current candidate's complete
release gates. Full workflow [40433338725](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40433338725)
is a separate candidate qualification, outside this captured host/prerequisite
archive. The root worktree, candidate HEAD and production source were not
modified by this archive task.
