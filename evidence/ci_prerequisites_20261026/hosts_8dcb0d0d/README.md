# Four native-host receipts for source 8dcb0d0d

All four jobs in [host workflow 40435070768](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435070768)
completed successfully for source
[`8dcb0d0d8aabfa6bd260305c57344ce15ef72eca`](https://github.com/TrillionniumFoundation/Hepta/commit/8dcb0d0d8aabfa6bd260305c57344ce15ef72eca).
All four downloaded original reports passed that exact source version's
strict report validator in isolated LF/Windows CRLF source exports.

| Host | Provider job | Original ZIP artifact | Replay |
| --- | --- | --- | --- |
| Linux x86_64 | [121961687314](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435070768/job/121961687314) | [12703303903](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435070768/artifacts/12703303903) | Passed, LF |
| Linux aarch64 | [121961687471](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435070768/job/121961687471) | [12703881004](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435070768/artifacts/12703881004) | Passed, LF |
| macOS aarch64 | [121961687132](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435070768/job/121961687132) | [12704205769](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435070768/artifacts/12704205769) | Passed, LF |
| Windows x86_64 | [121961687459](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435070768/job/121961687459) | [12703383407](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435070768/artifacts/12703383407) | Passed, CRLF |

Each original report records **181 foreign calls at `-O0` and 181 at `-O2`**,
passing layout checks, and a compiled wrong C echo control rejected with
actual nonzero exit: `-6` for Linux/macOS and `3221226505` for Windows.
These are finite C ABI checks through the supported Rust-backed frontend.
They do not qualify every ABI shape, physical boards, GPUs, the independent
owned LLVM backend on all four hosts, or the complete release requirements.

## Exact source and replay

The source was obtained from `git archive 8dcb0d0d8aabfa6bd260305c57344ce15ef72eca
hepta tools`. All **183 Python files** are inventoried for both newline
profiles. The CRLF profile uses the explicit byte transformation
`data.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')`.

| Profile | Actual and reported compiler SHA-256 |
| --- | --- |
| LF | `baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7` |
| Windows CRLF | `e7a8bc04baaf6b4ae590f5303cdb6af29d09b20547c44b4e7a1873a25131db6f` |

These compiler hashes equal the earlier `3a424e42` values. The complete
replayed tool/source inventory is nevertheless the actual `8dcb0d0d` version;
an unchanged compiler hash is not treated as an identity for all repository
files or CI configuration.

`replay_host_report.py` ran the exact export's
`tools.validate_native_host.validate_report` in a fresh Python process for
each receipt. Its audit hook rejects `subprocess.Popen`, `os.system`,
`os.posix_spawn` and `os.exec`; source/report bytes are checked before and
after validation. `source-replay.json` records all four actual return codes,
stderr, complete source inventories, input hashes and outcomes. This was
data validation of prior execution receipts, with no native compilation,
execution or benchmark repetition. It is not a hostile-Python sandbox claim.

## Archive contents

`host-records.tar.gz.base64` retains **188 members, 3,265,709 uncompressed bytes**:
four original provider ZIPs, 183 exact LF Python files, and the exact native
host workflow. Windows source bytes are reproducible by the disclosed
transformation and checked against the retained CRLF inventory. Each ZIP was
checked against its provider SHA-256 before replay.

The gzip archive is **1,032,650 bytes**, SHA-256
`0f64b1118b6f303ccc67c839bf8c93cca09d1965cd63472fea3277013c3f96e0`;
the base64 file is **1,394,985 bytes**. `MANIFEST.json` binds each member's
size, hash and origin. `zip-identities.json` records public provider URLs,
sizes and digests. `provider-observation.json` preserves original artifact
and job metadata.

Original report bytes are also readable under `hosts/`. Each provider ZIP
contains only `native-host.json`: native executable hashes and commands are
retained in the report, but the actual native binaries were not supplied by
these ZIPs. Original Windows CRLF report bytes are unchanged. No signed
download URL is retained.

Verify all archive bytes, member identities, original ZIP/report equality,
LF/CRLF source inventories and recorded compiler identity linkage without
extracting or executing archived source:

```sh
python evidence/ci_prerequisites_20261026/hosts_8dcb0d0d/verify_bundle.py
```

`archive-verification.json` records this check. Exact-source report replay
can also be repeated with `replay_host_report.py`, an isolated corresponding
source export and an original report path.

## Separate full-CI observation

The metadata snapshot at **2026-10-27 02:01:20 UTC** shows full workflow
[40435070810](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435070810),
job [121961684415](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435070810/job/121961684415),
still `in_progress`: verification bootstrap had failed, the complete source
qualification step was skipped, and the HIA step was running. This archive
does not include that full job's log or infer its exception or final result.
Host workflow success does not override those independent full-CI outcomes.
