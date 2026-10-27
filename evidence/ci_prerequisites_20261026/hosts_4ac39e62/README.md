# Four native-host receipts for source 4ac39e62

[Host workflow 40445065374, run 21, attempt 1](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40445065374)
completed successfully on all four hosts for
[`4ac39e626acd7f78e2f66708be741e78308b4e6a`](https://github.com/TrillionniumFoundation/Hepta/commit/4ac39e626acd7f78e2f66708be741e78308b4e6a).
The exact source tree is `99a2273d45a333a1a9cc87110742399e7413d512`, also the
tree of local reviewed commit `8c88308eb9b6a8acf612ae9e8f7d9a7d89f5a776`.
The provider records the run as completed at its final update,
**2026-10-27 03:36:43 UTC**. The capture timestamp is retained in
`provider-observation.json`.

| Host | Provider job | Original artifact | Exact-source replay |
| --- | --- | --- | --- |
| Linux x86_64 | [121994261134](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40445065374/job/121994261134) | [12707981204](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40445065374/artifacts/12707981204) | Passed, LF |
| Linux aarch64 | [121994261088](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40445065374/job/121994261088) | [12707772859](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40445065374/artifacts/12707772859) | Passed, LF |
| macOS aarch64 | [121994260804](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40445065374/job/121994260804) | [12708355394](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40445065374/artifacts/12708355394) | Passed, LF |
| Windows x86_64 | [121994260948](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40445065374/job/121994260948) | [12707109574](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40445065374/artifacts/12707109574) | Passed, CRLF |

Each original report records **181 foreign calls at `-O0` and 181 at `-O2`**,
successful layout checks, and rejection of an actually compiled wrong C echo
implementation. That is eight positive executions and 1,448 reported foreign
calls across the four hosts, plus four separately compiled negative controls.
The negative return code is `-6` on both Linux hosts and macOS, and `3221226505`
on Windows; every original negative stderr identifies the expected
`v_scalar0_0` assertion. These are finite native C ABI checks through the
supported Rust-backed frontend. They do not establish every ABI shape,
foreign lifetime safety, physical-board or GPU qualification, four-platform
independent owned LLVM support, or complete release success.

## Original provider evidence and its limits

All four original ZIPs match their provider byte lengths and SHA-256 digests.
Their total size is **25,597 bytes**. Every ZIP contains exactly one file,
`native-host.json`. `hosts/` retains those four reports byte for byte, totaling
**310,596 bytes**. The Windows original has **2,815 CRLF pairs**; it was not
normalized or rewritten.

The reports contain no `git_commit`, `gitcommit`, or `source_git_commit` field.
They remain unchanged. Their source binding comes from the provider run,
job, and artifact `head_sha` records, the exact-head checkout and verification
steps in the complete job logs, and the independent exact-source replay.
Every one identifies the new `4ac39e62` commit; no earlier report stands in
for a report from this run.

`provider-originals/` preserves the metadata responses available through the
connector, including the complete run and jobs JSON response strings.
`provider-observation.json` collects the same run, jobs and artifact metadata
with the observation timestamp. `provider-logs/` preserves all four complete
**decoded** provider job logs as UTF-8, totaling **74,566 bytes**. These are the
connector's decoded logs, not a claim to have captured the provider's original
HTTP log encoding. No signed download URL is persisted.

The JSON reports retain hashes and paths for the generated native object,
positive executables, compiled wrong executable, and tools. **Their binary
bytes are absent from these four provider ZIPs.** The archive therefore
contains zero native binary members. Hashes of absent executables are identity
records, not independently rehashed retained executable bytes. This review did
not rerun any compiler, native executable, emulator, or performance task.

## Exact source and LF/CRLF replay

This appendix seals its own complete selected source set: **183 Python files
under `hepta/` and `tools/`, plus the native-host workflow**, totaling
**3,240,325 original LF bytes**. It does not depend on a prior evidence archive.
`capture_sources.py` read immutable Git objects and wrote separate LF and CRLF
exports. The CRLF profile replaces each LF with CRLF; it does not change the
original report.

`source-proof.json` contains the raw commit objects for the published candidate,
the local reviewed commit, and previous candidate `44cb3257`, together with
the **10 distinct Git tree objects** needed to traverse the selected source
paths. The portable verifier recomputes every commit/tree/blob identity and
checks that all selected Python files are included. It verifies that the new
remote and local commits have exactly the same root tree. It does not claim
that this selected source archive contains the whole repository.

Unlike the earlier `hosts_44cb3257` appendix, this appendix does **not** claim
that all 183 Python files equal the prior candidate. Exact Git traversal finds
two changed selected files:

- `tools/qualify_cpp_composed_llvm.py`
- `tools/qualify_cpp_owned_llvm.py`

The other 181 Python files and the host workflow have the same Git blob
identities as `44cb3257`. Changes outside this selected source set are not
enumerated by that comparison. `source-relationship.json` records every
selected path, mode, current and prior blob identity, LF hash, and CRLF hash.

Each of the four newly received reports was replayed in a fresh Python process
using `replay_host_report.py` and its preselected source profile. An audit hook
forbids native process creation and network access. The exact candidate's
`validate_report` implementation regenerated the source matrix and checked the
frontend, header, object identity, host targets, command arguments, layout
results and compiled negative-control observation. All four replays passed,
with zero blocked audit events and unchanged source/report inventories before
and after validation. `replay-results/` preserves each full replay output and
empty stderr; `source-replay.json` links the results to the exact provider jobs
and original report hashes.

| Source profile | Recomputed and original-report compiler SHA-256 |
| --- | --- |
| LF | `baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7` |
| CRLF | `e7a8bc04baaf6b4ae590f5303cdb6af29d09b20547c44b4e7a1873a25131db6f` |

These compiler hashes are unchanged because the compiler hash covers top-level
`hepta/*.py`; the changed files above are in `tools/`. The portable verifier
also recomputes both hashes directly from the sealed compiler bytes rather
than trusting the replay's stated values.

## Archive and offline verification

`host-records.tar.gz.base64` contains **188 members**: the 184 selected source
files and the four complete provider ZIPs. The source and ZIP archive was
compressed once with gzip level 6:

- Uncompressed tar: **3,420,160 bytes**.
- Gzip bytes: **831,364 bytes**.
- Base64 file: **1,123,074 ASCII bytes**, below the 3,500,000-byte part limit.
- Gzip SHA-256: `fc0008d9b2b88d9b00acd296693d2c5c02f6021f3b5c7fe9625f56f1ff2fa9a2`.

`MANIFEST.json` binds the encoded and decoded archive, all member bytes, all
original reports and provider records, source proof, replay outputs, helper
scripts and review sidecars. `seal_bundle.py` preserves the one-time archive
when refreshing sidecar hashes. `archive-verification.json` is the verifier's
output, intentionally excluded from the manifest's input-sidecar hash list.

The portable verifier requires only the Python standard library. It performs
bounded in-memory decompression, validates safe member paths and exact
inventories, recomputes Git source proofs and LF/CRLF compiler hashes, checks
provider head/job/artifact bindings and complete job logs, verifies exact
ZIP/report equality, and checks the recorded replay and native observations.
It extracts no files, imports no archived source, starts no process, accesses
no network, and does not repeat the original native execution:

```sh
PYTHONDONTWRITEBYTECODE=1 python evidence/ci_prerequisites_20261026/hosts_4ac39e62/verify_bundle.py
```

The exact-source replay is a separate recorded validation operation; the
portable verifier checks its inputs and result records, not a new execution
of the archived validator. This evidence preserves and cross-checks the
retrieved provider observations. It is not an authentication scheme against
an arbitrary author replacing the entire evidence set.

`independent-review.json` records a second reviewer's read-only examination of
all four ZIPs, reports, provider records and logs, the commit/tree/blob source
proof, both compiler hashes, all replay outputs and the portable verifier's
bindings. That reviewer independently compared 368 immutable Git blob reads
and 366 LF/CRLF Python export byte sequences. The reviewer found no blocking
issue and executed no compiler, native program, replay or performance task.

The new complete source/HIA workflow is a separate qualification. This host
appendix does not assert its outcome, replace its gates, or claim that all
seven project stages or blockers have closed.
