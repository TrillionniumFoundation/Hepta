# Failed full-CI appendix: source 3a424e42

[Workflow 40433338725](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40433338725),
[job 121956048659](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40433338725/job/121956048659),
completed with failure on source `3a424e427b378400802c9e3c2fef558c0a352756`.
The original traceback confirms **HTTP 503 during the pinned QEMU package
request**, followed by a skipped full release step and a separate HIA
command-line failure. This conclusion comes from this run's own log.

## Observed failure and successful prerequisites

The complete [job log](job-121956048659.log) contains 1,302 lines and
118,463 UTF-8 bytes. SHA-256:
`0b316ecc423dd94f64b199bfc8d2c8c51cc63d5d7ff21a53a3445b8c1a5e603d`.
It preserves the provider-decoded text without newline translation; original
HTTP transport bytes are not separately claimed.

| Step | Actual outcome |
| --- | --- |
| Distribution Bubblewrap profile/startup | Success; original startup receipt has `available: true`, return code 0 |
| LLVM 20 installation | Success; original log identifies Ubuntu clang 20.1.8 |
| Rust bootstrap and selected compiler identity | Both success; retained actual `rustc 1.90.0` identity and verified sysroot |
| Lean/QEMU bootstrap | At 01:52:04 UTC, `install_qemu` calls `urlopen(metadata["source"], timeout=60)` and raises `urllib.error.HTTPError: HTTP Error 503: Service Unavailable`; exit code 1 |
| Complete native/experiment qualification | Provider marks the step skipped; no `artifacts/candidate/` files exist in this ZIP |
| Standalone HIA qualification | The `!cancelled()` step runs, but argparse rejects missing required `--lean`; exit code 2; no `artifacts/hia-unified/` files exist |
| Raw evidence upload | Success; the complete job log records the uploaded artifact digest |

[diagnosis.json](diagnosis.json) preserves the exact diagnostic line anchors,
all provider step conclusions and the four new receipts.
[provider-observation.json](provider-observation.json) records the public
provider response captured at 2026-10-27 02:01:20 UTC.

The exact source files in `source/` identify the requested package as
[this Ubuntu snapshot URL](https://snapshot.ubuntu.com/ubuntu/20260828T000000Z/pool/universe/q/qemu/qemu-user-static_8.2.2+ds-0ubuntu1.18_amd64.deb).
The traceback prints the failing `metadata["source"]` call, and the matching
source lock establishes that URL. It is not a Lean-download exception or a
checksum mismatch. These records do not establish the service/network root
cause of HTTP 503, or prove the endpoint is permanently unavailable.

All four relevant source files are byte-identical to those in the earlier
`19299c82` failure: workflow, bootstrap, HIA CLI and QEMU lock. The two runs
independently observed the same HTTP error at the same package request.
[source-identities.json](source-identities.json) records that comparison and
exact Git/SHA-256 identities. No request to the package endpoint was made as
part of this archival task.

The successful startup receipt establishes startup only. The skipped full
suite supplies no complete isolation/native qualification. The HIA argument
failure occurs before entering the qualifier and must not be represented as
failed HIA program executions.

## Retained artifact bytes

[Artifact 12703840975](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40433338725/artifacts/12703840975)
is **29,696,799 bytes**. The downloaded SHA-256 matches both provider metadata
and the job's artifact-upload log:

`3aff13233b62cee98ac2014fa3ee785b53015f848a73f8763fb882c780a10df8`

All 2,081 file members are inventoried. Each `artifacts/` member was compared
by Git blob identity against the exact `3a424e42` source tree:

| Category | Files | Uncompressed bytes | Retention |
| --- | ---: | ---: | --- |
| New artifacts | 4 | 1,012 | Original bytes under `artifacts/` |
| Changed tracked artifacts | 0 | 0 | None |
| Unchanged tracked artifacts | 89 | 4,277,480 | Inventory/Git identities; no duplicate copy |
| Historical evidence | 1,988 | 103,115,692 | Inventory and whole-ZIP identity; no duplicate copy |

The new files are `bwrap-profile.sha256`, `sandbox-startup.json`,
`selected-rustc.json` and `workflow-source.json`. The last records matching
expected and checked-out source heads and the distinct workflow event SHA.
Historical files were not counted as fresh qualification results. This
appendix preserves the selected bytes rather than another entire ZIP copy.

## Verification and scope

Run the read-only byte verifier, optionally with the downloaded original ZIP:

```sh
python evidence/ci_prerequisites_20261026/failed_full_3a424e42/verify_appendix.py
python evidence/ci_prerequisites_20261026/failed_full_3a424e42/verify_appendix.py \
  --original-zip /tmp/hepta-ci-recovered-20261026/12703840975.zip
```

`verification.json` records both checks. The verifier also checks the unchanged
parent archive. Previous appendices are preserved. No native compilation,
program execution or timing measurement was repeated, and no signed download
URL is retained. The later `8dcb0d0d` host receipts are a separate sibling
archive and do not change this failed run's outcome.
