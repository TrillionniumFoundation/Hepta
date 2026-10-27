# Failed full-CI appendix: source 19299c82

[Workflow 40432186614](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40432186614),
[job 121952281854](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40432186614/job/121952281854),
completed with failure on source
`19299c82aa2e326ee323030715c54468da3c73eb`. The new records establish that the
namespace startup and selected Rust identity prerequisites succeeded. The
next bootstrap failed downloading QEMU with HTTP 503; the full release suite
was skipped, and the separately attempted HIA command was rejected for its
missing required `--lean` argument.

This is an additive evidence directory. The previously sealed parent archive
has not been modified. No native program, compiler or benchmark was run to
produce this appendix.

## What this run actually did

Provider step conclusions are preserved in [provider-observation.json](provider-observation.json).
The complete decoded job log is retained as
[job-121952281854.log](job-121952281854.log), including timestamps and terminal
control characters: 1,302 lines, 118,452 UTF-8 bytes, SHA-256
`cbb7887811c44c8fb868a99b7fe51dec7e82af63f8709816371e4b71f5333d90`.
This is the provider-returned decoded text encoded without newline translation;
the original HTTP response byte representation is not separately claimed.

| Step | Provider conclusion | Direct evidence and interpretation |
| --- | --- | --- |
| Distribution Bubblewrap profile | Success | `sandbox-startup.json`: `available: true`, `probe_returncode: 0`. The exact workflow loads the shipped profile and checks that the host user-namespace restriction value is unchanged. |
| Explicit LLVM 20 installation | Success | Job log identifies Ubuntu clang 20.1.8. |
| Pinned Rust bootstrap | Success | Rust 1.90.0 and cross standard-library install records are in the complete log. |
| Selected Rust identity | Success | `selected-rustc.json` identifies the actual `rustc 1.90.0`, its verified compiler-prefix sysroot, and executable SHA-256 `e6abf55ab1859e7c990be77fd593f51661ea99fb2fde626ae9f4108aaa34e7fa`. |
| Lean/QEMU bootstrap | Failure | Traceback reaches `install_qemu`, `urllib.request.urlopen(metadata["source"], timeout=60)`, then `HTTP Error 503: Service Unavailable`; step exit code 1. |
| Complete native/experiment qualification | Skipped | The provider marks this step skipped; the artifact contains no `artifacts/candidate/` files. |
| Standalone HIA qualification | Failure | The `if: !cancelled()` step runs despite the earlier failure, exports `LEAN`, but omits the CLI's required `--lean` argument. Argument parsing exits 2; the artifact contains no `artifacts/hia-unified/` files. |
| Preserve raw evidence | Success | The uploaded artifact identity is also printed in the job log. |

The HIA error is a workflow command-line defect. Exporting the environment
variable does not satisfy this version's required argparse option. The exact
workflow, bootstrap, HIA CLI and QEMU lock source files are retained under
`source/`, with Git blob and SHA-256 identities in
[source-identities.json](source-identities.json).

The QEMU request URL is established from that exact lock and the failing
`metadata["source"]` call, rather than printed by the traceback:
[Ubuntu snapshot QEMU package](https://snapshot.ubuntu.com/ubuntu/20260828T000000Z/pool/universe/q/qemu/qemu-user-static_8.2.2+ds-0ubuntu1.18_amd64.deb).
The observed HTTP 503 does not establish a permanent outage or a checksum
failure. No QEMU checksum failure was reported.

The startup receipt qualifies only startup. It does not replace the skipped
complete isolation/native suite. The missing HIA argument prevented this
invocation from entering its qualifier; it is not a set of failed HIA program
execution results. [diagnosis.json](diagnosis.json) preserves exact log anchors,
all provider steps, the four new receipts and these limits.

## Exact artifact selection

[Artifact 12702707920](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40432186614/artifacts/12702707920)
is 25,322,286 bytes. Its downloaded SHA-256 matched the provider digest and the
artifact-upload log:

`a0d7ff48aaed5a152d6b9e8c6bcca1a78e22dfeb7136d9c776556eda0f782280`

Every ZIP member is listed in [zip-inventory.json](zip-inventory.json). Each
`artifacts/` member was compared by Git blob identity against
`git ls-tree -r 19299c82aa2e326ee323030715c54468da3c73eb artifacts`:

| Category | Members | Uncompressed bytes | Retention |
| --- | ---: | ---: | --- |
| Added by this run | 4 | 1,012 | Complete original bytes under `artifacts/` |
| Changed tracked artifacts | 0 | 0 | None |
| Byte-identical tracked artifacts | 89 | 4,277,480 | Inventory and original Git blob identities; no duplicate file copy |
| Historical `evidence/` content | 1,698 | 93,567,930 | Inventory and original whole-ZIP identity; no duplicate file copy |

The four new originals are `bwrap-profile.sha256`, `sandbox-startup.json`,
`selected-rustc.json` and `workflow-source.json`. The last records matching
expected/checked-out source heads and a separate event SHA. The historical
files were not counted as new qualification results. The whole original ZIP
was retained in the recovery directory during this audit; this committed
appendix preserves the selected new bytes, not another copy of that entire
25 MB ZIP.

## Current candidate observation

At **2026-10-27 01:44:58 UTC**, the separately observed current-source job
[121956048659](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40433338725/job/121956048659)
was `in_progress`; its snapshot is included in the provider observation. This
task did not wait for completion.

An exact-source comparison shows candidate `3a424e427b378400802c9e3c2fef558c0a352756`
has identical qualification workflow bytes, including the HIA invocation
without `--lean`. That is a source observation. This appendix does not infer
the current job's final result from an older job or from that comparison.

## Verify the appendix

`MANIFEST.json` binds retained files, provider identity and the unchanged
parent archive. The verifier checks bytes and recorded relationships without
importing archived source or running native commands:

```sh
python evidence/ci_prerequisites_20261026/failed_full_19299c82/verify_appendix.py
```

To additionally verify all ZIP inventory entries and original selected member
bytes against a separately downloaded original ZIP:

```sh
python evidence/ci_prerequisites_20261026/failed_full_19299c82/verify_appendix.py \
  --original-zip /tmp/hepta-ci-recovered-20261026/12702707920.zip
```

`verification.json` records both checks. All persisted download identities use
public provider URLs; no temporary signed download URL is retained.
