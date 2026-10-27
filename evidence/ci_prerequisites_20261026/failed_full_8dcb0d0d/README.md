# Original full-CI failure at 8dcb0d0d

This appendix preserves the failed GitHub Actions run for source
`8dcb0d0d8aabfa6bd260305c57344ce15ef72eca`. It does not describe the later
`7ef57d1b` run. The provider job finished with **failure**: verification bootstrap
exhausted its QEMU download attempts, full source qualification was skipped, and
the independently continued HIA qualification completed **15 gates, 12 passed**.

## Provider and original identity

| Item | Identity |
| --- | --- |
| Run | [40435070810](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435070810) |
| Job | [121961684415](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435070810/job/121961684415) |
| Artifact | [12704417329](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40435070810/artifacts/12704417329) |
| Provider observation | 2026-10-27 02:15:46 UTC |
| Provider ZIP | 32,688,285 bytes |
| ZIP SHA-256 | `1d2085b27276f913cd519d48153446956ad274f3df020ddb0695cd2e84023cf2` |
| Complete decoded job log | 125,154 UTF-8 bytes, 1,363 lines |
| Job-log SHA-256 | `7c801717fdc9901a6234bb8986d9126f2d81911b02e136d60ccfdc980b2e7fca` |

The public provider metadata is preserved in `provider-observation.json`; the
downloaded ZIP digest equals the provider's SHA-256. `job-121961684415.log` is the
complete text returned by the provider log API, encoded as UTF-8 without newline
translation. This does not claim preservation of the original HTTP transport
bytes. Temporary signed download URLs are not retained.

## Failure sequence, from original logs

Distribution Bubblewrap profile startup, LLVM 20 installation, locked Rust
bootstrap, and selected Rust identity verification all passed (steps 7–10).
Step 11's Lean/QEMU bootstrap reached a Lean download attempt and then four QEMU
attempts. Log lines 1195–1202 contain these exact QEMU events:

| Attempt | HTTP status | Next delay | Exhausted |
| --- | ---: | ---: | --- |
| 1 | 500 | 1 second | false |
| 2 | 503 | 2 seconds | false |
| 3 | 503 | 4 seconds | false |
| 4 | 503 | none | true |

There were **four attempts and three retries**, not four retries. The final
traceback contains `urllib.error.HTTPError: HTTP Error 503: Service Unavailable`
and `_TransientDownload` in `_retry_download`/`install_qemu`; bootstrap exited 1.
The exact source lock used this URL:

<https://snapshot.ubuntu.com/ubuntu/20260828T000000Z/pool/universe/q/qemu/qemu-user-static_8.2.2+ds-0ubuntu1.18_amd64.deb>

Step 12 (full source qualification) was **skipped**. Step 13 used its continuation
condition and actually ran HIA to its terminal report, then exited 1. Artifact
upload succeeded. These observations identify the failed prerequisite and its
downstream effects; they do not establish the remote service's root cause.

## HIA terminal result

The original `qualification.json` started at `01:54:49Z` and finished at
`02:06:41Z` on 2026-10-27, with `status=scoped_gates_not_all_qualified`,
`completed_gates=15`, `passed_gates=12`, `ok=false`, and `unchanged_source=true`.
The three failed gates were:

| Gate | Exact retained result | Interpretation |
| --- | --- | --- |
| `unit_regression` | 2,102 tests; 0 failures; 0 errors; 3 skipped; process exit 0 | The zero-skip acceptance rule failed. The `-q` terminal log does not name the skipped tests. |
| `composite_bulk_targets` | `ToolIdentityRejected`; underlying `FileNotFoundError` for `/home/runner/work/Hepta/toolchains/qemu-8.2.2/qemu-aarch64-static`; zero process records | Tool verification stopped before native work. |
| `standalone_aarch64_qemu` | `E_HIA_PROGRAM_AARCH64: QEMU AArch64 unavailable` | 17 reference cases were retained; these are not QEMU native executions. |

The unittest terminal says `Ran 2102 tests in 559.735s` and `OK (skipped=3)`.
Its enclosing gate took 561.1850213969999 seconds. The brief diagnostic messages
before that terminal summary are retained unchanged; they must not be counted
as additional unittest failures. No skip names are inferred from source guesses.

The other 12 gates passed: `standalone_native`, `standalone_resources`,
`composite_resources`, `source_migration`, `cpp_template_migration`,
`c_configuration_matrix`, `cpp_configuration_matrix`, `selected_core_formal`,
`legacy_executable_core`, `legacy_hosted_composition`, `legacy_cortex_m4_qemu`,
and `standalone_performance`. The aggregate's 44 linked report/log identities
and 30 log byte counts were checked against the original archive members.

## Performance really reached its terminal state

`performance.json` reports `phase=complete`, `status=passed`, `ok=true`;
both measurement-quality and performance-threshold failure arrays are empty.
The enclosing gate exited 0 after 111.24347590599996 seconds. Its progress log
contains all 63 progress records, ending at 63/63. This is a completed finite
measurement, even though the containing CI job failed.

All **63 raw samples** are retained: seven paired groups, three kernels, and
three implementations (direct HIA LLVM, same-source checked Rust, and independent
handwritten safe Rust). Smaller LLVM/baseline time ratios are faster:

| Kernel | LLVM / checked Rust | LLVM / handwritten Rust |
| --- | ---: | ---: |
| `full_lifecycle` | 1.0003335470312145 | 1.001084433287505 |
| `constructor_error` | 0.8617370178412184 | 0.8470445603859528 |
| `two_stage` | 0.998613596298739 | 0.9967427935651708 |
| Geometric mean of paired medians | 0.9512741292729662 | 0.9454821994398747 |

Each kernel entry is the median of seven paired LLVM/baseline ratios. Fixed
limits were 1.2 per kernel, 1.1 for the geometric mean, and 0.05 for relative MAD.
The maximum observed relative MAD was **0.00510593275525877**. No samples were
excluded and acceptance thresholds were not adjusted. Lifecycle and two-stage
timings are near parity; the constructor-error case contributes most of the
geometric-mean difference. These are finite Linux x86-64 shared-host results,
not a prior-commit regression comparison or proof of universal superiority.

The originals also retain **588 correctness observations** and **71 complete
process records**. All 63 timing processes and the correctness child exited 0;
the sole nonzero process result is the expected missing-free negative control.
For the untimed LLVM resource observer, the positive case records 7 allocations,
7 frees, 0 live allocations, and 1 refusal. The deliberate missing-free mutant
records 7 allocations, 0 frees, 7 live allocations, and 1 refusal, exiting 1.
The mutated LLVM identity was rejected. The mutant's leak is an expected control
outcome, not a leak accepted in the qualified program. No C performance backend
or cross-target timing is claimed.

The performance retention manifest binds **16 exact build/output files**, plus
the manifest itself. Their bytes, the measured library/driver identities, all
71 stdout/stderr hash pairs, and the 588 duplicated correctness records have
been checked. The archived `native_compiled_not_executed` receipts describe
the compilation stage; later original process records separately prove execution.

## Retention and source binding

The provider ZIP contains 2,647 regular file members. `zip-inventory.json`
records every name, size and ZIP attributes. Every `artifacts/` member was
compared with the immutable **8dcb0d0d** Git tree, using Git blob identity:

| Classification | Files | Raw bytes | Treatment |
| --- | ---: | ---: | --- |
| Added by this run | 570 | 13,976,575 | All bytes preserved in the new archive |
| Byte-identical tracked artifacts | 89 | 4,277,480 | Identities recorded; not duplicated |
| Historical `evidence/` files | 1,988 | 103,115,692 | ZIP inventory retained; not recursively copied |

No changed tracked artifact was found. The new archive includes **58 ELF files,
8,208,592 bytes**; it preserves file contents and permission bits, not original
filesystem timestamps. The archive covers all newly added provider artifacts,
not every temporary file ever present on the CI machine. Nine principal original
reports/logs are also exposed under `originals/`, byte-identical to archive members.

Both source snapshots contain the same 922 files and have SHA-256
`19cfbb9a21f2dca8f52105d50522c5827eb533ccf3eee0ba27a85b0037ae2daa`.
Each of these 922 file hashes was independently compared with raw Git blobs at
the exact source commit. `source-snapshot-git-audit.json` preserves that mapping.
Selected exact workflow/bootstrap/qualifier/lock source bytes and Git identities
are retained under `source/` and `source-identities.json`; the current checkout's
compiler hash was never substituted for the old report's identity.

The selected reports agree on compiler SHA-256
`baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7`.
This appendix records a failed full CI attempt. It does not establish all seven
project deliverables, general backend refinement, physical-board qualification,
or results for any later candidate.

## Reproduce the archive checks without executing native code

The single XZ archive is **1,107,560 bytes**, SHA-256
`684e4a964895db809d77905d3db3c9d9105f5ebb3138f576a2cfd2f4c8fdd303`.
It was compressed once using XZ preset 6, a 64 MiB dictionary, and one thread,
in an agreed slot while the root task was running unit tests. Its base64 part is
**1,496,179 ASCII bytes**, below the 3,500,000-byte part limit. No native or
performance program was rerun during archival.

From this directory:

```sh
python3 verify_bundle.py
python3 verify_bundle.py --original-zip /path/to/12704417329.zip
```

The standalone verifier uses only Python's standard library. It checks sidecar
and archive identities, bounded ordinary-file membership, original report links,
retry events, source snapshot consistency, complete timing/correctness/process
records, resource controls, retention, and recalculated paired ratios/MAD/limits.
It never extracts or executes archive members, imports project code, or accesses
the network. The optional ZIP check rehashes the downloaded provider package and
compares its complete inventory and retained bytes. The recorded Git-source audit
is a separate read-only comparison made during preparation; this portable data
verifier does not fetch Git objects. `verification.json` records the successful
data replay including the original provider ZIP.
