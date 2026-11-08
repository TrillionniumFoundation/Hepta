# Persistent NDU: complete CI evidence at source 50c1578b

This retained observation belongs only to Hepta commit
`50c1578b4d4597e3070a9abc3700c9aacbf99851`, tree
`87b106d1e76337e02bda5e7a9132c4854c601b00`, and
[GitHub Actions run 42516119809](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42516119809),
job `128839401820`, attempt 1. Its successful NDU workflow is not transferred
to any later repaired source, release lock, installed worker or broader Core
qualification. All data here comes from the public CI artifact and its public
GitHub metadata. No private deployment configuration or preparation evidence
is included.

## Controls and original registered comparison

All 164 Python tests completed with no failures, errors or skips. The suite
included all 22 persistent transport tests and the three required actual native
integration tests. The original Rust framing suite passed its three required
tests with none ignored. The retained native executable is 2,345,848 bytes,
SHA256 `494d198e94f533c8a894dc141a42be2890fa12bce14d9b4b2c849ee5fbf46cb5`.
The integration report explicitly keeps model cost unavailable and complete
cost accounting false; it records zero new provider calls.

The original registration has SHA256
`e57aaa35b1484b60cb0492481909a5971a9c70df1f9a7bb5499837c3fda93151`.
All 72 registered cells completed, with zero failed cells and zero automatic
retries. There were 1,020 checked native responses, 534 observed native process
IDs, and 510 ordinary calls. All 510 paired prepared/persistent response bodies
were byte-identical. Every original cell, request, response, process and cleanup
record is retained, including slow and negative observations. This sealing
step performed no experiment rerun, native execution or resampling.

| Requests per session | Pairs | Ordinary median ms | Prepared median ms | Persistent median ms | Persistent wins over prepared | Aggregate saving over prepared |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 6 | 0.135144 | 8.327382 | 8.835613 | 1/6 | -3.20% |
| 4 | 6 | 0.588185 | 14.852395 | 12.898858 | 6/6 | 21.36% |
| 16 | 6 | 2.274683 | 40.588864 | 28.184112 | 6/6 | 33.41% |
| 64 | 6 | 8.960298 | 151.280048 | 88.374357 | 6/6 | 39.57% |

Aggregate savings use the registered sums of paired all-attempt arm costs,
not ratios of displayed medians. The ordinary algorithm is faster than both
native transport arms in all 24 pairs. At one request, persistent wins over
prepared in only one of six pairs and has negative aggregate savings.
**P2 remains HOLD.** Reusing a process reduces transport cost at longer
registered horizons; this is not evidence of stable application value,
complete lifecycle economics, provider billing, or a general machine
refinement proof. Shared CI host conditions and the recorded cost boundaries
remain limitations. No positive horizon is selected to replace the full
registered result.

## Exact original bytes

The original GitHub artifact is `13631367936`, ZIP size 8,087,371 bytes,
SHA256 `4b13273fc3dd4208e312803f369075603435e9f0e17cccb74099f727d9248ed2`.
The GitHub artifact metadata independently reports the same size and digest.
`raw.tar.xz` contains all 475 original regular-file members, totaling
37,742,792 uncompressed bytes. It was built directly from ZIP member streams;
no original member was extracted to disk or executed. Only archive container
metadata was normalized: sorted paths, zero owner/group/timestamp, and preserved
executable bits. Original member names and payload bytes remain identical.

The resulting archive is 1,276,956 bytes, SHA256
`544e51e235e647aa6d32f1b0360096adaddfc5e905f8cd253f1f9ed9d11df37c`.
`inventory.json` lists every original path, byte count and SHA256. A separate
streaming pass decoded the complete tar archive and checked every member
against those original ZIP hashes, including exact set equality and absence
of duplicate or non-file members. `archive-verification.json` records this
475/475 result. This is file-integrity verification, not timing authentication
or hardware attestation.

The raw archive includes both prepared and persistent registrations, all
registered cells, original source copies and build receipts, the native
binary, Python integration controls, Rust controls and both CI replay reports.
For review convenience, selected original JSON files are duplicated alongside
it as `registration.json`, `persistent-result.json`, `ci-replay.json`,
`integration-result.json` and `stream-rust-tests.json`. These copies have
unchanged bytes. `root-summary.json` preserves the root agent's supplied
summary byte-for-byte; its result fields and full replay object were checked
against the original archive. `provenance.json` records retrieved public run,
artifact and job metadata.

## Replay and scope

`ci-replay.json` is the original CI invocation of the standard-library-only
persistent replay verifier. It checked all 72 cells, 14 source-file hashes,
raw frame identities, response equality, process/EOF/cleanup evidence and
cost arithmetic. Its authority remains `DENY_ALL`; it explicitly states
`timings_independently_authenticated: false`,
`economic_benefit_established: false` and `machine_refinement_proved: false`.
It is not relabeled as a newly executed independent replay. The additional
local sealing pass verifies archive integrity only.

The supplied standard-library-only repacker can verify all archived member
hashes without extraction or any native execution:

```sh
python -B repack_ci_artifact.py --output-directory . --verify-only
```

To reproduce the normalized archive from the pinned original CI ZIP, use a
new output directory and the retained root summary:

```sh
python -B repack_ci_artifact.py --zip ORIGINAL_CI.zip --root-summary root-summary.json --output-directory NEW_DIRECTORY
```

The script checks the fixed original ZIP digest, source boundary identities,
registration identity and summary agreement before repacking. It refuses to
overwrite any output member. Integrity still depends on using the published
pinned inventory/script rather than replacing them together with the payload.
