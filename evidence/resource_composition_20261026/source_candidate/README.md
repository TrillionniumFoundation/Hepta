# Frozen source candidate: complete 50-gate run, 2026-10-27 UTC

This directory preserves one finished execution of the full source qualification
suite. The original release result is **failed: 48 gates passed and 2 gates
failed**. Both failing gates retain `measurement_inconclusive` performance
reports. No result, threshold, sample, observation or gate status was changed
during archival. All 105 samples from those two reports remain available.

The tested source is commit
`3a424e427b378400802c9e3c2fef558c0a352756`. The evidence-only branch starts from
`8dcb0d0d8aabfa6bd260305c57344ce15ef72eca`; that publication base is a different
commit and is not presented as the source executed in this run.

## Recorded outcome and identity

| Item | Original recorded value |
| --- | --- |
| Release schema | `hepta.release.v2` |
| Started UTC | `2026-10-27T01:34:40.805994+00:00` |
| Completed UTC | `2026-10-27T01:52:00.282507+00:00` |
| Gate denominator | 50 planned and executed; 48 passed, 2 failed |
| Unit and integration tests | 2,093; zero skipped; terminal unittest result `OK` |
| Unit timing | 615.644 seconds for the outer gate; 614.471 seconds in unittest's terminal summary |
| Source inventory | Exactly 920 paths from `report.source_snapshot.files` |
| Source snapshot | `339ed18eafd41c41e6b1e84f18bec100db5122cf60983c948aa721f54249c10b` |
| Compiler tree | `baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7` |
| Original report SHA-256 | `248a5aa6041e90e87e1528bf78ea35f97316caf8fe99b686b19156e55cf2ad8f` |
| Snapshot remained unchanged | `true` |
| Whole-project blockers closed | `false`; original P01–P12 list retained |
| LLVM scalar performance gate | Gate exit 1; 42 samples and 42 process observations; `measurement_inconclusive` |
| LLVM owned performance gate | Gate exit 1; 63 samples and 63 process observations; `measurement_inconclusive` |

The process observations cover the complete child capture call, including
startup, warmup, the timed loop, shutdown and output capture. They remain
separate from the driver's native elapsed time. They do not establish exclusive
CPU access or a cause for the measurement failures and do not justify discarding
samples or adjusting thresholds. A separate review evaluates the performance
data; this archive does not recompute or replace that review.

## Retained bytes

The source and run artifacts are separate xz archives, encoded as Base64 for
publication. The source archive uses xz preset 1. In an explicitly scheduled
interval without HIA native performance timing, the run archive was recompressed
once with xz preset 6 and a 64 MiB dictionary, preserving the same tar/member
bytes. No native execution or performance sample was repeated. Each archive
manifest lists every member
path, byte count, SHA-256 and permissions; it also records encoded and decoded
archive identities. Tar timestamps and ownership metadata are normalized. File
contents are unchanged; source permission bits follow the tested Git tree, and
artifact permission bits follow the files observed during archival.

| Archive member group | Files | Original content bytes |
| --- | ---: | ---: |
| Source snapshot | 920 | 10,927,330 |
| `artifacts/composition-candidate-20261026-run1/` | 306 | 97,848,679 |
| `artifacts/cpp-class-20261027T013440805949Z/` | 11 | 4,012,533 |
| `artifacts/cpp-owned-20261027T013440805949Z/` | 14 | 4,280,239 |
| `artifacts/cpp-owned-llvm-20261027T013440805949Z/` | 5 | 68,669 |
| `artifacts/cpp-composed-20261027T013440805949Z/` | 57 | 14,621,208 |
| `artifacts/cpp-composed-llvm-20261027T013440805949Z/` | 39 | 1,053,163 |
| `artifacts/cpp-upgrade-20261027T013440805949Z/` | 152 | 44,179,646 |
| Driver log | 1 | 27,282 |
| Run-artifact total | 585 | 166,091,419 |

The six C++ directories are exactly those named by the completed run's gate
commands using `--workdir`. Their existing native objects, executable files,
generated sources and reports are retained. All 50 gate logs and all 43 evidence
files named by the release report were checked against their recorded hashes.
No other historical `evidence/` or `artifacts/` directory is copied.

Both archives are split into numbered Base64 parts, starting at `part01`, with
each part no larger than **3,500,000 ASCII bytes**. Their manifests specify the
complete ordered part list. Joining each list yields one Base64 representation;
the parts are not independent xz streams. The verifier joins and checks them
automatically without creating an extracted tree.

The loose `release-validation.json`, `llvm_native.json` and `llvm_owned.json`
are byte-for-byte copies of their archive members. `driver.log` is the original
outer driver log. `source-snapshot.json` reproduces the release report's source
inventory. `source-git-identity.json` contains the raw tested Git commit object,
the 111 tree objects needed to reach the 920 source paths, and their blob IDs.
The verifier hashes those Git objects and source blobs, so source/commit binding
can be checked without the original repository or any network access.

## Explicit retention limits

This is a complete copy of the finished report directory, the six declared C++
workdirs and the outer driver log at archival time. **It is not a complete copy
of every temporary native build or the execution environment.**

The archived JSON refers to 44 distinct `/tmp/` namespaces through standalone
path strings. At archival time, 42 were absent. These include the scalar and
owned LLVM performance workdirs: their reports retain hashes, receipts, samples
and observations, but this archive does not supply their deleted native binary
or object bytes. The two present namespaces were external toolchains,
`/tmp/hepta-ai-rust-1.90.0` and `/tmp/hepta-ai-verification`; their contents are
also excluded. `archive-scope.json` records each namespace, referring reports,
example paths and observed presence. This enumeration does not claim to find
paths embedded only inside free-form diagnostic text.

No source tree or HIA result was changed or executed during archival. The HIA
run in progress was not read. Source Git identities and SHA-256 hashes establish
content relationships; they are not remote execution attestation, a proof of
whole-language safety, a broad performance qualification, or closure of the
project's production blockers.

## Read-only verification

Run from any working directory with Python 3 and its standard library:

```sh
PYTHONDONTWRITEBYTECODE=1 python evidence/resource_composition_20261026/source_candidate/verify_bundle.py
```

The verifier reads and hashes files, decodes bounded Base64/xz data, and reads
regular tar members in memory. It rejects unsafe member paths, links, duplicate
or unlisted members, wrong sizes or hashes, archive-part reorderings, changed
source/Git identities, and inconsistent gate/sample denominators. It never
extracts members, imports archived project code, compiles, runs a native program
or contacts a service. The result distinguishes byte verification from a new
qualification execution.

The small synthetic negative controls can be run independently:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s evidence/resource_composition_20261026/source_candidate -p test_verify_bundle.py -v
```

`verification.json` and `verification-tests.log` record the actual local
read-only verification and negative-control results. `MANIFEST.json` binds the
loose documentation, reports, verification code and archive manifests; archive
manifests bind all Base64 parts and all archived members.
