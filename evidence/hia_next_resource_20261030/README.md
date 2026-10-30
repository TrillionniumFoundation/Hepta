# Fresh integrated P1/P2 correctness evidence

This package retains one actual execution on source commit
`44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304`, tree
`835555fb35dbdcf867724ef7a0bb1a6616270217`. It is the same authored regression
corpus on the integrated source, not a new holdout or a performance study.

The original 34 evidence files are stored under `fresh/`, together with their
original `MANIFEST.json`. The independent peer readback is stored under `review/`.
All stdout/stderr, raw Rust process inputs/responses, Cargo build evidence,
source/tool identities, launcher, frozen PLAN, terminal receipts, summary and
initial offline verifier are retained unchanged. There are 36 archive members.
No target binary, compiler toolchain or earlier development archive is embedded.

## Actual observed results

- Rust: 116 tests in 21 test binaries; zero failures, skips or filtered tests.
- Python focused corpus: all 51 exact method IDs completed with zero failures,
  errors or skips.
- 296 direct Rust processes: 261 returned process status 0 and 35 returned 1.
- 253 complete bound/Machine/Python comparisons: 183 returned, 48 exceeded a
  runtime budget and 22 trapped. These are a subset of the actual processes.
- The 28 explicit `raw_refusals` are a subset of the 35 nonzero-return controls;
  the remaining seven controls are preserved too. One isolated Python child
  is recorded separately. Do not sum overlapping categories.
- 53 stopped observations retained nonzero live payload. Agreement of the
  stopped ledger and a conservative payload bound does not establish cleanup
  after every trap or budget stop.

The unchanged pinned Rust artifact was 4,527,792 bytes, SHA-256
`eca5c05c474471506dd375f17a4bb8e79bce8d5f7239934885d02e3a32dc685e`.
Actual locked/offline Cargo commands and tests ran while retaining the existing
external target cache. Matching binary bytes do not establish a clean rebuild.

The independent interpreter profile is `raw-byte-dag-finite-heap-v1`, limited to
one exact scalar invocation of checked primitive v7/v8 byte-owner DAG Core.
It bounds logical live payload, not host RSS, native stack or CPU time. Default
and native admission authority did not expand. Source-to-Core refinement,
Core-to-native refinement and whole-language soundness remain unproved.

## Cost and historical boundaries

The actual outer execution interval was 59.249860604 seconds. Rust stage
5.045021326 seconds and focused stage 50.430129204 seconds are nested inside it.
Initial/offline/peer/archive verification costs are separately recorded and must
not be added again as if they were application speed measurements. Final receipt
serialization and shell startup are outside the execution outer interval. Full
human development/review cost is unknown, not zero. Correctness could run
concurrently with P3/P6, so timings do not qualify a performance advantage.

Earlier development evidence retains its own source commit
`958790711467018ffb0da56c4834e6bfb5f29f3e` and evidence commit
`6f97deb51e1ab5d34987c3b4ae0b3d534c8b8721`. Its failed attempts are not removed,
relabeled or reused as current qualification. That earlier package is referenced
rather than copied here.

## Offline readback

Run `python3 -B verify.py` from this package, or supply its directory as the one
argument. The verifier requires only Python's standard library on the qualified
POSIX host. It does not extract the archive, execute the archived launcher or
verifier, import the repository, build code, run the target or load a model.

The verifier bounds the compressed input to 16 MiB, the decoded tar and aggregate
member bytes to 32 MiB, each member to 16 MiB, the member count to 64, the manifest
to 1 MiB and the XZ decoder to 64 MiB. These are framing/work limits, not a theorem
about Python process RSS or CPU usage. Only ordinary files are accepted; unsafe,
extra, duplicate, link and PAX members are rejected. It rehashes every member,
checks the original and execution inventories, rechecks source/tool/plan bindings,
recounts actual footers and processes, compares all 253 observed results and
checks the peer's four original input identities and recorded stdout.

The manifest is an unsigned integrity inventory. Readback does not authenticate
a hostile producer, prove compilation refinement or confer renewed admission.
