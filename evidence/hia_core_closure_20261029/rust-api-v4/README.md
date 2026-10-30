# Bound-v4 exact finite API increment: retained evidence

This package preserves three distinct evidence origins without relabeling:

* Original local component executions: bf143a7ebf12e4a7013c0dd41fe23d14ad3e5ec7.
* Actual required focused public executions: adbe4a1168a84d0696749ef54f933994b5dc554c.
* Independent review: 11 actual executions on the original local commit,
  plus static review, with no findings. The review's 26 files are unchanged.

The two component commits have the same exact source tree 04b70dccc157af470aa2b5bdeb74e6f88dbff5bf.
Both native builds produced identical 3,470,040-byte executables, SHA256
5c39bec4def3b274487c4dce5f37475d7c2e0ac0c1e14634f5fa906f87c15abc; one exact binary is retained
under payload/native/. Its original and rebuilt identities remain separately
recorded in the execution records. The full transitive toolchain and system
runtime are not bundled or claimed to be closed by this archive.

The public run actually performed the full Rust crate (93 passed across 18
harness blocks), all 8 selected v4 methods, and 45 related existing Python
methods, with zero failures, errors or skips. The v4 collector retains 155
actual observations, 37 raw refusals, and 72 legacy reports across primitive
v1-v8. These observations and reports are not additional language test methods.
The local and public reruns are not added together as new unique coverage.
The earlier initial-* records remain historical pre-freeze attempts.

The source-files directory, exact patch, local/public/base raw Git commit
objects, changed-file blob/mode map, and the four original publication receipt
files are retained. The historical public-source-commit.json snapshot saying
public_execution_not_yet_repeated=true is intentionally unchanged. The later
public-focused-summary.json and actual public process logs record the new run.

This is finite bound-v4 API evidence. Policy transport still has a 1024-byte
ceiling; scalar transport remains 8192 arguments and 128 KiB. Production
authority remains Python and optimization policy remains no_change. Full P2
and all P0-P7 closure remain false. The separate full eight-gate 699de39
qualification is not a public-v4 execution and is not included in these counts.

MANIFEST.json binds every payload file's bytes, SHA256, Git blob SHA1 and stored
mode. The external archive-receipt.json binds this entire archive and records
complete gzip-stream and per-member tar read-back verification.
