# Preserved finite C++ checkpoint qualification at 3533b95

This package retains the successful fresh P3/P6 finite checkpoint collector at
`3533b95c53d23de2d22c91fcc05cb601b8448eb3`, tree
`12fae5261a4478645c53e864bc262c1609d2f81d`. A later CRC timing-profile change
requires another source-specific qualification. This record is not relabelled
as evidence for that later source.

## Actual observations

Both pinned nlohmann/json releases executed 73 workers each: two calibration
calls, four calls at each of 17 actual ordinary allocation sites, and three
ordinary cases. The total is 146 workers. Each release retains 14 caught
foreign exceptions and three SIGABRT failures at sites 15, 16 and 17.

All 34 faulted operations preserved the previous parent checkpoint. Separate
new explicit requests reconstructed the bounded integer-array operation and
then continued to the next state. These 34 reconstruction observations do not
turn the six terminating foreign invocations into in-process C++ recoveries.
There is no claim of a C++ library rewrite, general foreign-state migration,
external side-effect rollback, pointer/handle transfer or automatic retry.

The formal run's 6903 tracked repository-file identities and 13 observed
compiler/assembler/linker/loader/runtime identities remained unchanged. This
is not a complete environment-closure proof. The package preserves actual
worker ELF bytes, not all toolchain binaries.

## Contents and source scope

The archive contains 1574 regular members, 17,125,567 uncompressed payload
bytes. It contains the complete formal invocation, all three development
attempt directories, local and independent production-audit receipts, and
1129 original Git objects. Those objects provide the original commit, the
complete raw tree graph, and all 354 profile-source blobs under the exact
recorded `hepta`, `tools`, `examples/cpp/upgrade` and
`tests/fixtures/cpp_upgrade` closure. They are sufficient to check that closure
without a current repository checkout or object store. The package does not
contain every one of the 6903 repository-file blobs.

`local-audit/INDEX.json` and its accompanying README preserve the earlier
index-preparation stage, before packaging and payload readback. The completed
archive result is in the external `SUMMARY.json`, `MANIFEST.json` and
`verification-attempt-002` files; the earlier stage is not rewritten.

The first development suite ran 23 methods. The later pure regression run
ran three methods, including one already in that first suite. These are
method executions with overlap, not 26 distinct tests and not additional
formal worker calls.

## Offline verification

`verify_evidence.py` uses only Python's standard library. It reads the
manifest and compressed archive once, refuses nonregular/symlink inputs,
checks external SHA-256 pins before parsing, and bounds compressed bytes,
XZ decoder memory, tar bytes, member size and member count. It never extracts
or executes archive payloads and does not import repository modules.

The verifier checks every member hash, original Git object hashes/tree/source
closure, each actual raw worker response, request/state chain, independent
integer result, allocation-site denominator, retained SIGABRT outcome,
formal wrapper identities and nested elapsed costs. It grants no execution
permission or qualification to a new HEAD. Byte consistency does not
authenticate a hostile producer's claim that historical execution occurred.

Run with the two external hash pins:

```sh
python -B verify_evidence.py \
  --archive p3-p6-json-checkpoint-3533.tar.xz \
  --manifest MANIFEST.json \
  --archive-sha256 5e69e0790bead8d54a9c9126b34d8bc7bb8ca7f133a75bfdf905d8d2724e9ace \
  --manifest-sha256 2479de679af9ec53928d4a74dcf565c64f68f48cd020651a88a683457cb6b1d8
```

The first offline-verifier attempt failed because a new archive-path local
was named `prefix`, which an existing calibration-record local overwrote
before the second version. Its exact verifier, rc1, raw stderr and measured
0.304775049 seconds remain in `verification-attempt-001`. Renaming that local
and explicitly checking tree-object kinds fixed the reader. Attempt 002
passed the same unmodified archive, rc0 with empty stderr, in 0.393612004
seconds. This was a reader defect, not a repeated native experiment or a
change to the source qualification.

The collector's 23.462315125 seconds, command's 23.573861140 seconds,
launcher's 27.418451040 seconds and outer invocation's 27.504660162 seconds
are nested and must not be added. Archive creation took 2.795372846 seconds;
audit/readback costs are separately retained. Human development/review cost
and complete agent usage remain unknown. The correctness run overlapped
another correctness task and supplies no performance comparison.

All original raw directories remain intact; no staging copy of the whole
repository was made or removed. `DELIVERY.json` binds this final external
package, including both verifier attempts, without rewriting the archive.
