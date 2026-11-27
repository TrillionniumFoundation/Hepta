# Versioned u32-immediate compiler: generation and Source observations

This fixed bundle contains the completed generation and nine Source methods for
`hepta.hia.selfhost-encoding.u32-immediate.v1`. It grants no Native, fixed-point,
matching-cold, portable, R8 fuel, aggregate-fit, or whole-system qualification.

The source remains an isolated successor of the exact R19 tree
`d15d7a476fc3f711b2729236e84b7a9573da7a3d`. Four new authored paths and one new
generated asset produce 3,180 files at tree
`4c62be4ed66ff107fa6f88c6131313a354868bd9`. All 3,175 original file bytes and modes
are preserved. The full external R19 base is not duplicated in this capsule.

## Observed results

- Generation once and `--check` once passed, each under its own original 180+3
  second process owner on CPython 3.14.4. Exact-base materialization used a
  separate owner with the same bounds.
- The generated HIA has 125 functions, 1,472 blocks, and 8,141 operations, within
  all original IR limits. Its 466,876 bytes have SHA-256
  `d88247557387a72a8bd2ca31f7de10b684334bff96764db69ee220f5e1f2007b`
  and Git blob `5425435a6eb6c07bf6793350038ac47fb4fddf4d`.
- Actual expanded compiler source passed the complete inverse AST comparison;
  the other 124 helper functions remain byte-identical.
- All nine frozen Source IDs loaded, started, stopped, and ran in the same order.
  There were no failures, errors, skips, expected failures, or unexpected
  successes. The owner completed cleanup and observed ECHILD.
- All 452 real VM observations retain their complete six input/output/workspace
  before/after frames: 2,712 files and 46,403,838 bytes. The original 10M fuel
  limit remained in force for every invocation. Bounds traps in the deliberately
  short-buffer cases remain recorded as real traps.
- Ordinary compiler assets, Code's default encoding, B0, machine-plan paths,
  old tests, and their qualification are unchanged. The R8 image-size failure
  and earlier R5/R6/R7 fuel failures are not reclassified by these results.

## Lossless originals

`INDEX-CAPSULE.json` is a gzip/base64 wrapper of the complete index. Its declared
decoded byte count, SHA-256 and Git identity must be verified before use. The
ordered 30 `parts/raw-*.b64` files contain one base64 stream without line endings.
Strictly decoding that stream produces a 2,901,198-byte gzip whose SHA-256 is
`76c4bee9717a2c9e86d84443a6911255870a2fa22231c6f0fb17c1ba89719618`.

The gzip contains a JSON content-addressed capsule with all 3,342 logical files,
60,788,301 logical bytes, original modes and directories, and 917 unique byte
objects. It includes all complete frames, owner requests and receipts,
stdout/stderr, loaded/start/stop/subtest events, full source manifests, expanded
before/after sources, generated source, authored sources and scripts, and the
preserved pre-execution authoring errors. The archive was reconstructed from
actual Git GET response contents and every file was compared in full with its
frozen original. The verification did not create a redundant second disk tree.

To verify a mounted bundle without restoring files:

```sh
python restore.py --bundle . --report verify-new.json
```

To restore all logical files into a new directory and verify their bytes and modes:

```sh
python restore.py --bundle . --output restored-new --report restored-new.json
```

Both report paths and the output directory must be new. These commands run only
the standard-library archive verifier and do not run products. `SOURCE-ADDENDUM.json`
is an independently pinned gzip/base64 capsule carrying the complete generated
source text and its before/after relationship. `RESULT.json` is the concise
qualification boundary; `GIT-READBACK.json` retains the actual ACKs and complete
content verification receipts. C0 and any later generation are outside this
frozen observation bundle and require separate evidence.
