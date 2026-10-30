# P3/P6 evidence at integration commit 44e34b7a

This package preserves the fresh P3 changed-body qualification and P6 context regression on committed source `44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304`, tree `835555fb35dbdcf867724ef7a0bb1a6616270217`. It also preserves the original development, failure reproduction, old `ffe4a127` qualification and subsequent readback fixes. No historical run is relabelled as a run of the new integration commit.

## Actual result and scope

P3 passed its actual CLI and strict retained-data replay. It recaptured all six active scalar functions of the unchanged, pinned full `stb_divide.h` headers at versions 0.93 and 0.94. The real changed active bodies are `stb_div_floor` and `stb_mod_eucl`. The route is the existing C capture → Hepta source → Core → direct LLVM route, without manual migrated-body edits, Rust code generation, or linking the original C implementation into the HIA target.

The observation is limited to the actual Linux x86-64 / LP64 host, 32-bit C `int`, and `-std=c11 -O2 -DC_INTEGER_DIVISION_TRUNCATES`. It does not qualify other macro configurations, arbitrary C/C++ maintenance, general C++ rewriting, or all-input source/backend refinement.

| P3 category | Actual denominator / outcome |
|---|---:|
| Conservative common-defined input pairs | 119 |
| Functions per upstream version | 6 |
| Common-domain native function observations | 2,856 |
| Common-domain VM observations | 1,428 |
| Old original-C UBSan failures | 4, retained as failures |
| Old HIA overflow terminations | 4, retained as failures |
| Successor-only native / VM observations | 48 / 24 |
| Witness VM observations | 8 |
| Invalid-target HIA native / VM observations | 24 / 24 |
| Actual stale/wrong-target negative controls | 2, rejected as expected |

Old undefined inputs are not counted as successful cross-version equivalences. Native allocator counters were not measured for this scalar corpus.

P6 completed the four full context/reference/reentrancy/map-repeat test modules plus one actual native map-repeat lifecycle method: **46 test methods, 0 failures, 0 errors, 0 skips**. The actual footer is `Ran 46 tests in 21.623s / OK`. Method count is not native-call count. The callback reentrancy fix rejects state-changing owner calls during reference computation, with exception-state restoration and the existing nonce, quota, poison and cleanup-debt rules retained. It is a finite context profile, not a qualification of general foreign exception recovery.

The historical nlohmann/json 3.11.3 → 3.12.0 qualification on commit `50c4067399989e7194028576c38c0e783b78cf06` still contains **six unrecovered foreign `noexcept` SIGABRT events**: 17 actual allocation sites per version, 14 recovered and 3 terminated per version. This package includes the exact prior package SUMMARY, MANIFEST and DELIVERY as bound references. Its larger, already preserved execution archive is not duplicated here. That C++ path retains the foreign library and bridge; it is not a rewritten C++ library, and its general safety/recovery gap is not closed by the new scalar-C component success.

## Archive and source bindings

`executions.tar.xz` contains **1,222 regular members, 40,498,810 uncompressed payload bytes**. Its compressed size is **1,649,148 bytes**.

| Item | SHA-256 |
|---|---|
| `executions.tar.xz` | `ae46861484a159341143aaf0ee4dfab2696e280d46dbea7c397c86ebd492b4f2` |
| `MANIFEST.json` | `d15048f2f5c7dc0260f25752570fbdf925903f88139e138bc0ce28bc984f4cfa` |
| Final `verify_evidence.py` | `d29defe4ad29bea14ac9984b019b67a4cd8d29b348f2962e3f5edd8c5cf9dc88` |
| Current P3 qualification JSON inside archive | `e23a911fa50e748b6ee2cf60bcc1d4488061507b79160f44739e438f406d2475` |
| Current outer receipt inside archive | `12eca7ede8b4232eef2493b93703d94b7d589e409e63242b2bdc21319c228b92` |
| Original unchanged `ffe4a127` qualification | `1739deaae7229d6494732a495dac38e195ccef0fbd7586f08b725ebcd51a6f4c` |

The archive holds all 170 current execution/launcher/review members and all 485 files in the four historical directories. These include complete raw stdout/stderr and original native artifacts. Current outer capture is complete; its stderr is empty. No temporary raw payload copy was created during packaging, and all original execution directories remain available.

Selected source bytes are also archived with their raw Git commit/tree objects. The verifier recomputes the commit/tree/blob hashes and follows each selected pathname from the named commit's root tree; it does not rely only on a clean-status string.

| Archived source snapshot | Files | Purpose |
|---|---:|---|
| `current-44e34b7a` | 353 | Current Hepta/tools Python sources, P3 declared closure, relevant P6 tests and documentation |
| `original-p3-ffe4a127` | 163 | Original qualification's complete declared source ledger |
| `context-before-73922c1` | 3 | Selected pre-fix context implementation and regression helpers |
| `context-fix-eeb41d7d` | 4 | Selected context fix and reentrancy regression |
| `readback-fix-0f2bc05b` | 3 | Selected VM/source binding fix, tests and retained VM fixture |
| `owner-mode-96459326` | 3 | Selected owner-execute-bit correction, tests and fixture |

These selected snapshots do not constitute a full transitive toolchain or OS image. The runtime's complete recorded inventory of 6,685 tracked repository files is preserved in the execution receipts; it includes docs/evidence/fixtures as well as code. Only the explicitly listed source subsets are reproduced as file contents in this archive.

## Safe offline verification

Run a trusted copy of the supplied verifier using Python's standard library:

```sh
python3 -B verify_evidence.py --directory . --output my-readback.json
```

The output path must not already exist. The verifier reads and hashes the exact compressed archive and manifest bytes before decompression. Input opens use `O_NOFOLLOW`, `O_NONBLOCK`, `O_CLOEXEC` and regular-file checks; streams are read with explicit limits. Its limits are 16 MiB compressed archive, 2 MiB manifest, 64 MiB XZ decoder memory, 128 MiB complete expanded tar stream, 4,096 members and 8 MiB per member. Paths, links, sparse/special files, duplicate members, unexpected members, and mismatching size/mode/hash values are rejected. Expanded headers are included in the complete tar-stream bound.

It never extracts files to the filesystem, imports repository/archive modules, executes binaries, invokes a compiler/SMT solver, or generates model answers. In addition to hashing every member, it checks the recorded source and tool identities, Git source bindings, exact P6 footer/method set, every retained P3 process stream, both versions' native/VM finite matrices against independent integer arithmetic, the preserved UB/overflow/invalid-target categories, and the old C++ failure summary. This is an integrity and finite consistency check, not a cryptographic attestation of past execution or a whole-language proof.

The final verifier completed its full actual readback with exit code 0 and empty stderr. Records are in `verification-attempt-002.*`. The earlier successful verifier and readback remain in `verification-attempt-001.*`; the only later hardening adds nonblocking and close-on-exec flags to input opens. An independent agent also replayed that first version successfully; its external review is referenced in the final delivery information. The archive and manifest bytes did not change between these checks.

## Cost and historical accounting

Actual current P3 collector time was 31.952196561 s, P3 outer-stage time 32.222954833 s, P6 outer-stage time 21.735303912 s, and complete outer time 58.838356302 s. These are nested and must not be added. This correctness run could overlap P1/P2 correctness work; no runtime-performance advantage or dedicated-host timing qualification is claimed.

Packaging took 10.435578184 s through its build receipt boundary. Final offline verification took 0.453693072 s at its external process boundary. These later evidence operations are separate from the original qualification. Complete human development/review effort and complete historical tool acquisition cost are **unknown**, not zero.

`SUMMARY.json` is the formal machine-readable summary. `MANIFEST.draft.json` and `P3_P6_REVIEW_DRAFT.md` are retained preparation documents and describe the earlier pre-archive phase. `P1_P2_INDEPENDENT_REVIEW.json`, `P7_PEER_REVIEW.json` and the `P7_ARCHIVE_PEER_*` records document separate read-only reviews; they are not additional P3/P6 qualification runs and are not added to its test denominator. `DELIVERY.json` records exact delivery-file identities.
