# Four existing C++ CI gates, fixed-source replay

Source: `46d88bd18b1b3dadb246e92eb22c49fe44ec2d72`; tree `5d99211867c7b3a091dfc07c44366bbfe2b73cdb`.

These are the four C++ commands from step 21 of `.github/workflows/hepta-verified-optimization.yml`, with only output directories relocated to temporary storage. All four ran once and returned 0 with `ok: true`. This is a local replay of existing CI qualifications, not a rerun of the preregistered Ring, NDU or Agent studies, and not a replacement for the final remote CI job. No source or protocol changes were made.

| Gate | Finite cases | Actual implementations / controls | Result |
| --- | ---: | --- | --- |
| scoped ownership | 1,121 | C++ reference, translated Rust, C and direct LLVM; actual leak and destruction-order mutations detected | Passed |
| composed project | 437 in each of 2 configurations | Original C++ versus standalone HIA; missing-drop Core rejected without publishing an object in each configuration | Passed |
| unique_ptr project | 437 in each of 2 configurations | Original C++ versus standalone HIA; missing-drop Core rejected without publishing an object in each configuration | Passed |
| unique_ptr assignment project | 789 in each of 2 configurations | Original C++ versus standalone HIA; missing-drop rejection and actual incorrect assignment cleanup-order mutation in each configuration | Passed |

Clang/Clang++ 20.1.8, Rust 1.90.0, and the system GCC/G++ were used; `RESULT.json` contains exact version strings and command vectors. All materialized `hepta/`, `tools/` and `examples/` files were checked against their fixed Git blob before execution and again after the gates. The tracked checkout remained clean.

The checkout used an independent Git directory with read-only object alternates into the main repository. Initial local-clone transport failed because unrelated historical artifact objects were not locally cached; that setup failure is retained in `setup.json`. The subsequent sparse checkout succeeded. Its warnings about an omitted historical artifact are retained in `setup-alternate.json`; that artifact was not an input to these gates. No GitHub fetch, gate retry, compiler modification, or main-repository write was used.

`EVIDENCE.tar.gz` retains exact materialized compiler, tool and fixture sources, all four generated gate directories including native artifacts, and the run logs/receipts. `MANIFEST.json` binds every archived payload. `ARCHIVE.json` records archive identity. The original `/dev/shm` paths in `RESULT.json` identify the execution locations. After the archive was fully verified, this replay's temporary checkout and run directories were removed to release constrained shared memory; `CLEANUP.json` records that later action. The README inside the archive is the pre-cleanup snapshot. The complete source and run artifacts remain in the archive.

These finite cases support their declared C++ ownership profiles and scalar ABI behavior. They do not establish general C++ equivalence, arbitrary RAII support, complete C++ ABI preservation, formal end-to-end safety, performance superiority or a real upstream C++ maintenance cycle.
