# Hepta P0–P7 historical Library source snapshot

Historical code-only recovery; no mainline replacement and **no release qualification**.

This directory preserves nine original standalone Library files (verification scripts, test cases, C++ fixture snippets, and one unapplied CI patch). Their full Git Blob SHA-1 values were checked against the uploaded bytes, and the Git tree was checked before commit. The original Hepta recovery parent is `6ab5621ca3917c8e2fdf9370f6d9fcf2186ed93b`.

## Locally rerun the available subset

From `source/`:

```sh
python3 -m py_compile *.py
python3 -m unittest -q test_hepta_exact_head_closure.py
```

Observed on the standalone recovery copy: **10/10 tests OK** for `test_hepta_exact_head_closure.py`. The other test file `test_hepta_p0_p7_verify.py` cannot run in isolation: its direct required local fixture `HEPTA_P0_P7_BLOCKERS_20261023.json` was absent from the source-only extraction; it failed with FileNotFoundError. No test pass is claimed for that suite. The C++ samples also require their original compiler flags, harness and targets; the patch is preserved only, not applied.

No production ABI, proof, performance, Agent, memory-safety or P0–P7 blocker is declared closed.

## Original source SHA

| Original name | Git Blob SHA |
|---|---|
| `hepta_declared_for_normalized_20261025.cc` | `be7b12f21d853f066c3bea2334567192aeefcb27` |
| `hepta_declared_for_original_20261025.cc` | `06e6db4b6896caa90896b1db1083582657ca1643` |
| `hepta_declared_for_ubsan_driver_20261025.cc` | `bf6bbef6d1a625a1ae8385398c42472a33967108` |
| `hepta_exact_head_closure.py` | `5afd63a092c58eb01d5bf2183722f80a5c333994` |
| `hepta_exact_head_gate.py` | `88c84064e36693037964f28384e6574d6ed7150e` |
| `hepta_p0_p7_mandatory_native_ci.patch` | `84dbb40fa51e913d03817e80fc2f15da6d986433` |
| `hepta_p0_p7_verify.py` | `db8140aa32f4f8ac613c73018256524481c3df08` |
| `test_hepta_exact_head_closure.py` | `58c8593dc563684871602b23b87898cdb1cdec66` |
| `test_hepta_p0_p7_verify.py` | `4688f81514e436d7f93451cf67104be6de85e135` |

## Publication / cleanup

The two historical duplicate `hepta_security_candidate_Cargo*.lock` files and `hepta_security_candidate_MODULE.bazel.lock` were *not included* in this source-only subset. They must be resolved separately by exact configuration identity; do not delete Library before completion of all source and dot-host checks. The original document and patch contents may reference historical local paths; they are not active CI workflows.
