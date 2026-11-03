# Historical Hepta language source recovery — 2026-11-03

**DRAFT / DENY_ALL / HOLD_NO_GO. No production use.**

Preserves 16 original source/test files from ChatGPT Library under `source/`, not installed into the active `hepta/` compiler or tooling. The Library was not deleted.

## Exact byte identities

Every raw file's Git Blob SHA-1 was computed on the original bytes and independently matched with the GitHub blob before reference update.

| Original Library filename | Git Blob SHA-1 |
| --- | --- |
| `hsir.py` | `054e3ebdf36a7515a4fd4535cb45f292cb73facf` |
| `test_hsir.py` | `a987dd9fbce16dc0161cced9fed63f486482d087` |
| `c2hepta.py` | `3e1813f844ac5f1a5e89a37cd01ca9b4fde82e36` |
| `test_c2hepta.py` | `3f61cef5faeb94253a16599336663928ce97b8de` |
| `Hepta_cpp2hepta.py` | `d0940d18956b1f0940057cc60b527122f1b9c037` |
| `Hepta_test_cpp2hepta.py` | `d8799feb9dd4072e1a4a2169c578abccbf8215ba` |
| `Hepta_P6_llvm_scalar_backend.py` | `a9304c64f3b53fca5174580dcd34fcdb3df9d668` |
| `Hepta_P6_llvm_scalar_tests.py` | `7e34453508312a2d5ae07cdf3730d83aa7b2ed03` |
| `Hepta_P6_llvm_backend_cross.py` | `f2291ce7a33c9bb041e80c21b96bcdd598b7fccb` |
| `Hepta_P6_llvm_cross_tests.py` | `7345321b4affac0b45d057c4dc791ea3f05f4b47` |
| `Hepta_abi_host_probe.py` | `70e7c584e0dbf4f22f6c302135c9f852ffd93265` |
| `Hepta_test_abi_host_probe.py` | `b2771567e4db3b4c97a3fdca35d0705131ed2925` |
| `Hepta_cpp_bridge_source.py` | `3c370f38082aad2120034de96ff535cc39752b52` |
| `Hepta_cpp_bridge_tests.py` | `21fa93fde38500a0f36838563b035e2c97ecb5a5` |
| `Hepta_test_llvm_scalar_phi.py` | `df68945aae792d826fe9001536abed62e83f2842` |
| `Hepta_verify_llvm_subset_host.py` | `9dd362467cc8381fb72b818c0e9c1257a32f0a64` |

## Execution and environment limitations

- On the isolated Python 3.13 environment, `python -m py_compile` passed for all 16 files.
- Three ABI/C++/LLVM test modules were attempted with `python -m unittest -v Hepta_test_abi_host_probe Hepta_cpp_bridge_tests Hepta_test_llvm_scalar_phi`. **3/3 modules had import errors** before tests ran: missing original `tools.abi_host_probe`, `hepta.cpp_bridge`, and `hepta.llvm_scalar_backend` layouts. No unit tests were executed by this command. Earlier five historical test modules had the same missing-complete-checkout limitation. These are **NOT PASS claims**.
- Original package path names and imports differ from each other and from current GitHub sources. Do not assert functional parity or transplant without building the original complete source tree and checking API/ABI contracts.
- Minimal static scans for email addresses, PEM private-key markers, common GitHub/OpenAI/AWS token patterns, and hard-coded `/home/` paths returned no findings on the six newly added files. This is not a complete security review; no Gmail author address intentionally added.
- Frozen original GitHub `main` parent: `125d11c5454835a7df1dc51915fc49901fbede5b`. Historical sources must be explicitly compared with current development PRs before proposed integration. No evidence from this archive closes HIA P0–P7 or grants Final-use/release/production authority.

## Reproduction instructions

1. Confirm Git blob identities against this table, and run syntax checks:
   ```bash
   cd library-recovery/hepta-language-standalone-20261103/source
   python3 -m py_compile ./*.py
   ```
2. Restore the **actual historical** `hepta` and `tools` package/dependency graph (not represented by these snapshots). Preserve checkout SHA, OS/arch, Python/Clang/LLVM/rustc versions.
3. Map source filenames to the package paths in the historical manifest, run the original dedicated suites on a clean source and independent holdout, record full stdout/stderr, exact exit status and source tree SHA.
4. Keep any unverified or failing gate OPEN, without silently skipping, relaxing, or treating synthetic unit tests as native qualification.

Historical-source preservation only; not a replacement compiler, not a completed C/C++ migration, not a production release.
