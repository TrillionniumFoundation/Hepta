# Hepta standalone language prototypes — Library recovery (2026-11-03)

**Status: HISTORICAL SOURCE SNAPSHOT ONLY / DRAFT / DENY_ALL.**

This directory preserves ten text sources from the owner's ChatGPT Library, stored under their original Library basenames. The original source file bytes (including final newlines) were verified against GitHub Git Blob SHA-1 before this commit. These are **not** replacements for current `hepta/` compiler/runtime/CI paths, and must not be installed or treated as release gates without compatibility and provenance review.

## Source identities (Git Blob SHA-1)

| Original Library basename | SHA-1 |
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

## Evidence and limitations

- The 10 source files were materialized as original raw files and compiled for Python syntax with `python -m py_compile ./*.py` on Python 3.13: **10/10 syntactically valid**.
- Focused `unittest` attempts on the five historical test modules **failed during import** because this isolated snapshot lacks the complete `hepta` package (starting with `hepta.ast`). This is a **failed/unavailable functional test gate**, not a test PASS. No import error was suppressed and no production behavior was exercised.
- Basic static review of these ten source files found no email addresses, obvious key/token literal patterns or home-directory paths. This is not a comprehensive security audit.
- A current active HIA branch has different Git blobs at `hepta/hsir.py` and `hepta/cpp2hepta.py`; the historical files here must **not** overwrite those paths. `hepta/c2hepta.py` and `hepta/llvm_scalar_backend.py` were not found on the sampled current branch; this does not imply they are missing from all PRs.
- No compiler safety theorem, C/C++ ABI equivalence, sound ownership checker, multi-target native execution, sustained performance claim, CI qualification, or P0–P7 closure follows from this archive.
- Original Library file timestamps/versions and any separate audit log are outside this package. Additional independent verification is required before any promotion.

## Local inspection

```bash
cd library-recovery/hepta-language-standalone-20261103/source
python -m py_compile ./*.py
# Before running the tests, restore an exact historical Hepta checkout
# and reconstruct the original module paths in an isolated environment.
```

No Gmail author address is included in this archive.
