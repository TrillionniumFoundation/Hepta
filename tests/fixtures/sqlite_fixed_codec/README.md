# Real SQLite four-byte codec migration fixture

`codec.inc` contains the complete, unchanged, contiguous definitions of
`sqlite3Get4byte` and `sqlite3Put4byte`, including all original preprocessor
branches. `UPSTREAM.json` records the amalgamation SOURCE_ID, full SHA-256,
Git blob ID, exact byte interval, slice hash, release URL, and pinned source
mirror commit for SQLite 3.46.0 and 3.53.2. The corresponding GitHub tree
receipts identify the full amalgamation blob and byte count. Both versions
have the same selected function text; this is a tested version matrix, not
evidence that arbitrary SQLite upgrades require no manual work.

`adapter.c` and `contracts.json` are authored integration material. The
qualification selects the portable configuration `SQLITE_BYTEORDER=0`,
`GCC_VERSION=0`, `MSVC_VERSION=0`. Other preserved branches are not qualified.
The importer captures each actual Clang translation unit. The generated
safe core takes a four-byte slice; callers still supply a valid, initialized
allocation and exclusive access for the mutable argument. A length check
cannot establish foreign raw-pointer provenance or validity.

The conversion denominator is exactly the two selected candidate functions
per version, not every SQLite function, line or semantic category. The rest
of SQLite remains external, unchanged and unqualified, with its original
byte count recorded. The native migrated test links none of the original
SQLite objects, and does not include a SQL engine. The exported scalar
Hepta harness and Python byte oracle are authored. Original C is compiled
separately with GCC; generated Hepta is checked, lowered to HIA, independently
verified and compiled through direct LLVM. The generated Rust raw-pointer
ABI bridge is inspected but is not executed in this qualification because
the required pinned Rust 1.90 toolchain is unavailable.

Reproduce together with the real GSL lifecycle component:

```sh
python tools/qualify_migration_resource_profiles.py --clang /path/to/clang --output /tmp/hepta-migration-fresh
```

The runner requires a new output directory and keeps original/migrated
observations, independent expected values, Clang capture identities, LLVM,
HIA core, compiler build receipts, commands, and negative controls. Full
amalgamations can be retrieved from the recorded URLs and checked against
the hashes; this repository vendors only the exact selected functions.
