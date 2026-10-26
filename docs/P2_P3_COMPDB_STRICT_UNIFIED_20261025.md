# P2/P3 bounded C compilation database + typed ABI capture integration

The single `hepta.c_project` implementation now applies two complementary
checks **together**. No alternate C migrator or second Clang semantic authority
was created.

- **Untrusted input intake:** `_load_compdb` is the bounded, duplicate-key
  rejecting, UTF-8 only parser. Both initial capture and verification replay
  parse the very same original byte snapshot. It admits 1–32 commands and
  exact `directory/file/(arguments XOR command)/optional output` fields.
  Size budgets: 2 MB database, 4 KiB paths, 16 KiB arguments, 256 arguments
  per command, and 8 MB per dependency before allocation.
- **Typed ABI provenance:** the existing strict capture fields, compiler
  identity, target long/char/pointer widths, every local-vs-system header
  flag and exact dependency hash/byte count remain mandatory. Rehashed JSON
  `False`/0 or float/int substitutions are not accepted.
- **ABI probe flags:** `_abi_model_arguments` independently reconstructs
  permitted target-model arguments from the exact frontend flag allowlist.
  A rehashed record cannot add an unreviewed `-D__SIZEOF_POINTER__` or
  pretend a different char signedness.
- **Race and memory bounds:** captured header bytes are limited before
  reading; compiler executable identities are streamed in 1 MiB chunks;
  the database bytes are re-read with the same strict parser after actual
  Clang dependency/macro/ABI probes. Modifications during probing reject.
- **Shell safety:** a compilation database `command` is tokenized with
  `shlex.split` only; it is **never executed as a shell program**. The
  source compiler driver remains explicitly selected by Hepta.

## Exact merge context

Base: #144 unified compiler at
`ba90aae079926e916af72982b0f70ab6c9b890d2`, containing typed C capture
module blob `3c0bbea9a8a41a8dbc20cce7dcf6f4628dc527dc`.

Borrowed the **single bounded parser** and its standalone regression file
from PR #146 code blob
`68bf17f8fb0073f32646979125e5e84fa2372486` while **retaining** the
independently developed strict typed dependency/ABI provenance from #144.
Neither full file was blindly cherry-picked across divergent branches.

The standalone `tests/test_compdb_intake.py` was transplanted by its exact
original Git blob identity. Three additional compiler-connected negative
tests cover duplicate compile database keys after a manifest rehash,
valid-compdb mutation during Clang probing, and ABI model argument injection.

## Execution status and limits

PR #146 reported isolated parser mirror tests; those observations belong
to its own source and do **not** qualify this merged code. New current-branch
complete Hepta tests/native migration have **not** been executed here.

Run:

```sh
python -m unittest tests.test_compdb_intake tests.test_c_project -v
python tools/qualify_c_migration.py --help
```

The C project migrator still supports only its explicitly documented C subset
and 64-bit hosted ABI. A complete C/C++ translation theorem, foreign pointer
provenance and memory safety, macOS/MSVC true ABI parity, physical hardware
and production Agent throughput **remain unqualified**.
`whole_project_blockers_closed=false`.
