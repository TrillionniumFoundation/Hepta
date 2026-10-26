# P3 C compilation database: fail-closed capture and replay — 2026-10-25

This is a narrowly scoped C migration qualification increment. It closes
the duplicate/ambiguous/unbounded compile database *intake* gap; it does
**not** close P3 general C migration, P1 memory safety, P4 C++ interoperability,
or production P0–P7 qualification.

## Parent and sole authority

- Source parent: `0edacd07e0c723b720e885fb9497045755ac8daa`
  (existing P1 native resource-gate development branch, stacked on PR #121).
- Independent continuation: `agent/hepta-p3-compdb-failclosed-20261025-v2`.
- Keep the existing `hepta.c_project` project capture and C migrator
  as the **only** C configuration interpretation authority.
- Both initial `capture_project` and `verify_capture` replay now call
  `_load_compdb`. No alternative language frontend, semantic IR,
  compiler execution method, or implicit safe code certification is introduced.

## Reviewed data contract

The untrusted `compile_commands.json` must now:
- decode strict UTF-8 and contain no duplicate JSON keys, including in nested
  objects; malformed, nonfinite and unbounded JSON fails closed;
- be at most 2,000,000 bytes, with 1..32 translation-unit configurations;
- contain records with `directory`, `file`, exactly **one** of
  `arguments` and `command`, and optionally `output`;
- contain no unreviewed metadata fields, empty/NUL-bearing field values,
  oversized UTF-8 paths (4096 bytes), oversized arguments (16384 bytes),
  or more than 256 command arguments;
- use syntactically correct shell-style quoting when the `command` string
  field is used. `shlex.split` only tokenizes data; no shell is executed.

The existing `_flags` allowlist still governs which compiler flags may
reach the selected real Clang binary. Compilation databases do not control
the executed compiler identity. Changed source files, headers, macros,
preprocessing and target/ABI probe facts continue to invalidate a capture.

For replay, the SHA-256 of the **exact bytes parsed by _load_compdb**
must match the bound original database digest. A second unrelated disk
read cannot serve as the proof identity for an earlier parse.

## Executed evidence and scoped test sources

A standalone Python 3.13 mirror containing the exact new parser logic ran
**15/15 positive and negative tests** successfully on this host; these
exercise valid argument/command records, duplicate names, NaN, invalid
Unicode, NUL fields, mismatched types, forbidden combinations, quoted
commands, argument count, source count, byte limits and unknown metadata.
That mirror is **not** a run of the full Hepta source tree.

Repository test files added/updated:
- `tests/test_compdb_intake.py`: compiler-independent parser
  roundtrips and negative controls;
- `tests/test_c_project.py`: real Clang capture/replay rejects duplicate
  keys even after a hostile actor recomputes the database and manifest
  digests.

The latter integrated tests have not run against the final source
candidate in this current local container. Do not infer broader C ABI
or pointer ownership properties from passing intake tests.

## Reproduce

    python -m unittest tests.test_compdb_intake -v
    python -m unittest tests.test_c_project -v
    python -m unittest discover -s tests -v

Scope limitations remain: only explicitly listed build configurations,
hosted 64-bit C profile, and a restricted safe migration subset. Full
C/C++ language coverage, arbitrary pointer provenance, FFI allocation/
lifetime guarantees and inter-target equivalence are not established.

Keep `whole_project_blockers_closed=false`.
