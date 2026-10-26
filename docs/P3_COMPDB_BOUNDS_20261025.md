# P3 bounded Clang compilation database identity

2026-10-25. This work is stacked on PR #121 at exact base
b236d424ef8b155812cb014e20217403a2d28d3f. It modifies the existing
single c_project capture and replay authority; no separate migrator was
created. This is not a claim of universal C project migration.

## Before

The migration reader used unbounded Path.read_bytes + json.loads for its
compile_commands.json input at both capture and later identity revalidation.
Its 1–32 TU check was applied only AFTER JSON decode, so a malformed deeply
nested/huge JSON value could cause excessive time/memory or a parser error
before receiving a structured migration refusal. Duplicate keys and nonfinite
JSON constants were not explicitly refused at input.

## Now

hepta.c_project._read_compilation_database is shared by capture_project and
verify_capture. It enforces:
- 4,000,000 UTF-8 bytes maximum, read with a bounded stream.
- Strict duplicate-key rejection and rejection of NaN/Infinity.
- 1 to 32 explicit translation-unit configuration records.
- A finite iterative 65,536-node and 48-level JSON depth budget, 65,536
  characters per leaf and 256 characters per JSON key.
- Only records, lists and strings in the captured configuration shape;
  ambiguous primitive metadata is not silently promoted to compiler flags.

Remaining active flag analysis, actual Clang invocation, system/local header
dependency capture, full preprocessing and project input identity checks are
unchanged and stay under the same canonical c_project implementation.

## Tests

tests/test_c_compdb_bounds.py supplies valid direct input and rejects
duplicate fields, nonfinite constants, oversized bytes/string fields,
wrong JSON root, invalid encoding, malformed types and deep recursive
metadata. An optional real-Clang test verifies that replay uses the exact
same parser and rejects a formerly valid database changed to duplicate-key
JSON.

Run locally from the exact candidate checkout:

    python -m unittest tests.test_c_compdb_bounds tests.test_c_project -v

The integrated tests have been committed but have not been run in this
session on the complete source tree. No new C runtime ABI or universal
semantic equivalence claim is granted by successful parser rejection.

P3 full multi-TU pointer migration, all real build configurations, actual
C/C++ link/runtime ABI qualification, P1 general ownership/provenance,
P2 compiler port, P4 advanced C++ semantics, P5 whole-language backend,
P6 real Agent trials and P7 physical hardware all remain open/partial.
whole_project_blockers_closed stays false.
