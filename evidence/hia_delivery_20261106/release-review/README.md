# HIA candidate release audit: three reproduced findings

The `before/` directory preserves the source of the builder, verifier, release tests and release document inspected before the fixes. The builder snapshot was restored by reversing only this audit's initial edits before saving it; its original 203-line length was checked. The verifier and other files were copied before editing.

`reproduce_before.py` runs the saved builder/verifier against a temporary, independently committed copy of the HIA modules and two fixtures from a supplied checkout. It leaves the supplied checkout and its caches untouched.

```sh
python reproduce_before.py --source-root /path/to/Hepta --output before-observations.json
```

`before-observations.json` records an actual completed run:

1. A valid timestamp `.pyc` changed the imported route inventory. Two clean candidates had the same source seal and version but different wheels.
2. A resealed manifest and wheel accepted an unknown manifest field, a production qualification claim set to true, and an undeclared console entry. This tests schema and source/metadata consistency; it does not claim to bypass a separately trusted manifest hash.
3. The original pinned bundle still passed installed verification after a test hook changed a nested installed Python module. The previous top-level compiler hash did not cover that nested module.

The fixed regression suite supplies these counterexamples, plus installed data drift and a second integrity check after smoke execution. The fixes use a fresh empty cache prefix, exact manifest field/type and false-claim checks, source-bound wheel metadata using the delivered pyproject.toml, and independent complete installed package checks before and after execution.

`fixed-regressions.log` records 27 successful tests with no skips: 19 candidate release tests and 8 delivery gate tests. `fixed-source-sha256.json` identifies the four edited source files at that successful verification point. The root agent will separately run the final clean candidate/native qualification; this audit log does not claim native cross-target execution.
