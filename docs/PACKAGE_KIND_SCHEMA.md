# Package kind schema diagnostics

The `kind` field in `[package]` accepts only the strings `"bin"` and `"lib"`.
Omitting it selects `"bin"`. The respective default entry paths remain
`src/main.hepta` and `src/lib.hepta`.

All other TOML values reject with package-phase `E_PACKAGE_SCHEMA` and the
message `Package kind must be bin or lib`, attributed to the manifest that
contains the invalid value. Arrays and tables must produce this diagnostic,
just like unsupported strings and scalar types. They must not escape as a
Python `TypeError` when membership in the allowed set is checked.

This validation happens after package name/version and unsupported-key checks,
and before source paths, entry-file existence and dependency declarations.
The order and messages of those existing checks are unchanged. An invalid
kind in a dependency is attributed to that dependency's manifest. A valid
`"bin"` dependency still rejects separately because dependencies must be
libraries.

`hepta check` and `hepta inspect` with `--frontend-only --json`, and `hepta lock`,
return one machine-readable rejection with exit status 1 for invalid container
kinds, rather than a traceback on standard error. For check/inspect this holds
for directory, manifest and direct-source entrypoints.

## Focused reproduction and validation

Run from the repository root:

```sh
python -m unittest discover -s tests -p test_package_kind_schema.py -v
```

The ten methods cover invalid array/table spellings, every TOML scalar category,
unsupported strings, existing diagnostic precedence, dependency attribution,
default entry selection, fourteen actual CLI invocations and valid content-lock
round trips. All fixtures are temporary; the tests do not compile or execute
Hepta programs, launch models, invoke native compilers or change release gates.

On original main `125d11c5454835a7df1dc51915fc49901fbede5b`, the same ten methods
produce fourteen failure records and fourteen error records. Those records are
nested subcases, not twenty-eight independent methods. The repaired suite
passes all ten methods with no skips on local Python 3.12 and 3.13. The dedicated
PR workflow checks the exact head on Python 3.11 and 3.13; its hosted status must
be read separately and is not implied by local results.

This is a narrow package diagnostic fix. It does not qualify the whole package
loader, prove language soundness, extend the supported manifest schema, or
close the broad production/research blockers. Main is not merged by this change.
