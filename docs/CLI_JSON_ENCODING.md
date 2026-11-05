# CLI JSON transport encoding

CLI JSON reports escape non-ASCII characters with JSON's `\u` notation. Python's
JSON decoding recovers the original strings, including paths, diagnostic messages,
non-BMP characters represented by surrogate pairs, and Python filesystem
strings containing lone surrogates. ASCII report bytes, indentation, key order,
field names and exit-status contracts are unchanged.
Lone-surrogate compatibility is tested with Python's JSON decoder only; other
JSON implementations may reject those strings. This is not a cross-language
interoperability guarantee for such filesystem names.

This prevents output-encoding failures when stdout uses a narrow character set
such as ASCII or Windows-1252. Previously a successful `hepta lock` in a Unicode
directory could write `Hepta.lock` and then return `E_DRIVER`/exit 2 when printing
its result. Printing a structured rejection from an exception handler could
instead raise an unhandled `UnicodeEncodeError`, replacing the intended JSON
diagnostic with a traceback.

The fix changes only the shared CLI JSON serializer. It does not alter source
or lock encodings, compiler output files, manifest validation, hashing, program
semantics, or non-JSON `emit`/`run` output. It does not change stdout's codec or
claim support for arbitrary non-ASCII-compatible stream encodings, broken
pipes, output-device failures, or native-program byte streams.

## Focused validation

Run `python -B -m unittest discover -s tests -p test_cli_json_encoding.py -v`.
The ten methods cover strict ASCII, Windows-1252 and UTF-8 streams, nested
Unicode values and keys, lone-surrogate strings, unchanged ASCII formatting,
real CLI lock writes and repeatability, package and missing-manifest refusals,
an early driver error, frontend-only check/inspect success and stale-lock
refusal. Lock contents are read back and verified, and rejection controls
check the original diagnostic and exit status.

The suite uses owned temporary fixtures. It does not invoke a native compiler,
execute Hepta programs, apply patches, exercise filesystem aliases, or run
research, formal-proof, performance or release gates. Frontend-only success
remains explicitly incomplete validation, not native qualification. This
narrow transport repair does not close broad P0–P7 research blockers.
