# Original request history oracle fixture

This is qualification data, not an installed runtime implementation.

The source projection in reference-project.tar.gz copies 27 production blocks
without edits from TrillionniumFoundation/hepta-runtime at
ae1c7ea593da45f7299c692a2acd44605c35be09. Its source-spans.json and original source
allow exact block verification. The two small observer entry points only seed
private fixtures, invoke the original code, capture its result, and expose the
real rmcp 3.9.0 parameter parser and Rust string Debug table.

Use Rust 1.96.1 and the included locked project to reproduce the reference.
All 103 registry dependency checksums matched the original Runtime lock.
The history observer takes a fresh, absent fixture directory as its sole
argument and one oracle-cases.jsonl record on stdin. Run each case in a fresh
process, twice: a deliberately overflowing selected time poisons the original
process-global store lock. Feeding the entire corpus into one process changes
that test condition. The history-params observer accepts the complete
params-cases-v2.jsonl stream and supports --debug-ranges.

oracle-cases.jsonl.gz expands byte-for-byte to SHA-256
8d9bac08b840dd160a6f20ea1f3d0364cbc1abcccf18d89fc6f8a13d63d2f0db.
Its original-observations.json contains the 37 equal paired observations.
For the native public qualifier, expand the case file to a fresh directory and
copy original-observations.json, oracle-params-schema.json,
params-cases-v2.jsonl and params-observations-v2.jsonl into that same directory.
Pass the expanded file with --cases and original-observations.json with --oracle.

JSONL records are separated by byte 0x0a. Unicode U+0085/U+2028/U+2029 inside
valid JSON strings are not record delimiters. The observed native comparison
keeps those characters intact.

The native service's explicit 1 MiB diagnostic-string bound returns a bounded
-32602 error above that size; matching original diagnostic text above that
bound is not claimed. The query's 32/128/512 and 64 KiB page limits are unchanged.
