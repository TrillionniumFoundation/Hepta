# Reviewable JSON fragment format

Each dataset INDEX.json binds the exact original file bytes with SHA-256 and lists ordered JSONL parts with their bytes, SHA-256 and record count. No experiment is executed while packaging or inspecting.

Canonical JSON is UTF-8 encoding of Python json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False), with no trailing newline. This is a defined local convention, not a claim of RFC 8785 conformance. The raw file digest separately preserves original whitespace and numeric spelling.

Each JSONL record uses an RFC 6901 escaped pointer. A value record supplies a complete subtree. An object record lists its original keys; an array record supplies its length. Their child records use the corresponding pointer plus escaped key or decimal index. A string record supplies character count and part count; string_part records at that pointer supply indexed string segments. Root pointer is the empty string. Each non-string-part pointer occurs once. Part order in INDEX.json is the packaging order; recorded array indices preserve original observation order.

For JSONL source files, the reconstructed value is the ordered array of their parsed nonempty lines. The filecheck differential and maintenance input ledgers are complete. For normal JSON files, the reconstructed value is their root JSON value.

Three qualification reports are complete JSON values. The C++ report has exactly two documented omissions: /variants/0/migration/standard_library_declarations and /variants/1/migration/standard_library_declarations. Its retained digest covers the report with those keys deleted. Each deleted array's count and canonical digest are recorded. The original canonical digest also binds the full original report including those arrays; the original raw SHA-256 binds the exact source file. The full raw archive is required to recover omitted arrays. No omitted field is silently represented as an empty list or zero.

Run inspect_evidence.py from any directory with Python to check all retained content and indexed files. With --output DATASET PATH it also writes the reconstructed retained JSON value for inspection. This is a file-format audit only. It does not load project code, invoke a compiler, execute a native artifact, select a performance winner or create a new experiment result.
