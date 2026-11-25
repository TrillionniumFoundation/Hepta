# Native Python string repr and KeyError messages

This pure component preserves CPython 3.14 string representation for the native background coordinator and shared result values. It does not qualify a complete BackgroundOptimizer, Future, ranker, or multiversion runtime.

## Behavior and source

The quote-selection and escape rules derive from the existing HIA CLI formatter: choose a single quote unless the string contains a single quote and no double quote; escape the selected quote and backslash; use the original tab/newline/carriage-return escapes; and render nonprintable characters with the original lowercase x/u or uppercase U prefix and lowercase hex digits. The CPython 3.14 / Unicode 16 printable ranges from tools/hia_cli_unicode_tables.json are embedded as literal words in the generated HIA source. That development table is not a runtime dependency. The Rust evaluator's Debug character table is not used.

Input is the exact UTF-8 / WTF-8 representation of a Python string. Lone surrogates remain individual code points and are escaped by repr. Malformed byte encodings are private framing errors. No aggregate 8 MiB string or result limit is added.

## Fixed six-word ABI

Input is HIABRP01 with a 64-byte header, followed by the actual string bytes:

| Offset | Value |
| --- | --- |
| 8 | Mode: 0 measures, 1 emits |
| 16 | Kind: 0 raw repr, 1 JSON string containing repr, 2 complete KeyError JSON |
| 24 | String byte length |
| 32–63 | Zero |

Output requires at least 64 bytes. Workspace requires at least 16,384 bytes. Input, output, and workspace are separate owned views. Both modes validate the complete source before writing output; mode 1 also checks the complete measured output extent before the first output byte.

A successful return is zero. HIABRR01 occupies output bytes 0–63: kind at 8, full required output byte length at 16, input Unicode code-point count at 24, selected quote at 32, and zero at 40–63. Mode 1 places all bytes at offset 64. Mode 0 exposes the exact allocation size and does not truncate.

Kind 2 emits the sorted, compact, UTF-8 JSON object with message equal to str(KeyError(the_actual_string)) and type equal to KeyError. It is suitable for the background worker's actual caught exception path. It does not reinterpret a canonical JSON representation as Python repr.

Private malformed input returns 4294967293; short output returns 4294967294. Both preserve output bytes.

## Actual qualification

The accompanying JSON records exact source and native pins, two byte-identical native compilations, and external report identities. The suite compares 1,813 actual native measure/emit cases against unchanged Python repr, JSON string rendering, and KeyError messages. This includes every one of the 1,114,112 Unicode code points (including all surrogates), random quote and character combinations, and an 8 MiB + 1 byte string. Twenty-two invalid encoding, header, and short-output controls verify atomic rejection. Source and surrounding output/work canaries are checked.

The character-class source file describes observed reference classes; the fresh native comparison supplies this component's qualification. No whole-runtime or release success is inferred from these tests.
