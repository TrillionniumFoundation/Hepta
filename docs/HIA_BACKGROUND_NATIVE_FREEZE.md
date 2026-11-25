# Native checked JSON freezing

This pure role preserves checked canonical JSON conversion for an already
captured JSON subtree. It does not decide background admission and does not
replace the original structural gate. The full BackgroundOptimizer remains
unqualified until its real runtime, rank, worker, accounting and shutdown
composition passes the original tests.

## Construction and scope

The generated HIA source uses the existing canonical serializer, binary64
conversion and shortest formatting helpers. The independent native source
compiler constructs the flat twice; both products are byte identical. No
Python is used by the resulting role.

The capture owner supplies a matching raw buffer and fresh 72-byte arena.
The owner also captures the actual integer string conversion configuration.
The original host default is 4300; zero is an explicitly separate unlimited
configuration. An untrusted request cannot choose this policy.

The qualified scope is JSON-owned null, booleans, integers, binary64 numbers,
strings, arrays and string-keyed objects, plus separately identified private
typed arenas for nonfinite numbers and WTF-8 surrogate values. Arbitrary
foreign object classes, cycles, non-string dictionary keys and the ambient
Python recursion stack are public typed-capture responsibilities. Background
submission retains its original depth-64 structure gate before this role.

## ABI

Six SysV words describe three disjoint views: source, output and workspace.
All lengths and offsets are full unsigned 64-bit words.

The input is a 128-byte header followed by raw bytes and the complete arena:

| Offset | Meaning |
| --- | --- |
| 0 | `HIABJF01` |
| 8 | Action: 0 measure/check, 1 emit/check |
| 16 | Root node index within the complete arena |
| 24 | Raw input byte length |
| 32 | Complete arena byte length |
| 40 | Captured `int_max_str_digits`: 0 or 640 through 2147483647 |
| 48–120 | Zero |

Workspace is at least `max(131072, arena_bytes + 16384)`. Live state is
initialized on every call, including when workspace contains nonzero data.
No background byte, node or depth limit is imposed here. The original Core
and background limits are enforced by their own callers.

Output is a 128-byte header followed by canonical bytes or an error object:

| Offset | Meaning |
| --- | --- |
| 0 | `HIABJR01` |
| 8 | 0 success, 1 original conversion exception |
| 16 | 0 success; 1 integer conversion limit; 2 NaN; 3 positive infinity; 4 negative infinity; 5 Unicode encoding |
| 24 | Canonical byte length on success |
| 32 | Complete error JSON byte length |
| 40 | Unicode character count on success |
| 48 | First failing character index for Unicode errors |
| 56 | Exclusive end index for Unicode errors |
| 64 | First surrogate code point |
| 72–120 | Zero |

All semantic outcomes return native code 0. Private malformed frames return
`0xfffffffd`. Insufficient output returns `0xfffffffe` without partial
output. At least 128 output bytes are required. Measure calls with 1024
output bytes accommodate every complete error; actual errors require at
least 512 output bytes. On successful measurement, emit needs exactly
`128 + canonical_byte_length` bytes, including for small scalar values.

The error body is compact JSON with `type` and `message`. Its variable
fields are bounded textual renderings of a captured 31-bit conversion policy,
64-bit character indices, and a single 16-bit surrogate. No error truncation
or caller-provided verified result is used.

## Conversion order

Objects are traversed in sorted key order. Integer conversion and nonfinite
float exceptions occur during serialization in that order. Unicode encoding
errors occur only after serialization succeeds, as in the original
`json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False,
allow_nan=False).encode("utf-8")` path. Unicode indices count characters,
including non-ASCII characters and JSON escape syntax, rather than UTF-8
bytes. Negative integer zero canonicalizes to zero; binary64 negative zero
retains its original representation.

## Qualification

The source-bound JSON beside this document records both native compiles and
1253 original/native cases. These cover 400 binary64 values, 80 conversion
policy boundaries, sorted competing errors, 61 subtrees, 200 surrogate
controls, 150000 nodes, outputs exceeding 8 MiB, raw whitespace exceeding
8 MiB, poisoned workspace, input immutability and output atomicity.
The private typed cases are distinguished from actual native JSON decoder
cases; they do not claim that the public JSON parser accepts lone surrogates.
