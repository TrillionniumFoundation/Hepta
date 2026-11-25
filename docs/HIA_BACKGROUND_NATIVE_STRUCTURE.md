# Native background JSON structure admission

This leaf implements the original hia_program._structure traversal on a
fresh, owned JSON arena or one of its subtrees. The public owner must capture
the input and its original type before this leaf. Foreign class handling,
mutable-container capture and cycle detection remain at that typed boundary.
This qualification is not whole BackgroundOptimizer or whole rank closure.

The exact original budgets remain 8,388,608 canonical UTF-8 bytes, 262,144
visited or queued nodes, and depth 64. Dictionary keys are counted before
values; values are visited right to left. The selected subtree starts at
depth zero. No 8 MiB limit is added to the raw transport containing whitespace
or a larger enclosing tree.

## Fixed private ABI

The six-word entry receives three disjoint views. Input is HIABST01 followed
by fifteen little-endian u64 words, then the exact raw JSON, complete fresh
72-byte-node arena, and the captured mathematical threshold source.

| Offset | Meaning |
| --- | --- |
| 0 | HIABST01 |
| 8 | Selected root node |
| 16 | Raw JSON bytes |
| 24 | Complete arena bytes |
| 32 | Threshold bytes, exactly 10,100,891 |
| 40 | Actually captured integer-string conversion policy |
| 48 through 127 | Zero |
| 128 onward | Raw JSON, arena, threshold |

The arena has the already-qualified size-derived JSON format. All topology,
spans, metadata and complete u64 lengths are checked. Workspace is at least
4,202,496 plus the full arena node count; output is at least 512 bytes.
Initialization writes every live field and supports poisoned workspace.
The output/header workspace and the immutable input do not alias.

Conversion policy is 0 for an explicitly configured unlimited policy or an
integer from 640 through 2,147,483,647. The current original host default is
4,300. The native public owner fills this field from its real captured
configuration; a submit/rank caller cannot claim a different policy.
Unbounded decimal generation/epoch/accounting owners remain unbounded.
This policy applies only where the original code converts an integer to text.

The exact order is bit_length > 33,554,432, then the configured str(int)
conversion limit, then the existing JSON byte budget. The threshold source
is decimal 2^33554432. Its SHA-256 is
735f15939ea8fbf91283013a1719773d01018683e1fdb417c3f18ce22f2f1706.
It is named examples/hia_bootstrap/background_optimizer_integer_threshold.hiadat.
It must be captured and bound as algorithm data together with the HIA source;
arbitrary caller bytes do not become threshold authority. Production does
not use GMP or Python. The development generator constructs the exact integer
and independently checks its modular decimal tail.

Ordinary shorter integers only take the decimal-length branches. Only the
10,100,891-digit boundary compares the whole threshold. Positive and negative
threshold-minus-one, threshold, and threshold-plus-one were all tested under
both the default and explicit unlimited conversion policies.

## Result

Native return zero produces HIABSR01 in the 128-byte output header. A
malformed private request returns 0xfffffffd without publishing a header.

| Offset | Meaning |
| --- | --- |
| 0 | HIABSR01 |
| 8 | 0 accepted, 1 original semantic exception |
| 16 | Error identifier |
| 24 | Nodes actually visited |
| 32 | Canonical bytes accounted before the result |
| 40 | Error JSON bytes |
| 48 | Last visited depth |
| 56 | Remaining private stack entries |
| 64 through 127 | Zero |
| 128 onward | Complete canonical exception JSON |

Accepted output reports the original complete _structure byte count.
Semantic failures preserve the original exception class and message.
Identifiers 1 through 8 name the original structural, queued-node, cycle,
key-type, value-type, surrogate, byte and integer-bit budget errors.
Cycle/key-class errors are reserved for the typed boundary because a fresh
parser arena is already a tree with string keys.

Identifier 9 is ValueError with the dynamically rendered configured limit:
Exceeds the limit (N digits) for integer string conversion; use
sys.set_int_max_str_digits() to increase the limit.
It is not converted into HIAProgramRejected or a generic source rejection.

## Actual construction and qualification

The generated HIA was compiled twice by the captured native source compiler
with an empty PATH and sealed executable descriptors. Both 151,614-byte
outputs were identical:
501694a31b52ec095f31a6e650e1ca15f7c0999c1cee62c6afcbe077a838afde.

The sealed native role passed 871 fresh original comparisons and private
guards. They include 400 random trees, 263 Unicode cases, 39 subtrees, 8 depth
controls, 17 actual large byte/node/ordering cases, 82 conversion-policy
cases, 12 exact mathematical-threshold cases, 6 owned Unicode-span controls
and 26 private-frame/capacity refusals. Ordinary scalar cases make up the
remaining 18. The parser used for fresh arenas is the already-qualified
native size-derived decoder, not the Python JSON decoder.

The private Unicode-span controls explicitly distinguish the typed owner's
decoded string representation from JSON text syntax: the syntax decoder
refuses lone surrogate escapes, while the structure leaf preserves the
original surrogate-versus-byte-budget order for an owned decoded span.

HIA_BACKGROUND_NATIVE_STRUCTURE.json records complete actual source,
construction, output and report pins. Earlier author-only syntax failures
are retained in the external v1/v2 construction directories. No limit,
original test, syntax check or source-capture requirement was weakened.
