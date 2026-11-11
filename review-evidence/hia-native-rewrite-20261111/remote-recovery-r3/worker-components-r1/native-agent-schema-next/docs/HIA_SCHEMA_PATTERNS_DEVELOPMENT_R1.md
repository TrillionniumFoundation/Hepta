# Native Worker schema pattern owner — new development revision 1

No generation, bounded compile or actual image execution has run for these
new sources. The lost pre-interruption schema results are not inherited.

This component implements the exact five patterns present in the fixed 0ef
eleven-tool catalog and its complete workload, objective, cost-policy and
machine-plan schemas. Generation inventories all eleven input/output schemas
and all ten named schema constants and requires exact set equality. It is not
a general regex engine, a replacement for arbitrary caller-supplied schema
patterns, or the complete validate/check_vocabulary owner. Those APIs and the
remaining validator logic are explicitly open.

The schema owner supplies the actual pattern bytes from its immutable issued
schema, not a host-selected pattern ID. The kernel identifies the entire pattern
in HIA. Unknown patterns produce private BAD; they are never silently matched,
rejected as a user schema error, or sent to a hosted fallback.

## Exact matching

All five expressions start with ^ and end with $. Python re.search allows $
immediately before one final LF. The HIA kernel therefore removes precisely
one final byte 10 for matching, then checks the entire remaining ASCII profile.
It preserves empty-match behavior for the even-length lowercase-hex expression,
including the string consisting solely of one LF. Two LFs, CRLF, non-ASCII
digits, uppercase hex and any unallowed character keep their original results.
Lengths 192, 64, artifact-prefix plus 192, and 20 are regex constraints already
present in the original expressions, not new resource quotas.

The value view comes from an already issued Unicode string value. This kernel
does not re-run a raw JSON UTF-8 admission or confuse bytes with a string.
Private test inputs use surrogatepass bytes to cover strings containing isolated
surrogates; every non-ASCII byte is rejected by these ASCII-only expressions,
which is the same re.search result. General DataJSON's raw decoder and value
materializer retain their own earlier errors and budgets.

## Raw RWW ABI

Input bytes contain eight little-endian u64 words:
HIARXC01, private invocation lease, call sequence, pattern byte count, value byte
count, total exact extent, 0,0; followed by exact pattern UTF-8 and value bytes.

The fixed coordinator must supply the original immutable value/schema views.
Header numbers are correlation only, not authentication of external buffers.
There is no new total string-size limit. Existing upstream owner limits remain
at their original points.

The output requires 64 bytes and returns 64:
HIARXR01, same lease, same call sequence, matched (0/1), native identified pattern
ID (1..5), actual value bytes,0,0. Work bytes are unused. Invalid framing,
unsupported pattern or short output returns 0xfffffffd without publication.
This is stateless: there is no session poison claim. The caller retires a failed
invocation and does not interpret unchanged output as a new event.

## Proposed independent validation

compile_and_test_schema_patterns_ci_r1.py is an unexecuted new gate. It requires
the existing exact Worker restore directory, repository object store, and a new
output directory. It performs inventory, authoring, ordinary verification and
fresh historical f50 B3 compilation under the unchanged 10 CPU / 20 wall /
256 MiB compiler gate. It then runs the actual mapped image under the existing
90 CPU / 1 GiB native bound.

Proposed comparisons include every Latin-1 character in multiple positions,
selected Unicode/surrogate boundaries, all regex length edges, deterministic
mixed strings, final LF behavior, and full two-MiB hex strings. Every expected
result is independently computed by the original re.search outside the actual
native interval. The interval forbids host re.search and the old validate
entry. Framing and unsupported-pattern controls verify private BAD, complete
input readback and output/work canaries. Complete raw buffers and original
source/compiler/receipt pins are retained. No namespace effects, schema
completion, cold qualification or whole Worker claim follows from this gate.
