# Native serde Value canonical JSON

`examples/hia_bootstrap/mcp_canonical.hepta` implements the pinned
`serde_json::Value` interpretation and compact serialization. It is a pure HIA
component; the syscall owners decide which inputs use a Value profile and which
use an independently typed struct profile.

## Value rules

Decoded object keys sort by UTF-8 bytes. Repeated decoded keys retain their last
value, including nested objects, escaped spellings of the same key, empty keys,
and embedded NUL. The existing stable merge sort preserves the source order of
equal keys; HIA then relinks the final member of each equal run.

Every input value is validated before a duplicate is discarded. For example,
`{"x":1e400,"x":0}` is rejected, because the first value cannot be represented
by the pinned finite binary64 number profile. Invalid Unicode and excessive
nesting in discarded values also remain errors. Signed and unsigned integers,
floating negative zero, decimal conversion and shortest decimal formatting
retain the existing exact number behavior.

The default standalone Value accepts at most 127 nested containers, matching
the original serde recursion budget. Callers that extract a Value from a typed
container must preserve the remaining original budget. The root Jobctl profile
therefore uses 126 levels for `Exit.scratch_cleanup` and 127 for a complete
retained-scratch Value.

These rules do not relax typed known-field duplicate rejection. In particular,
the typed job Record, Exit, Witness, Request and runtime configuration owners
keep their own original policies. An outer transport can also have an existing
independent admission rule; successfully canonicalizing a fragment does not
authorize bypassing that rule.

## Pure native ABI and resource bounds

The default six-argument flat entry takes input bytes, an exactly 8 MiB output
buffer, and an exactly 23,085,120-byte workspace. It returns the output byte
count or an existing error code above the output bound. Input remains bounded
by 8 MiB and the default arena contains at most 262,144 value nodes.

`source_program(maximum_nodes=..., maximum_depth=...)` permits a caller-specific
HIA image to allocate the original input domain while sharing the same
algorithm. Workspace size is `64 + maximum_nodes * 56 + 8 MiB + 16,384`.
Such a derived profile must independently qualify its caller's limits and ABI;
it must not silently shrink an existing file or request budget to fit the MCP
default arena.

## Qualification and retained counterexamples

`tools/qualify_hia_mcp_canonical.py` compares native bytes with an independently
compiled serde_json 1.0.151 oracle with `float_roundtrip` and `raw_value`, without
`arbitrary_precision`. The updated 618-case gate retains all previous number
coverage and adds duplicates at multiple depths, escaped equivalent keys,
overwritten invalid values, stable ordering, and recursion-limit neighbors.

The previous 572-case report explicitly assumed duplicate-free input. Its
duplicate-key refusal is not evidence for general Value behavior. The later
native/original mismatches and frozen source snapshots remain in the external
qualification record: repeated retained-scratch schema keys exposed the
duplicate gap; a 128-container Value exposed the recursion-limit gap. Neither
counterexample is removed or reclassified as a successful test of the old image.

Passing this pure component gate does not qualify the whole MCP server, its
typed envelopes, its durable job registry or its privileged system-job owner.
