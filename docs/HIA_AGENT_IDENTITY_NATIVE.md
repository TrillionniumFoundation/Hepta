# Selected HIA Agent scalar identity admission

This ordinary HIA Core application checks canonical decimal u64 values and
exact 64-byte lowercase ASCII hexadecimal digest strings. It does not compute
a digest or grant authorization. The high-level Hepta source language has been removed; this is a direct Core application.

`HEPTA_HIA_AGENT_IDENTITY_MANIFEST` selects a pinned Linux x86-64 native image.
The existing store sequence decoder and worker digest-format validator then
invoke HIA without reference numeric/regex fallback. A bad manifest or native
result fails closed. Ordinary worker discovery no longer eagerly imports the
foreign Rust-comparison module via macro advice; explicit native NDU calls
still reuse its unchanged bounded process pump and charge first-import time to
the original deadline. No selection leaves the existing reference route intact.

The host retains JSON/value-kind/ASCII transport checks and the 64-character
transport bound. Every in-profile digit, leading-zero, overflow and lowercase
hex decision is made by HIA; the reference code is not an equivalence oracle at
runtime. This is trusted immutable executable code, not a submitted-code sandbox.

## Byte ABI

The source is `examples/hia_bootstrap/agent_identity.hiaasm`, authored by
`tools/generate_hia_agent_identity.py`. Input is a 16-byte little-endian header
(`HIAIDP01`, operation u64), followed by at most 64 ASCII bytes. Operation zero
checks u64 decimal and returns its value; operation one checks digest grammar.
A 24-byte result (`HIAIDR01`, valid u64, parsed value u64) returns length 24.
Rejected scalar text produces valid=0/value=0; valid digest produces value=0.
Malformed input packet returns 0xfffffffd. Insufficient output returns
0xfffffffe without writing output. No scratch workspace is required or touched.

Build with `python -B -m tools.build_hia_agent_identity --compiler B3.image.bin
--cold-report cold.json --output NEW_DIRECTORY`. A complete matching cold
qualification and unchanged inputs are required before publishing a manifest.

Tests interpret three independent full result-byte witnesses before native
seed compilation, compare overflow boundaries and randomized integer oracles,
mutate all byte values, check canaries and concurrent owned calls, and execute
real store callers with both former Python predicates disabled.

## Remaining authority

JSON decoding/serialization, hash computation, worker report correlation,
authorization, filesystem and SQLite transactions, recovery and all other Agent
operations remain host-owned. This selected component is not full Agent
protocol replacement, native-only installation, production activation or
legacy-retirement qualification. Defaults and prior failed evidence remain.
