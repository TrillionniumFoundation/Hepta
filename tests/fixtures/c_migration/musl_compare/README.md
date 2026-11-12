# musl 1.2.5 comparison component

`memcmp.c` and `bcmp.c` are complete, byte-for-byte copies of the generic source
files in the official musl 1.2.5 release. Together they contain 319 bytes and 16
source lines. `UPSTREAM.json` records the official archive URL and SHA-256, the
release tag commit and every retained upstream file hash. `COPYRIGHT` and
`UPSTREAM_README` are unchanged upstream files. The MIT terms apply to generated
derivatives, and the qualifier carries the full copyright file into each output.

This fixture is an explicitly selected source component. It does not include
the full libc, musl's generated build headers, alternate macro configurations,
architecture-specific string assembly, or the unselected string routines.

`platform/string.h` and `platform/strings.h` are authored qualification adapters,
not upstream musl headers. They bind the component's exact declarations and
`size_t` to the captured host model. Both original C compilers and the translator
use these same adapters. The two source files themselves are never edited.

`contracts.json` is also authored: each of the four input pointer parameters is
an initialized, live, read-only `unsigned char` view of `n` bytes. Read aliases,
including identical and partially overlapping input regions, are allowed.
Concurrent writes, uninitialized bytes, excessive lengths and invalid foreign
allocation provenance are outside that caller-supplied contract. The compiler
does not infer or prove these foreign pointer obligations.

Run `tools/qualify_c_musl_compare.py` from the repository root. Its new output
directory retains both `-O0` and `-O2` configurations, their actual build captures,
all generated sources and native artifacts, exact per-case input/result logs,
resource event observations and refusal reports. The full official release
archive may be independently downloaded from the URL in `UPSTREAM.json`; its
contents must match the frozen file hashes before using a different source copy.
