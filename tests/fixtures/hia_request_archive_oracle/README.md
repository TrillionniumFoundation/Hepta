# Complete original archive / usage reference

`reference-project.json.gz` expands to the exact 605121-byte reconstruction
packet used on the Mac observer, SHA256
`defdc8c4fff2a0fac494640b2ae7082e328ee0104a734307a03adc24b245155b`.
Its `production` map contains 18 whole files from Runtime
`ae1c7ea593da45f7299c692a2acd44605c35be09`; `files` contains the complete
manifest, original lock, configuration fixture, exact eligible-tool extraction,
main and observer. Materialize both maps by their relative paths. Preserve a
copy of each production source under `original/`, and append only
`include!("request_archive_observer.rs");` to `src/mcp/runtime/request_audit.rs`.
No original archive/query implementation or assertion is rewritten.

The recorded toolchain is Rust 1.96.1 on aarch64-apple-darwin. Build with Cargo
using the supplied original lock and the exact package versions; the receipt
records that all active registry versions/checksums are unchanged. The original
build uses the ordinary development unwind profile, which exposes the actual
metadata projection panic/poison behavior. It does not claim a full Runtime
release build or a panic-abort qualification.

`cases-v1.json` is the exact input set, SHA256
`86feb3e773333491365c8d279c9ffad59da7ca236a162af0247a57a616d870c8`.
Each fixture is sent to a new reference process. Record JSON is stored as text
so full u128 values survive transfer without JavaScript number conversion.
`observations-v2.json` retains 11 fixtures, 46 queries and two fresh runs per
fixture. Compare the `text` and error fields directly; elapsed time is an
observation, not part of the semantic equality check.

The first four fixtures completed with macOS soft RLIMIT_NOFILE 256. The first
attempt at a 256-shard layout then failed during fixture setup, before a query.
The remaining seven were run with explicit soft RLIMIT_NOFILE 1024, preserving
that failure and keeping the production query deadline at three seconds.

Native archive controls compare 34 archive queries. The live-registry fixture
is covered separately by a real native kernel ticket; its Rust Weak registry is
not fabricated in the public service. Eleven usage queries remain original
reference observations for the following native usage component. They are not
evidence that native usage already exists.
