# Filecheck: a complete, small file checksum application

`checksum.c` and `chunk.c` implement a two-translation-unit component with an
LP64 scalar C ABI. The application reads an actual file, packs groups of up to
eight bytes, and computes an IEEE CRC-32 or Castagnoli CRC-32C checksum. The
component owns and releases the byte array used for each group. Both original
implementation bodies are structurally migrated through Clang capture, checked
Hepta source, independent HIA Core, and direct LLVM code generation.

This is a new, deliberately small component authored for this repository. It is
not evidence that an existing large application or a C++ standard library has
been migrated. The byte-at-a-time CRC algorithm and per-group allocation are
deliberately the same in the C, independent C++ RAII, independent safe Rust,
and HIA comparisons. A table-based or hardware CRC implementation is a different
algorithm and can be substantially faster. No result is a best-available CRC
claim. C++ and Rust are performance references, not translated source routes.

`app_driver.c` remains host code. It owns file I/O, packing, dynamic loading,
request-boundary switching, timing, and error reporting. It calls an identical
scalar ABI in every route; no foreign pointer is passed to HIA. Measurements
include this common application work, with batch latencies reported as batches
of at most 4096 bytes, not individual end-user request percentiles. The shared
library boundary prevents cross-boundary inlining in every route. Peak RSS is
for the entire process, not a precise owner-byte measurement.

The declared failure policy is return without changing the caller's checksum
state. An allocation failure is observed separately using real linker wrappers
on the original C and generated HIA objects. Rust/C++ allocator internals are
not equated to those wrappers. Files larger than available memory can still be
processed with a bounded 4096-byte host buffer; stream state is a scalar.

`tools/qualify_hia_filecheck.py` captures the build, retains generated source and
Core, tests differential execution and resource events, performs a deterministic
maintenance change, builds LTO/PGO references, and executes the frozen protocol.
It records actual costs and failures without an automatic retry or sample
exclusion. This supplies a useful complete vertical slice; source refinement,
general C/C++ migration, universal speedup, and lower human migration cost remain
unproved. The dynamic loader experiment is a local harness experiment, not an
NDU deployment grant or a process isolation boundary.
