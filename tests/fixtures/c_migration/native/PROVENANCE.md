# Frozen in-repository C interop module

`native.c` and `native.h` are byte-for-byte copies of
`examples/interop/native.c` and `examples/interop/native.h` at Hepta commit
`d29a246cabaec5ddd8c5f6043b6b234b56ae8b67`. Their original Git blob identities are respectively
`b0218e98bda265e51f72f2aa5f555aa0fba362f5` and
`16122ca85d740b2e9db78b0bfc134decc275f15b`.

No third-party source was imported and no new license is assigned here. The
original files have no per-file license notice; repository ownership and any
applicable repository terms remain unchanged. The qualification harness checks
the recorded byte digests before migration and records them in its receipt.

This is an existing Hepta example module, not an independent production C
library or evidence that an arbitrary library can be migrated. The separately
stored slice contract is a caller-supplied annotation, not source inference.
The test corpus uses defined C arithmetic and initialized live buffers.
