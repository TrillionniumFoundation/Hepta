# Native mutable values and classes: actual qualification

The complete ten-role value image is constructed from HIA sources with the captured native compiler and the native HIA packer. The qualified image for this checkpoint is 1,580,944 bytes with SHA-256 `54d89c801840bef61e2eaff0fdb59f7e0e943ed5b74dcf53d437a5c140cf3a82`.

## CPython 3.14 dictionary order

The original mutation oracle on the target is CPython 3.14.4. Its dictionary insertion first looks up the key. Unicode-table conversion is needed only for insertion of a missing non-exact-string key. Overwriting an existing equal key does not compact the table and does not move a live iterator's raw cursor.

The earlier development comparison used CPython 3.12 and did not establish this 3.14 behavior. The first actual native mismatch and the identical development-author mismatch are retained in the machine-readable evidence. The correction moves the actual lookup before the conversion decision. Missing-key conversion remains in its separate resumable phase so persistent allocation failure cannot reset its retry state.

The actual native image passes 164 iterator groups and all 3,120 next-result comparisons. The development-author run additionally covers eight allocation-failure controls; those eight are not counted as native qualification here.

## Actual lifetime and compatibility evidence

The new Q02 cleanup profile passes the 11-group qualification, including the private kernel-fixture check, original and extended request guards, captured PID, concurrent final references, and actual `munmap` failure/retry for anchors, context tokens and value references. The old Q01 failure behavior is preserved. The fault fixture binds syscall number, arena address, extent and actual native syscall instruction pointer; unrelated libc allocations that reuse a released address are outside that mediation.

The original six complete value campaigns pass on this image: private request domains, independent context tokens, actual Linux ENOMEM, mutations/concurrency, import/export and large values. Their cases and budgets are unchanged; only image path, image hash and new evidence destinations differ. The large campaign includes the 96 MiB decimal, 64 MiB plus one byte object, all Unicode code points and 262,144 independently owned children.

The class/MRO component passes 273 actual groups including C3 acceptance/refusal, actual class identity, live namespace lookup, rename and graph collection. These component results do not close the complete public Path, callable, dynamic bases, ScalarMultiversionRuntime or BackgroundOptimizer APIs.

## Construction and evidence

[HIA_NATIVE_VALUE_CLASSES_QUALIFICATION.json](HIA_NATIVE_VALUE_CLASSES_QUALIFICATION.json) contains exact source/image pins, both core compilations, the native packaging receipt, original reports, failure provenance and the remaining open boundaries. The production path does not invoke the Python development authors or test harnesses.
