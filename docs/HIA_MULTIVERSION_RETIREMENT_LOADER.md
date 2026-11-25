# Native multiversion retirement loader diagnostics

This component preserves the actual loader failure from the same retirement attempt. It does not claim completion of the full public multiversion runtime.

Before dlclose, the fixed mechanical adapter resolves dlerror with dlsym. After a failed close it calls that saved function immediately. HIA captures the returned bytes with actual process_vm_readv, before any later loader operation can replace the thread-local error. The fixed runtime import domain remains dlopen, dlsym, dlclose, malloc, and free.

The original _ctypes.dlclose error is OSError with errno=None. Its text uses UTF-8 with surrogateescape; the original retirement report retains the first 1024 Unicode characters. A 4096-byte prefix suffices for those characters. Invalid bytes each become one surrogate character. The native owner stores that bounded text as WTF-8, and the qualified snapshot renderer produces the original ASCII-escaped JSON. Empty loader text is a captured empty message. A missing error function, null error pointer, or failed actual read remains an explicit capture failure and never becomes an invented errno error.

The original HIAMVRT1 and diagnostic HIAMVRT2 requests retain their exact output extents and zero reserved tails. The new private HIAMVRT3 request uses the same 24-byte request and 768-byte reply. Reply offsets 736, 744, 752, and 760 contain message byte length, capture status, raw prefix length, and actual copy failure respectively. Captured text is retained with the generation holder. The public BG provider wire is unchanged.

## Ownership and failed release

A library close is attempted once. A failed library close does not prevent the independent native fd close. The original uncertain library handle remains charged to the same generation and pending retirement. Repeated query, cleanup, and last-reference finalization never retry it. The runtime context cannot be destroyed while that uncertainty is retained. A publication already committed before retirement failure keeps its selected generation and the same Future commit marker.

## Qualification

The machine-readable companion contains every source and image pin, all 13 actual qualification reports, and the exact new development QA programs.

- 77,921 pure native decoding/truncation calls compare against fresh Python surrogateescape results, including every two-byte word and the 1024-character boundary.
- 16 actual original/native loader cases include invalid UTF-8, incomplete sequences, long messages, guard pages, replaced thread-local storage, and concurrent independent threads.
- The original attestation, retirement, private guard, and syscall-fault suites pass with the new same-holder image.
- Six complete provider suites pass: actual construction and publication, concurrency, real allocation faults, native pack/link bounds, original entry-clock budget behavior, and the original runtime effect comparison.
- Eight additional whole-provider checks exercise actual original/native dlclose failure during publication. The second generation remains committed; the first generation keeps the real error, closes its independent fd, stays pending, and prevents context destruction after last drop.

The fixed provider image is 8,049,424 bytes, SHA256 be9663e24e50b9103c27c10b251ef09bb511a0e9c52d0024de2c93d3e79cca5a. Full public snapshot/history capture, the remaining original dependency exception mapping, and final aggregate qualification are still open.
