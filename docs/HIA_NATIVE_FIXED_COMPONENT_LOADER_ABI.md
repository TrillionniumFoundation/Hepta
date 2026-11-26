# Native fixed component loader ABI

## Qualification and scope

This component implements actual HIA policy for admission, native dynamic loading, borrowed image custody and observed image retirement. Its five-role standalone image has passed the 16 actual kernel/filesystem/concurrency groups recorded in HIA_NATIVE_FIXED_COMPONENT_LOADER_QUALIFICATION.json. Both native packer profiles have passed their original compiler and bounded packer gates.

The qualification fixture loads an actual previously qualified native recursive-directory cleanup DSO from a generated fixed catalog and invokes its real native export. It does not register Python callbacks or fabricate syscall, loader, mapping, borrow or retirement replies.

Final root composition, its prepare/BG catalog and child initialization remain separate unqualified integration work. The fixed catalog in this component qualification is a test catalog. No production claim is derived from its four test entries.

## Six-word entry and stable work

The export is hia_native_fixed_component_loader. Its six arguments are input pointer/length, output pointer/length and work pointer/length. Input is exactly 128 bytes, output is at least 131072 bytes, and work is exactly 26214400 bytes (25 MiB). Work begins zeroed and remains at the same actual address in the same process until a true retirement acknowledgement. Its image binding is captured from the entry's own RIP; it is not supplied by a request.

The mechanical prefix validates wire shape, non-null non-overlapping spans, integer overflow, work alignment and an existing context's PID/address/fixed entry before output writes. The HIA mutex protects state, native capability lists and the reply snapshot. Waiters use real 10 ms FUTEX_WAIT_PRIVATE timeouts and retry actual CAS; a failed wake cannot indefinitely strand a waiter.

## Request HIANLCQ1

Every field is little-endian u64. Unlisted fields must be zero.

| Offset | Meaning |
| --- | --- |
| 0 | ASCII HIANLCQ1 |
| 8 | Operation 0 through 4 |
| 16 | Reviewed fixed catalog ID, only for operation 0 |
| 24, 32, 40 | Actual borrowed capability triple, only for operation 3 |

| Operation | Meaning |
| --- | --- |
| 0 | Admit and load the fixed catalog entry. A context can be initialized once. |
| 1 | Close. Live borrowed capabilities return busy without consuming them or changing ready state. |
| 2 | Create an actual independent image borrow. |
| 3 | Consume one actual image borrow. |
| 4 | Retry known pending native capability or close cleanup. |

Requests carry no file path, digest, export name, function pointer, child context pointer or authority flag. A caller cannot select a different native role.

## Reply HIANLCR1

| Offset | Meaning |
| --- | --- |
| 0 | ASCII HIANLCR1 |
| 8 | Status |
| 16 | Context state |
| 24, 32, 40 | Newly delivered borrow capability; zero unless delivered |
| 48 | Export count when a borrow is delivered |
| 56 | Borrowed actual source-directory FD when a borrow is delivered |
| 64 through 79 | Zero |
| 80 | Pending flag |
| 88 | Ownership-known flag |
| 96 | Operation consumed/delivered flag |
| 104 | Context retired flag |
| 112 | Actual error detail, including the raw negative syscall return where applicable |
| 120 | Borrow count captured under the same native mutex |
| 128 onward | Actual fixed export addresses, only on borrow delivery |

Statuses are 0 success, 1 actual system/cleanup error, 2 artifact identity or digest mismatch, 3 fixed catalog failure, 4 native loading/export/mapping rejection, 5 unknown custody quarantine, 6 busy, 7 unknown/wrong/stale borrow, 8 context/state rejection and 9 allocation/size failure. A malformed top-level wire or mechanical span returns 0xfffffffd without a public reply.

States are 1 loading, 2 ready, 3 closing, 4 retired and 5 quarantined. A returned status is not an ownership acknowledgement by itself. The enclosing owner must keep context, image and any already delivered capability according to the separate known/consumed/pending/retired facts.

A successful borrow is held by a native mmap-backed list node with an actual getrandom nonce and owner/PID identity. User pointers are compared to owned-list addresses before dereference. Drop unlinks a capability only once; a failing munmap retains its actual pending node for operation 4. A stale second drop never consumes it again.

## Admission and installed source custody

The loader calls its fixed catalog role. The reviewed catalog supplies a fixed relative artifact name, fixed relative source-directory name, exact byte length, SHA-256 and ordered export names.

It obtains the fixed loader image's real origin through dlsym(NULL, "dladdr") and dladdr on its own native entry. The installation directory and fixed source directory are opened as actual directory FDs. The catalog artifact is captured by the existing native clang_stable_file role with exact stable-file identity and full bytes, then compared with the catalog length and digest.

The captured bytes are written to an actual memfd. The loader adds and verifies the complete seal set, verifies regular file/zero link count/length, reads the sealed bytes back and hashes them using the same fixed SHA-256 role. Only then does it call dlopen. Each catalog export is obtained through dlsym and checked against a real /proc/self/maps snapshot by the existing native_mapping role, matching executable permissions, device, inode and file bounds of that owned sealed memfd.

The source-directory FD is independent of the memfd pathname. It survives renaming of the original source directory while the image borrow is live. A child such as Clang must take its own native strong FD through its private B2 initializer before the parent releases its borrow. In particular, a sealed child must not derive its installation source directory from its own /proc/self/fd image name.

This entry must itself be statically bound into the installed root image, or loaded from its real installed location during trusted initialization. Loading this loader itself from an unnamed sealed memfd does not establish an installation origin and is not qualified. The root must capture child installation custody before exposing user work that could invalidate a relative origin. Final root initialization and relocation domains require their own gates.

## Retirement and uncertainty

The loader refuses close while any actual image borrow is live. The parent must retain its borrow until every child holder, execution and retirement continuation has completed; the loader cannot infer a child-specific in-flight call from an exported pointer.

On close, dlclose is performed at most once for the current owned handle. A zero dlclose return does not prove kernel mappings were removed. Before closing the memfd, HIA reads actual /proc/self/maps again and compares every row's device/inode to the still-owned memfd. An actual maps-open/read failure retains known pending state and operation 4 retries that observation without calling dlclose again.

If the actual image remains mapped after dlclose, the context is quarantined and retired stays false. The kernel fault gate demonstrates this case by denying ld's actual munmap: libc still returns successful dlclose, but the loader detects the surviving mapping and does not issue a false retirement acknowledgement.

Known close_range failures retain actual descriptors for retry. ENOSYS uses the existing close fallback. A failing fallback close has ambiguous consumption; the FD number is not blindly retried, and the context remains unknown/pending. Uncertain native loader or capture acknowledgements are similarly quarantined. Such a context is not reusable and must not be freed on a fabricated success.

Only actual complete cleanup produces ready-to-release state 4, known 1, pending 0 and retired 1. Closing or retrying an already retired authentic context repeats that acknowledgement.

## Native packaging

HIANLCP1 retains five fixed roles in this order:

1. native_fixed_component_loader
2. generated native_fixed_component_catalog
3. clang_stable_file
4. sha256_stream
5. native_mapping

Its header is 56 bytes: magic, count 5 and five lengths. All native role images retain the existing 4 MiB role limit and the complete .text retains the existing 16 MiB limit. The only dynamic imports are dlopen, dlsym and dlclose.

The new HIANLCP2 profile uses three roles (loader, catalog, stable) with a 40-byte header and count 3. It has two additional fixed ELF imports for the enclosing native fusion:

| Fixed import | Exact shared native role |
| --- | --- |
| hia_root_sha256_stream | 33264 bytes; SHA-256 d18077e7a13f00859e61101cf487ae579def62df2f5288066dfbb305ae386bfc |
| hia_root_native_mapping | 80848 bytes; SHA-256 39b2175453bda3f81ce233c5fe31290e22e0d6f83b69fd57c46d396a6cf895f3 |

These imports are resolved statically to the parent's actual existing role bodies. They are not libc dynamic lookups and cannot come from a request. The thin native object is 363440 bytes with 362396 bytes of .text. Actual native pack plus independent mechanical resolution against the exact shared bodies reproduces the entire already tested standalone .text byte for byte, saving 114116 bytes of duplicate text. Final same-root relocation remains an explicit integration gate.

Development Python authors and qualifiers are provenance and test tools. Production admission, catalog selection, stable capture, hashing, seals, mapping checks, borrow accounting, retry and retirement policy execute as native HIA. Author and test paths must not become runtime source-authority dependencies.
