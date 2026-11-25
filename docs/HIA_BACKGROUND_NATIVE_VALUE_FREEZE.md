# Native checked freezing of owned values

The private six-word `hia_background_value_freeze` owner performs the complete internal chain: actual value capability → native lossless sealed stream → fresh native owned-JSON capture → checked sorted freezer → actual immutable payload capability. The controller still performs the original structural admission at its original point. This owner adds no aggregate byte, node, depth, integer, or payload domain limit. Public Future results remain shared mutable objects.

## Captured context and request

Input is exactly 128 bytes: `HIABFZQ1`, operation at 8, and the actual value capability at 24/32/40. Operation 0 freezes a value; operation 1 resumes quarantined cleanup without repeating completed semantic work and uses a zero capability. All unused input fields are zero.

The private output view is at least 262144 bytes and the exclusive per-call context is at least 2048 bytes. Context header:

| Offset | Actual captured field |
| --- | --- |
| 0 | HIABFZC1 |
| 8 / 16 / 24 | Value entry / context / extent |
| 32 | Qualified lossless value transport entry |
| 40 | Qualified owned-JSON capture entry |
| 48 | Qualified checked sorted-freezer entry |
| 56 / 64 / 72 | Immutable payload entry / context / extent |
| 80 | Captured original int-string conversion policy |
| 88 / 96 | Native actual PID / retained-cleanup marker |

Bytes 104 through 127 are zero. The rest of the context is private native cleanup ownership. Function pointers and contexts are fixed captured composition dependencies, never authority supplied in a public user request. The value and payload context records remain strongly owned for the entire call and any cleanup retry.

## Reply

`HIABFZR1` is the 128-byte reply header. Status at 8 is 0 for a frozen payload, 1 for the original checked-freezer exception, 5 for allocation failure, 6 for lifecycle/PID refusal, 7 for a failed dependency, 8 for an OS error, or 9 for a private invariant/retained-cleanup failure.

Success returns an owned immutable payload capability at 16/24/32 and full byte length at 40. The caller owns that independent reference. Original conversion errors return their complete class/message JSON at byte 128, with its length at 48; Unicode character count, start, end, and code point are preserved at 72/80/88/96. Cleanup flag is at 56 and dependency/system detail at 64.

Malformed private views and frames return 0xfffffffd without changing the public reply. A normal call is refused while retained cleanup exists. Operation 1 resumes cleanup from the native context; it does not repeat payload creation, capture, or freezing. A delayed success may return the original still-owned payload after resources are safely released.

## Ownership and original ordering

The HIA policy maps the actual sealed stream, uses the capture's actual size pass to allocate a fresh arena/workspace, and allocates the exact sorted output. The completed output is copied into the actual immutable-payload owner. Every mapping and FD is released before normal return. Failed reference cleanup remains explicitly owned and blocks fresh work until retried.

The stream never applies integer-digit, finite-number, or UTF-8 policy prematurely. The checked freezer retains sorted numeric/conversion error precedence before final UTF-8 encoding. Its configured digit policy is captured by the composition owner; a public submission cannot override it.

## Actual qualification

The fixed native owner passed 226 end-to-end original comparisons, including 9 MiB streams, wide values, 100001-digit numbers, nonfinite values, raw WTF-8 strings, competing conversion errors, exact Unicode spans, and detached payload survival after all original value references are dropped.

Sixteen control groups passed: six actual allocator failures in the stream/payload owners; four real kernel ENOMEM mapping boundaries using measured native capture sizes; actual partial-write EFBIG; both input-reference and newly-created payload cleanup quarantine/retry; dependency rejection; and the complete private frame/view domain. The HIA packer passed 24 controls. Policy was compiled twice by the native compiler with byte-identical results; HIA packer and HIA shared linker produced the image.

Exact source/product/evidence pins are in the companion JSON. This closes the fixed freezing component. The BackgroundOptimizer public controller and worker pipeline remain separate work.
