# Native NDU execution owner

## Scope

This checkpoint supplies a fixed six-word HIA execution owner and a separate error renderer for the native NDU evaluator. The composed effects entry executes the policy, syscall effects, path resolver, bounded subprocess pump, source verification and post-execution verification. It does not create an additional business process around the evaluator. The only business child is the sealed evaluator image.

The evaluator's mathematical behavior and native build identity remain the earlier independently qualified leaf. This owner adds actual runtime custody, deadline accounting and exceptional cleanup. It is not a complete rank implementation, rank context, background optimizer, production registration or new cold-replay claim. The standalone `--source-root-fd` command is not part of this checkpoint: the production integration is the fixed six-word entry described here.

The accompanying JSON records actual selected source and image digests, native packer receipts and qualification reports. Failed intermediate evidence remains separate and is not relabelled as a pass.

## Entry and memory

The function convention is `(input_ptr, input_bytes, output_ptr, output_bytes, work_ptr, work_bytes)`. All extents use unsigned 64-bit values. The selected effects flat starts at offset zero, completes the full effect loop, and returns zero with a 128-byte HIANOR01 record. The yielding policy flat instead returns zero for completion, one for a syscall action or three for a continuation.

Output requires at least 128 bytes. Work requires 201326592 bytes (192 MiB) and must be private memory across the subprocess fork. The mechanical entries check nonwrapping ranges and disjoint input/output/work views before storing a base address. Empty input, overlap and wrapped views fail before those stores. No public input supplies a pointer, callback, source root or cancellation location.

Trusted caller state:

| Work offset | Value |
| --- | --- |
| 0 | Zero to begin; private continuation thereafter |
| 8 | Actual syscall feedback in the yielding interface |
| 16 | Work base address, written by the mechanical adapter after view checks |
| 24 | Borrowed, strongly held source-root directory descriptor |
| 32 | Private external-interrupt word |
| 2240 | HIANDG01 marker for captured integer conversion policy |
| 2248 | Captured integer digit limit: zero or 640 through 2147483647 |

A missing HIANDG01 marker retains 4300 solely for earlier private callers. The final rank context explicitly supplies its constructor-captured value for every call. The public request cannot change it. An external interrupt is distinct from a normal rank outcome; when a child exists, cancellation kills its owned process group and reaps it before returning status three.

## Request

HIANBO01 is a 128-byte header followed by the request JSON and the raw bridge JSON subtree.

| Offset | Value |
| --- | --- |
| 0 | HIANBO01 |
| 8 | Request byte length |
| 16 | Bridge byte length |
| 24 | Duration in nanoseconds, at most 60000000000 |
| 32–127 | Zero |
| 128 | Request bytes followed by bridge bytes |

The bridge span is already valid under the outer Python-compatible value capture. Its shape and path values have not yet been admitted. The bridge-specific projection preserves last-value-wins duplicate keys and classifies nonfinite values without prematurely canonicalizing or converting overwritten values. The strict build-receipt parser is separate: duplicate fields, nonfinite values and captured integer conversion limits keep their original strict order.

There is no new one-MiB limit on the bridge subtree or whole frame. The request one-MiB limit is checked at its original position after identity. Duration zero still performs identity before the pre-execution budget rejection.

## Custody and order

The policy performs these operations in order:

1. Read the entry monotonic clock and validate the held source-root directory.
2. Check bridge shape and binary-path type; resolve the binary path using the actual working directory and symlink semantics.
3. Check receipt-path type and resolve that path.
4. Capture the receipt as a stable regular file within four MiB, hash its actual bytes, decode it with the strict receipt semantics, and validate the native build contract.
5. Re-read and hash all eleven fixed evaluator source files relative to the constructor-held source root. Neither bridge nor receipt may select another source root.
6. Capture and hash the actual evaluator image within 128 MiB.
7. Produce the verified identity, apply the one-MiB request bound and check the remaining entry deadline.
8. Copy the image into a new memfd, apply and verify seals 15, and verify a complete actual readback. Check the same remaining deadline.
9. Execute that sealed image with bounded stdout and stderr, wait and clean up the owned process tree, and confirm the terminal child result.
10. Re-read the original on-disk binary and verify its post-execution identity, close owned descriptors, and read the final clock.

Stable reads compare actual device, inode, size, mtime and ctime, including nanoseconds, and read one extra byte to detect a changed extent. Opens use NOFOLLOW, NONBLOCK and CLOEXEC. A successful pre-execution hash is not substituted for the post-execution read.

The original resource bounds remain: binary 128 MiB; build receipt four MiB; request one MiB; stdout and stderr one MiB each with an extra detection byte. The evaluator's separate private output allocation is not an increase to either pump limit. Cleanup retains the original two-second bound. No deadline is restarted after identity or sealing.

Native source files are a new explicit contract, not the former Python/Rust build claims. Empty, nonregular or over-bound native source files report source-custody code 31 with detail 256 plus the source ordinal. Missing or symlink source opens retain code 23. The fixed leaf source map is in HIA_NATIVE_NDU_EVALUATOR_BUILD.json and is actually read on each call.

## Result

HIANOR01 is exactly 128 bytes.

| Offset | Value |
| --- | --- |
| 0 | HIANOR01 |
| 8 | Status: 0 success, 1 rejection, 2 custody/internal failure, 3 cancellation |
| 16 | Error code |
| 24 | Actual negative errno, when relevant |
| 32 | Stdout byte length |
| 40 | Stderr byte length |
| 48 | Identity JSON byte length |
| 56 | Actual elapsed nanoseconds |
| 64 | Signed child return code in a 64-bit word |
| 72 | Actual evidence flags |
| 80 | Stdout work offset |
| 88 | Stderr work offset |
| 96 | Identity work offset |
| 104 | Stage or diagnostic detail |
| 112 | Owned sealed error-path descriptor, or UINT64_MAX |
| 120 | Error-path byte length |

The parent must close a returned error-path descriptor after consuming it. Stdout, stderr and identity are work views, not independently retained results.

Evidence flags are 1 identity, 2 child started, 4 reaped, 8 one owned-group kill, 32 executable sealed, 64 stdout EOF, 128 stderr EOF, 256 post-read hash and 512 descriptor cleanup. A normal successful leaf call has 1007. A cancellation before sealing is not required to claim the sealed flag.

Additional error work views are normalized receipt offset/length at 2176/2184 and raw receipt offset/length at 2192/2200. The 128-byte parser metadata is at 2048. Unused views have zero length and may have offset zero.

| Code | Meaning |
| --- | --- |
| 10–16 | Bridge shape, path type, NUL, Unicode encoding, path OS or resource error |
| 20–23 | Bounded-file regularity, mutation, changed length or read error |
| 30 | Native receipt contract |
| 31 | Native source custody or pin mismatch |
| 32 | Binary pin mismatch |
| 33 | Strict receipt JSON diagnostic |
| 40 | Request bound |
| 41 | Identity completed but execution budget is exhausted |
| 42 | Executable sealing or readback failure |
| 43 | Execution deadline |
| 44 | Output bound |
| 45 | Subprocess mechanism failure |
| 46 | Owned cleanup unconfirmed |
| 47 | Child failure or rejected output shape |
| 48 | Post-execution binary identity changed |
| 50 | Descriptor close OS error |
| 90 | Private invariant violation |

Code 41 is an admission refusal for the caller's rank policy, not an ordinary exception. The error renderer preserves the other exception classes and messages rather than converting every failure into one rejection class.

## Strict receipt parser and renderer

The parser normalizes valid UTF-8, UTF-16 and UTF-32 input, including byte-order detection and the existing surrogate behavior. It preserves CPython 3.14 JSON error positions, line and column values, trailing comma and incomplete escape diagnostics, duplicate/nonfinite checks, and the captured integer conversion limit. Parser tests use the actual independent Python implementation; they do not infer error text from the native implementation.

HIANJD01 metadata holds status at 8, normalized byte count at 16, message code at 24, byte position at 32, character position at 40, line at 48, column at 56, encoding at 64, Unicode span at 72/80, relevant byte at 88, captured digit limit at 96 and digit count at 112. Statuses are 0 valid, 1 JSON decode, 2 Unicode decode, 3 duplicate, 4 nonfinite, 5 integer digit limit and 6 defensive-depth refusal.

The error renderer input is HIANER01/128 followed by path filesystem bytes, optional 128-byte metadata, normalized receipt bytes and raw receipt bytes:

| Offset | Value |
| --- | --- |
| 8 | Owner error code |
| 16 | Actual negative errno |
| 24 | Owner detail |
| 32 | Path byte length |
| 40 | Metadata length, zero or 128 |
| 48 | Normalized receipt length |
| 56 | Raw receipt length |
| 64–127 | Zero |

Renderer work is at least 32768 bytes. Output can be zero-sized for sizing. Its external return is a full unsigned 64-bit value: UINT64_MAX for malformed private input; UINT64_MAX minus one for insufficient output with the complete required length at work offset zero; otherwise the complete emitted length. A fixed 41-byte mechanical adapter converts the bounded HIA primary status into this full-width result. It never truncates a result length to 32 bits.

The emitted exception JSON has exactly message and type. Filesystem decoding retains surrogateescape. In particular, the NUL-path error is the original lstat diagnostic, not an invented generic path message. There is no added one-MiB or eight-MiB error-path/output bound. This renderer does not implement general Python string repr and must not be used as a KeyError quote-selection oracle.

## Native construction

Seven new HIA policies/packers and three readable mechanical assembly sources form the owner-specific runtime source set. Existing native_path_resolve and the qualified SHA streaming composite remain explicit dependencies. Development authors are not required by the runtime.

Compile the six owner roles as HIA flats: main, SHA, identity, path, pump and strict JSON. The owner packer consumes HIANOP02/64, six lengths at offsets 8 through 48, mode at 56 (zero yielding; one complete effects), followed by the six flats in that order. Each constituent flat is 16 bytes through one MiB. Output capacity is at least eight MiB. The HIA packer emits either actual selected product; production construction does not invoke an assembler or concatenate executable parts in Python.

The renderer packer consumes HIAERR01, the policy length word and that actual policy flat, and emits the fixed 41-byte adapter plus policy. The renderer policy is 16 bytes through one MiB; the packer output capacity is at least two MiB.

Both packers were compiled and executed as actual native HIA. The qualified generic HIAFLT01 filter was used only to wrap their small flat bodies into executable packer tools. Readable assembly and checked literal templates remain source-bound.

## Qualification boundary

The JSON ledger includes the following separately identified sets, not one inflated sum of overlapping assertions:

- 73 composed identity/order/error cases.
- 126 Python-compatible bridge projection cases.
- 41 effect faults, short I/O, interrupted operations and cleanup cases.
- 18 actual live binary-mutation, cancellation and deadline cases.
- 228 private ABI, native packer, full-width renderer and Linux errno controls.
- 475 captured integer-limit comparisons, including 20 actual composed receipt cases.
- 3385 strict receipt JSON and Unicode comparisons.
- 186 identity cases.
- 15 actual subprocess fixtures and 115 concurrent subprocess controls.
- 16 native source-custody extent/type controls.
- Shared path qualification: 223 path cases, 124 borrowed-input cases and 207 Unicode cases.

The live mutation cases change the actual original binary only after observing the real child PID. The sealed child still executes the admitted bytes, and post-read verification rejects the changed source file. Cancellation cases confirm actual group cleanup, reaping, ECHILD and no descriptor leak. Actual 80 ms deadlines retain the configured bound; they are not synthetic clock-only tests.

A malformed evaluator request used in an early fixture emitted only 196 stderr bytes and therefore was explicitly not counted as an output-overflow case. Actual cap/EOF/descendant behavior is covered by the dedicated subprocess fixtures. Earlier failed renderer/JSON fixtures and the erroneous requirement for a seal flag before sealing remain recorded as development failures.

No claim here transfers this component qualification to a different source identity, the unfinished rank context, a production installation or a whole cold replay.
