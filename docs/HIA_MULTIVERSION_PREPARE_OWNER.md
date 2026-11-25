# Native multiversion preparation owner

## Qualified component scope

The native owner performs actual constructor capture, pathname identity acquisition,
complete artifact reading, captured report validation, ELF inspection, sealed
loading, loaded-symbol mapping verification, complete HIA VM probes, and owned
retirement in one fixed HIA continuation. Its mechanical bridge supplies only
syscalls, the three loader imports, and fixed six-word role calls.

The enclosing multiversion runtime, global retirement registry, publication
linearization, leases, public snapshot rendering and background optimizer are
separate obligations. `whole_native_runtime` remains false. The finite native
probes do not constitute a backend refinement proof.

The qualified constructor is the fresh P3 native product, 3,819,682 bytes,
SHA-256 `539ce9aab49b6f3e04517a511b08a6351421f86b978e03510ea3220e90f231e0`.
It is not the unavailable older e646 constructor. Native constructor receipts
retain their real HIA backend and source identities; no LLVM identity is invented.

## Original ordering and custody

The source contract is `hepta/hia_multiversion.py::_prepare`: constructor,
published-path identity pin, complete artifact read and stability checks, report
binding, actual ELF admission, sealing/loading, mapping and probes. The report
must bind the actual canonical Core and actual read artifact.

The capture companion records the fixed native constructor's entire stdout but
defers report interpretation. The image companion first pins and reads the
actual pathname, then decodes and verifies that same captured report. An actual
two-fault test moves the constructed artifact away and corrupts the captured
report: pathname capture fails before the malformed report is examined.
Every receipt mutation starts with a completed real constructor call.

The same 192 MiB workspace is the generation's holder throughout. It is neither
copied to another holder nor released by probing. Failed preparation invokes
the existing native retirement owner on that same holder. An unacquired path is
never treated as owned. Native and identity release uncertainty remains in the
holder; the enclosing runtime must keep and charge it until its original
retirement state permits release. Global registration and synchronization are
the responsibility of the enclosing runtime, which can drive the same pure
continuation and register its fixed retirement action before executing it.

## Six-word interface

The exported function is `hia_mv_prepare_owner(s, sN, o, oN, w, wN)`.
The source and output are disjoint from the exclusive holder. The holder is at
least 192 MiB, initially zero, and belongs to the creating process. Preparation
requires output capacity 1 MiB + 2,048 bytes. Retirement/query require 2,048.
Concurrent access to one holder is serialized by its enclosing runtime.

The 256-byte request starts with `HIAMVGF1`:

| Offset | Meaning |
| --- | --- |
| 8 | Operation: 0 prepare, 1 attempt retirement, 2 observe retirement |
| 16 | Actual sealed constructor descriptor |
| 24 | Absolute monotonic transport deadline |
| 32 | Aligned cancellation word address, or zero |
| 40 | Canonical Core byte extent |
| 48 | Actual admitted `HIAMVAB1` extent |
| 56 | Absolute output pathname byte extent |
| 64–127 | Zero |
| 128–159 | Expected complete captured constructor SHA-256 |
| 160–255 | Zero |

Operation zero appends Core, ABI, and the absolute pathname without a NUL.
The existing limits remain: Core at most 8 MiB, 1–16 exports, 0–16 scalar
arguments, pathname at most 4,095 bytes, constructor image at most 8 MiB,
captured build report at most 1 MiB, and the original 64 MiB artifact/capture
limits. Retirement and observation are exactly 256 bytes with bytes 16–255 zero.
A second preparation on a previously admitted holder is refused.

No public generation, epoch, lease count or accounting value is encoded by this
interface as a machine integer. The retirement leaf's generation word is a
constant private holder identifier; the enclosing runtime owns the public
arbitrary-precision identity separately.

## Result and ownership transfer

The result begins with `HIAMVGR1`. The entry returns the status at offset eight.
A malformed private frame returns `0xfffffffd` without writing output.

| Offset | Meaning |
| --- | --- |
| 8 | Prepare: 0 ready, 1 capture, 2 image/report, 3 probe failure; retirement/query: original retirement status |
| 16, 24 | Nested status and detail |
| 32 | Retirement status, or UINT64_MAX when not attempted |
| 40 | Ready flag |
| 48, 56, 64 | Actual Core, ABI and pathname extents |
| 72 | Captured report extent, preparation result only |
| 80 | Actual constructor wall time |
| 88, 96 | Actual live VM/native comparisons and VM steps |
| 104, 112 | Owned stdout/stderr descriptors transferred once, or UINT64_MAX |
| 120 | Actual raw child wait status |
| 128, 160, 192 | Constructor, canonical Core and ABI SHA-256 |
| 224, 256, 288 | Actual artifact, native object and machine-text identities |
| 320, 328 | Machine text and artifact extents |
| 512 | Original image reply, 512 bytes |
| 1024 | Original probe reply, 128 bytes |
| 1152 | Original retirement reply, 768 bytes |
| 2048 | Actual captured build report |

Transferred diagnostic descriptors must be closed exactly once by the caller.
No unready result exposes callable addresses. Observation preserves a ready
holder and its function addresses. Retirement clears readiness and the output
address area before release. A pending or uncertain retirement does not grant
permission to free or recreate the holder.

## Fixed native packaging

`multiversion_prepare_owner_packer.hepta` consumes `HIAMVGP1`, count 15,
fifteen little-endian lengths, then the complete role bytes:

`owner, capture, process, hash, json, image, sha, elf, mapping, probe,
vectors, projector, vm, retire, retirement_state`.

Each role remains in the original 1–4 MiB domain. The complete text, including
mechanical capsules and alignment, remains at most 16 MiB. The native packer
emits the original closed seven-section ET_REL. Its only imports are
`dlopen`, `dlsym` and `dlclose`; its only public export is the owner.
The existing HIA shared linker produces the actual shared object. Production
packaging executes neither assembler nor host linker. Both mechanical assembly
sources are retained as auditable source for the exact embedded capsule bytes.

## Qualification

The companion JSON stores complete machine-readable case records and pins:

- 18 fresh actual constructor runs, 283 original scalar signatures, and all
  16,547 original vectors, including all eleven scalar types and arities 0–16.
  Every vector invokes the complete HIA VM and the actual loaded native ABI.
- 85 actual refusal, cancellation, process-reaping, receipt, error-order,
  wrong-native-function and same-holder cleanup gates.
- 75 native packer gates, including every role's exact 4 MiB boundary,
  atomic malformed/short rejection, and the exact 16 MiB text limit.
- Query preservation, second-prepare refusal, repeated retirement, actual
  pathname inode binding and restored descriptor sets are checked in every
  successful batch.

The initial guard harness incorrectly attempted to JSON-decode a deliberately
malformed diagnostic result. Its failed log is retained. The corrected harness
decodes success reports only; the product image was unchanged. The prior
development missing-label/path failures are also retained. The final shared
object is 2,769,680 bytes with SHA-256
`a19162fd00bd94e6b6bc76cf86a3d9554f9398937a51f0745dda1f657baf2129`.
