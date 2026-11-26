# Native Clang generation preparation and observed retirement

## Qualified scope

This component is the fixed native preparation child for a Runtime generation.
It holds no second Value implementation. Its 47 bounded role bodies include the
already qualified Clang Value adapter, fresh LLVM/ELF image validation, native
and VM probes, and the original holder retirement policies. The fixed linker
shares the identical LLVM and shared-ELF bodies. The single-shot and streaming
SHA interfaces remain separate because their actual bodies and protocols differ.

The v4 native product and the 17-case qualification are recorded in
HIA_NATIVE_GENERATION_CLANG_PREPARE_QUALIFICATION.json. Original compiler
function, block, operation, per-role and total text bounds are unchanged.
The native object and flat outputs equal their independent mechanical oracles;
the object was linked by the existing HIA native linker.

This qualification covers the component and its real cleanup custody. The
parent Runtime registration, public constructor and final installed loader
integration are not yet qualified by these gates.

## Exports and authority

All entries use the existing six-word ABI: source pointer/length, output
pointer/length, context pointer/length. The context is exactly 512 MiB, stable
at one address in one process. The mechanical entry validates PID, actual
context address, actual fixed entry address, nonoverlapping spans and a native
atomic busy guard before executing a continuation. Copies, forked contexts,
malformed frames and simultaneous operations are rejected without modifying
the context or output.

The main exports are:

| Export suffix | Purpose |
| --- | --- |
| hia_generation_lease_clang_prepare | Prepare, retire or observe this actual holder |
| _bind | Private native Value and source-directory binding |
| _exception | Transfer the actual retained exception once, or observe its presence |
| _bind_owner | Private initializer that reads the actual existing owner identity |
| _image, _retire, _probe | Fixed internal constituent entries for assembly |
| hia_program_llvm, hia_program_llvm_metadata | The same fixed LLVM body and its metadata role |

The constituent _retire export has its original protocol; it does not by itself
prove that the kernel unmapped an image. Production complete retirement must
use the main HIAMVGF2 operation 1, which wraps that constituent with real mapping
observation. A successful dlclose return alone never establishes retirement.

The private HIAMVGB1 binding frame is 128 bytes:

| Offset | Meaning |
| --- | --- |
| 0 | HIAMVGB1 |
| 8, 16, 24 | Captured fixed Value entry, actual context, extent 256 |
| 32 | Actual Value binding nonce |
| 40 | Borrowed installed source-directory descriptor |
| 48..127 | Zero |

Only the fixed native parent constructs this frame. Ordinary compile requests
contain neither an entry pointer nor a Value context. Binding first acquires a
real Value context token through Q06/21. The Clang B2 adapter owns its separate
token and duplicates and authenticates the supplied source-directory FD.
Failed initialization retains every actually acquired resource for retirement.
An untrusted or malformed receipt is quarantined rather than guessed unconsumed.

The private owner initializer accepts HIAGPOB1/32 with only source FD at 8.
Its second span is the prepare context; its third is the existing 2048-byte
owner. It checks HIAGLOW1, the actual PID, owner self address, fixed entry,
ready state and the actual owner + 512 Value span. It constructs HIAMVGB1 on
its own native stack. Qualification uses this initializer; it does not write
binding pointers, resource masks, mutexes or authority flags from Python.

## Preparation request and actual stage order

HIAMVGF2 has a 256-byte header. Operation at 8 is 0 for prepare, 1 for retirement
or 2 for observation. Operations 1 and 2 have exactly 256 bytes with all fields
from 16 onward zero.

| Prepare offset | Meaning |
| --- | --- |
| 16 | Zero |
| 24 | Parent validation deadline, nonzero |
| 32 | Parent cancellation location, zero or aligned |
| 40 | Actual canonical Core JSON byte length, 1..8 MiB |
| 48 | Scalar ABI byte length, 336..5136, actual HIAMVAB1 with 1..16 entries |
| 56 | Absolute filesystem path length, 1..4095, without NUL |
| 64, 72, 80 | Actual clang Value capability |
| 88..255 | Zero |
| 256 onward | Core bytes, actual ABI bytes, output path bytes |

The private bounded path domain is not evidence of arbitrary-length public
directory support. The constructor must preserve its complete original domain
through its own path/descriptor ownership.

The native sequence binds the already qualified Clang adapter, performs actual
compiler discovery/version/target validation and compilation, captures the real
receipt and any real Value exception, validates the artifact against fresh
LLVM and actual ELF bytes, seals and loads the actual image, and executes the
actual native/VM probe pairs. The image and probe requests are built from these
captured facts, never caller-written success claims.

Deadline and cancellation fields describe the parent Runtime boundaries.
They do not shorten or add polling to Clang's original version/target 10-second,
compile 60-second or reap 3-second phases. The parent must preserve its original
pre-prepare and post-prepare cancellation/deadline order. The child does not
claim to implement those parent checks.

On preparation failure, this child returns the actual holder and
registration-required fact before holder retirement. The parent must first
register that same holder with the Runtime retention owner. A receipt flag is
not a substitute for actual registration. The parent then calls operation 1.
Successful preparation also retains the exact holder until genuine retirement.

## Reply and independent custody facts

The reply is HIAMVGR2. Prepare output capacity is at least 1,050,624 bytes;
retire and observe require at least 2048. The principal fields are:

| Offset | Meaning |
| --- | --- |
| 8 / 16 / 24 / 32 | Stage error / child return / detail / original retirement status |
| 40 | Prepared |
| 48 / 56 / 64 / 72 | Core, ABI, path and receipt lengths |
| 80 / 88 / 96 | Schema, actual probe count and actual VM steps |
| 104 / 112 | No transferred producer stdout/stderr FD |
| 128..223 | Captured Clang Input, Core and ABI hashes |
| 224..255 | Actual loaded image SHA256 |
| 336 / 344 / 352 / 360 | State / ownership known / completely retired / pending |
| 368 / 376 | Cleanup error and errno |
| 384 / 392 | Actual holder custody / registration required |
| 400 / 408 / 416 | Exception retained / Clang work retained / own context token retained |
| 424 / 432 | Captured Clang failure fields |
| 448 | Original holder retirement was actually consumed |
| 456 | Observation identity: 0 pending, 1 real memfd fstat, 2 no image FD or library |
| 464 | Actual kernel mapping absence proved |
| 472 | Mapping-observation FD is still owned |
| 480 / 488 | Mapping observation result and errno |
| 512 | Captured actual image reply, 512 bytes |
| 1024 | Actual probe reply, 128 bytes |
| 1152 | Original holder retirement reply, 768 bytes |
| 2048 | Actual receipt bytes on preparation |

States are 1 bound, 2 preparing, 3 prepared, 4 registration required, 5 closing,
6 fully retired, 7 unknown quarantine and 8 partial bind. Status, known,
pending, consumed and retired are independent facts. A nonzero error never
licenses dropping custody of a resource that may already have been acquired.

## Observed retirement and failure recovery

Before consuming the original holder, the child obtains the actual memfd
device and inode with fstat. It then executes the original retirement exactly
once. Once that child reports actual consumption, retries never repeat
dlclose. The child instead resumes the unfinished observation/descriptor step.

For a mapped image, the child opens and streams /proc/self/maps. It compares
the device/inode of each real mapping to the captured memfd identity. Reads
use 64 KiB chunks; line state crosses chunk boundaries. Only the bounded
numeric prefix is retained, and arbitrary path suffixes are ignored. There is
no total maps-file, path-length or number-of-mappings truncation.

Only actual EOF without a matching mapping followed by actual descriptor
closure allows complete retirement. close_range failure retains the FD;
ENOSYS uses real close, whose uncertain failure quarantines the owner.
fstat/read failures retain the actual holder/token/observation state for retry.
A dlclose that returned zero while the image still exists in /proc/self/maps
is explicitly not retired. It enters unknown quarantine and retains the
parent context and Value token.

Untransferred exceptions are released through actual deferred Q05/78.
Context tokens use Q05/92 and 93 and their actual consumed/mapping facts.
No resource is cleared merely because an inner return code is zero.
Repeated complete retirement is idempotent.

## Exception object handoff

HIAMVGE1 is 128 bytes, with operation 0 to transfer once or 1 to query and all
remaining input fields zero. HIAMVGER carries disposition at 16, the actual
strong exception capability at 24/32/40, known at 88, delivered at 96 and
cleanup at 104. Raised user __fspath__ exceptions preserve object identity.
Unclaimed exceptions remain native-owned until the actual drop acknowledges
consumption. The parent must transport this real object separately from
stage diagnostics and preserve it across its own cleanup.

## Context layout

The enclosing context uses the existing image/probe areas below 336 MiB,
preserves proof slots at 336 and 352 MiB, allows an exact output alias at
384 MiB, places Clang/image/probe/retirement scratch at 386 and 388 MiB,
streams maps at 389 MiB and keeps this owner's 4096-byte continuation at
400 MiB. The frame begins at 402 MiB; Core/ABI/path remain at 448/456/473 MiB.
An exact input alias at 480 MiB is supported. The existing parent GEN control
at 500 MiB is untouched.

Within the 400 MiB control, the native busy field is 312; the own Value token
and its custody fields start at 320; observed identity/consumed/absence/FD
fields occupy 384 onward. Actual fstat bytes are held at 1024.
The generated HIA and mechanical bridge are the authoritative field definitions.

## Qualification

All 17 groups pass against the same v4 product. They include true Clang
compilation and fresh LLVM/native/VM behavior; parent input/output aliases;
actual exception class/args and user exception identity; native unclaimed
drop; actual mmap, munmap, fstat, read and close_range failures; real fallback;
37 no-write wire/semantic controls; fork/copy refusal; kernel notification
while the actual busy guard is held; and a 200,997-byte real maps stream
with 3712 additional kernel mappings.

Two isolated process cases deliberately end with preserved native quarantine:
actual loader munmap EIO despite dlclose success, and ambiguous fallback close.
Their PASS means the required retained-custody failure contract was observed,
not that those owners reported retirement. The reports explicitly record
actual_retired=false. All normal/recoverable cases restore descriptor,
Value-capability and code-owner balances through actual native cleanup.

The first concurrency test run excluded the exact post-syscall instruction
address from the notification filter. Its failed evidence remains retained.
The corrected test uses the exact one-byte IP interval and observes the actual
kernel notification before asserting concurrent no-write refusal. No product
code or behavior assertion was relaxed.

Parent registration, complete public Runtime construction, immediate generation
Info pruning, final installed child binding and physical removal of the old
prepare bodies from the root remain separate required integration work.
