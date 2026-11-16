# Raw descriptor primitive ABI candidate

## Separate, explicit boundary

`tools/hia_capture_descriptor_syscalls.S` implements four raw Linux x86-64
syscalls: openat(257), fstat(5), read(0) and close(3). It contains no path-root
selection, traversal policy, stream decoding, artifact publication, fsync,
transaction, retry or cleanup decision. Existing publication and retirement
owners are unchanged.

This is a concrete source candidate, not an assembled or qualified image.
`NativeCaptureDescriptor` admits explicit exact assembly/image bytes, and
`DescriptorInvocation` owns one request/workspace through actual delivery.
It is not registered as a HIA six-argument helper because it has a distinct raw
protocol and no generated HIA source contract. The public file-capture owner
continues to use the original hosted effects.

The entry uses the existing SysV six-buffer-argument calling shape:
request pointer/bytes, output pointer/bytes, workspace pointer/bytes.
All fields below are little-endian 64-bit words; fd/result are signed.

## Request and workspace

| Request byte offset | Meaning |
| ---: | --- |
| 0 | magic 0x3151504143464948 |
| 8 | operation: 1 openat, 2 fstat, 3 read, 4 close |
| 16 | signed directory/file descriptor |
| 24 | open flags or read count; zero for fstat/close |
| 32 | open mode; zero for other operations |
| 40 | NUL-inclusive path length; zero for non-open |
| 48, 56 | nonce words, not both zero |
| 64 onward | open-only NUL-terminated bytes, with no interior NUL |

Open requests have exactly 64 plus declared path bytes. Other requests have
exactly 64 bytes. The Python raw API explicitly accepts a signed Linux int fd,
exact integer flags/mode within uint32, a read count below 2^63, and exact encoded
bytes without NUL. These are raw-ABI constraints, not new restrictions on the
original public Python functions.

The output is exactly 64 bytes. Workspace is exactly 64 bytes for open/close,
208 for fstat, and 64 plus count for read. fstat payload is the Linux x86-64
144-byte struct stat; it is retained as bytes and is not decoded here.
Admission verifies the first 64 workspace bytes are zero before any syscall.

| Workspace byte offset | Meaning |
| ---: | --- |
| 0 | stage: 0 unused, 1 actual syscall pending, 2 raw result saved |
| 8 | actual operation |
| 16 | signed kernel result |
| 24, 32 | original nonce |
| 40, 48, 56 | reserved zero |
| 64 onward | stat or read output extent |

The fixed request admission runs before the syscall cutpoint. The assembly
stores stage1 immediately before the operation dispatch. After the kernel
returns it stores the raw signed result first and then stage2, before returning
to Python. A negative kernel return is an acknowledged raw outcome; it is not
a transport loss and it is not retried.

| Output byte offset | Meaning |
| ---: | --- |
| 0 | magic 0x3152504143464948 |
| 8 | zero status |
| 16 | actual operation |
| 24 | stage2 |
| 32 | signed kernel result |
| 40, 48 | original nonce |
| 56 | reserved zero |

Successful entry returns 64. A malformed packet returns 0xfffffffd and does not
write output/workspace. All whole-buffer/nonce/extent/guard checks happen before
terminal confirmation. The workspace raw result is retained if Python delivery
is lost; it does not authorize replay or a guessed close. The invocation cannot
be reused. A successful fd ownership transfer does not itself close a file.
An unknown open/close case remains held until its owning test process exits.

## Build and independent controls

`tools/build_hia_capture_descriptor.py` accepts an explicit clang-compatible
assembler executable and a fresh output directory. It captures exact assembly
and executable bytes, supervises assembly for 30 seconds with bounded three-second
owned cleanup, validates one ELF64 .text function at offset zero with no
relocations, and writes the raw text image plus explicit development receipt.
It does not invoke publication code or infer current-cold qualification.

`tools/qualify_hia_capture_descriptor.py` runs six fresh owned 60-second cases:
relative directory open/stat/read/close, confirmed negative errno values,
O_NOFOLLOW refusal, unchanged malformed buffers, actual post-open return loss,
and actual post-close return loss. Both lost-return cases execute the real entry
before raising and preserve its workspace, actual exception identity and unknown
record. They do not reset shared custody.

The variable request/workspace ctypes array classes may affect explicit GC.
That boundary must be independently measured before this primitive is ever
substituted for a public provider. No libc buffering, Python fdopen semantics,
signals/EINTR loop, arbitrary path/limit object behavior, or universal OS support
is claimed by these raw controls.

Future provider adoption requires a distinct reviewed contract for Python path
encoding, overflow and arbitrary-object protocols, buffering and fdopen ownership,
interrupted syscalls, raw struct stat layout, descriptor generations and ancestor
ownership. This package deliberately does not infer those facts from a successful
raw syscall or from a file-capture control image build.
