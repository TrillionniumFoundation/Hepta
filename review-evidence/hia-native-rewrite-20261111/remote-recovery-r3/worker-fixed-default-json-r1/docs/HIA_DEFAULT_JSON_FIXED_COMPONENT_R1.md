# Fixed native default DataJSON forwarding component — draft r1

## Current status and scope

This is a new, unexecuted development source revision. At this checkpoint no
AST-generation, VM, B3 compilation, native component entry or executable test has
run for these new files. The existing default-DataJSON components and their CI
runs have their own identities; no result is inherited by this forwarding
component.

The component implements the whole private forwarding path for ordinary
`decode_data`: UTF-8 and input type checks, ordinary byte/preflight ordering,
the exact raw decoder, the complete DataGraph value owner, binary64 conversion,
and the late parser needed to preserve original numeric-callback/error order.
The HIA forwarding owner selects and validates every actual continuation. The
fixed x86-64 carrier only owns stdin capture, mappings, byte copies, protections,
actual image calls and output. Runtime Python parsing, value materialization,
numeric conversion, per-event dispatch and subprocess execution are absent
from the intended executable.

It is not the public eleven-tool Worker, not an installed entry, and not a
namespace service. Worker request validation, service records, journal,
schema/business calls, store transactions, installation identity and final
reports remain separate owners. No default selector is activated by this draft.

## Immutable source and actual peer authority

All eight images must be freshly source-bound by the development build. The
historical f50 B3 is exactly 668608 bytes with SHA256
`0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`.
Each individual compile retains the original 10 CPU seconds, 20 wall seconds
and 256 MiB address-space limits. This development compiler identity is not a
matching new cold qualification.

The input/arena numbers in headers are correlation values. They are not an
authenticator for arbitrary external bytes. The fixed executable captures one
input, copies its raw body to its own immutable mapping, calls the exact decoder
itself, and retains the actual returned mappings until their real consumers are
done. A caller cannot register or substitute an arena through the external input
frame. Every BAD return terminates the invocation, including short-workspace or
counter-overflow cases which cannot publish an updated poison event.

## Private external byte frame

The only initial input is 16 little-endian u64 words followed by exact raw bytes:

| Word | Meaning |
| --- | --- |
| 0 | ASCII `HIAGFI01` as little-endian u64 |
| 1 | Version 1 |
| 2 | Nonzero invocation correlation |
| 3 | Nonzero call correlation |
| 4 | Nonzero raw correlation |
| 5 | Nonzero result Graph correlation |
| 6 | 9 for Python bytes, 4 for Python str transported as UTF-8 surrogatepass; another value reaches the ordinary wrong-type owner |
| 7 | Integer decimal digits limit: 0, or at least 640 |
| 8 | Nonzero decoder arena correlation |
| 9 | Nonzero DataGraph correlation |
| 10 | Exact raw body bytes |
| 11–15 | Zero |

The bytes/text distinction exists only at this private development boundary.
It does not define a replacement public Worker wire protocol. In particular,
text transport preserves lone surrogates so the actual HIA ordinary encoder
can reject them at the original point. The carrier does not apply the ordinary
8 MiB data budget before the complete UTF-8 pass; that ordering belongs to HIA.

The carrier first captures stdin to EOF with EINTR handling, then seals it
read-only. Its internal initial 64-byte command is
`[HIAWDI01,1,capturedBytes,0,0,0,0,0]`. HIA verifies the full private header,
copies only its raw body into a separate mapping, seals that mapping, and starts
the original prefix owner. No JSON/schema/value field is examined by assembly.

## Fixed image roles

| Role | Exact responsibility |
| --- | --- |
| 1 | Default raw/type/UTF-8/masked-preflight prefix |
| 2 | Default preflight/decoder/value-result continuation |
| 3 | Default late source-order numeric/syntax parser |
| 4 | Exact integer JSON preflight |
| 5 | Exact general raw JSON arena decoder |
| 6 | Complete DataGraph value owner |
| 7 | Exact binary64 conversion |
| 8 | New fixed forwarding owner |

Roles 1, 2, 3 and 6 use a read-only second operand. The fixed mask is 0x4e.
All other second operands are owned writable mappings. Three operands must be
different mappings, every borrowed range is checked, and original protection
rights are restored after each actual call. The caller of role 8 supplies a
read-only acknowledgement, a 128-byte event output and its 65536-byte private
workspace. The component image language limits remain 128 functions, 1536
blocks, 8192 instructions, 256 blocks per function and 16 block parameters.

## Mechanical carrier protocol

The exact inherited protocol uses a 128-byte `HIACDE01` event. The actual
acknowledgement is `HIACDA01`, not similarly spelled magic values from an old
chat summary. Its fixed 64-byte header is followed only by the HIA-requested
observation of at most 256 bytes.

| Opcode | Operation |
| --- | --- |
| 1 | Call an already mapped fixed image |
| 2 | Grow an owned mapping while preserving its old bytes |
| 3 | Zero an owned writable range |
| 4 | Copy a checked range into a different owned writable mapping |
| 5 | Release one owned mapping |
| 6 | Protect an owned mapping read-only or writable |
| 7 | Terminal publication of two prevalidated read-only views |
| 14 | Observe a checked view without a component call |

Each nonterminal event consumes precisely the next sequence. Terminal uses
the last completed sequence. Reserved words, actual u32 return, requested
observation size, ownership and every extent are checked. Unknown operations,
wrong acknowledgements, replay, unexpected actual BAD, missing mappings or
range violations terminate with exit 126. System-call failures terminate with
exit 74. There is no retry of a semantic image after a failed acknowledgement.

The only carrier syscalls are read, write, mmap, mprotect, munmap and exit.
No open/path lookup, execve, fork, environment-based selector or runtime library
loader is needed by this component. That is a property to verify against the
built executable; the unexecuted source checkpoint alone is not execution proof.

## Actual continuation order

The HIA driver copies the original prefix's entire issued peer configuration.
It never derives a parser plan from Python values.

1. Raw prefix runs against the immutable exact raw body.
2. Prefix GROW preserves that workspace and reenters only the same owner.
3. A preflight request runs role 4 against the actual masked bytes and returns
   its actual complete 4256-byte state to the prefix.
4. A decoder request runs role 5 against the original raw bytes. Its actual
   returned extent, not a guessed header extent, creates the borrowed arena.
5. The DataGraph owner receives that same arena and original raw mapping.
   Its GROW reenters only role 6 with unchanged inputs.
6. Each binary64 request is fulfilled by actual role 7. The driver forwards
   actual status and actual eight output bytes; semantic errors do not acquire
   a fabricated eight-byte success extent.
7. DataGraph terminal state is returned whole to the original default prefix.
   A late parser request uses the same role 7 and original byte offsets.
8. Only the original prefix's complete terminal event permits publication.

The final private stdout is its exact 256-byte `HIAGDE01` event followed by
the complete native Graph, or by its exact UTF-8 error text. Exit is 0 for
accepted value, 1 for semantic refusal; stderr is empty. The event retains all
native error-domain, reason, position, line and column fields. No host renderer
recomputes the error. It is not yet the public Worker report presentation.

The driver copies the terminal payload into a dedicated mapping, protects it
read-only, releases all raw/prefix/decoder/value/binary owned mappings, and only
then issues terminal publication. A process-level trap or BAD discards all
leases. Input, carrier and controller mappings are reclaimed by process exit.

## HIA ELF packing

The development assembler creates only the immutable mechanical prefix. The
new HIA packer writes every final ELF byte, segment sizes, zero alignment,
all eight actual image bytes and their fixed role addresses. Its packet is
`HIAGFP01`, version 1, eight images, full packet extent, sizes offset 64,
three reserved zero words, eight nonzero sizes, then the eight images. Each
individual image retains the existing 1 MiB image budget.

The build must compare the actual HIA output byte-for-byte with an independent
expected layout, verify exact source/image/receipt bindings before mapping,
read them back after testing, and preserve the original assembly, object,
relocation report, prefix, authoring source, HIA source, receipts, images,
input packet and output. GNU as/objcopy are development authoring tools; their
use does not constitute a native source-authoring closure claim.

## Required new verification

New tests must use actual independent processes with empty PATH and HOME, and
compare full stdout, stderr and exit with the exact retained ordinary oracle.
They must retain every failure and verify input/source/image identity before
and after. Necessary controls include all value types, finite/subnormal/
negative-zero binary64, arbitrary integers, bytes versus str Unicode errors,
numeric-callback versus later-syntax order, digits/depth/input-byte boundaries,
empty payload, private framing, exact mapping rights and a meaningful complete
Graph or full-error publication. Direct controller fault injection must bind
its exact image and retain whole before/after workspace.

Existing default-component tests are neither repeated as new evidence nor
treated as proof of this fixed executable. The ordinary 11-tool Worker,
namespace and installation gates stay OPEN until their own actual complete
paths are implemented and run.
