# Native multiversion image ownership and finite probes

This component captures a built generation image, verifies its exact build
binding, retains the published inode, creates and reads back a sealed memfd,
loads its actual public symbols, and verifies the loaded mappings. Those
decisions execute in HIA. A fixed mechanical adapter executes one syscall,
one baked HIA role, or one loader operation selected by HIA.

It is a preparation component. Publication coordination, fresh totality and
translation proof, retirement, public leases, and background optimization
remain distinct owners. Passing this component does not assert that the
complete multiversion service or complete repository is native.

## Image entry

The private six-word entry is `hia_mv_image(source, source_bytes, output,
output_bytes, workspace, workspace_bytes)`. The output capacity is at least
512 bytes; the retained workspace is 160 MiB. The private input is:

| Offset | Field |
| --- | --- |
| 0 | `HIAMVI01` |
| 8 | Filesystem path byte count, 1 through 4095 |
| 16 | Complete `HIAMVAB1` ABI byte count |
| 24 | Actual native build image byte count, 64 through 64 MiB |
| 32 | Actual native build SHA-256, 32 raw bytes |
| 64 | Exact path bytes, followed by the ABI |

The parent supplies the actual captured build receipt and admitted ABI. This
interface is not a public authority to substitute a caller-supplied proof
boolean or arbitrary loader address. The HIA owner checks exact framing,
private scalar ABI extents, inode identity, complete file contents, shared
ELF inventory, seal state, symbol addresses, and the actual process mappings.
It preserves resources after a later failure for the single retirement
holder. A failed or interrupted close never grants a second close right.

Both 64 MiB and the preceding read-plus-one behavior are preserved. Readback
uses the original single `pread(size + 1, 0)` acceptance rule. All three
seal observations distinguish raw negative errors from a seal bit mask.

## Native packaging

`multiversion_image_packer.hepta` receives `HIAMVPK1`, a word containing
four, four nonzero flat lengths, and the policy, streaming SHA, shared ELF
inventory, and native mapping flat images in that order. Each flat is at
most 4 MiB and the complete text remains within the existing shared linker's
16 MiB domain. It emits the full general-layout ET_REL object, including the
exact mechanical capsule, four internal relative calls, two external loader
relocations, symbols, and section metadata.

`multiversion_shared_linker.hepta` preserves the existing general shared
linker grammar and output layout. Its separate closed import vocabulary is
`dlopen`, `dlsym`, and `dlclose`; the original allocator linker is unchanged.
The image component currently uses the first two. Production packaging is
HIA packer followed by this HIA linker. The assembly source remains readable
provenance; an assembler is used only by the independent development check
which compares the captured mechanical bytes and relocation holes.

## Exact probe vectors

`multiversion_probes.hepta` accepts the actual `HIAMVAB1` and an ABI ordinal
in the first output word. It returns `HIAMVPV1`, the complete finite vector
count, argument count, result type, original function index, name, exact
scalar type words, and 128-byte zero-padded argument records.

The zero vector, individual argument extrema and midpoints, seven diagonal
vectors, duplicate elimination, and signed lexicographic ordering reproduce
the original `_probe_vectors`. No vector is a replacement for fresh proof.
The preparation controller must execute the retained vectors against both
the loaded generation and its independent complete VM under the original
4224-step observation budget.

## Qualification boundary

The accompanying JSON records source and image hashes and the preserved
qualification reports. They cover 32 native packaging checks, 22 original
loader comparisons with 152 actual loaded calls, the exact 64 MiB boundary
with 22 additional calls, and 12 actual original/native syscall-fault pairs.
Every seal operation is tested with EPERM, EIO, and EINTR. The probe role
matches all 16,547 vectors in 296 original-domain and refusal cases.

The earlier packaging compiler capacity refusal and the incorrect test
assumption that input GNU-stack flags must be rejected remain historical
evidence. The implementation preserves the general linker's canonical
non-executable output stack behavior; that mutation is checked for identical
output rather than incorrectly changing the original grammar.
