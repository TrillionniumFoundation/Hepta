# Native multiversion proof preparation

This is the private per-export proof preparation stage. It does not publish a
generation, admit a caller-supplied proof receipt, or claim completion of the
whole native runtime. The enclosing owner supplies its freshly admitted
canonical Core and sorted scalar ABI and owns the configured sealed checker
image and its expected actual SHA-256.

## Execution and custody

The fixed six-word native entry is hia_mv_prepare_proof(source, source_bytes,
output, output_bytes, workspace, workspace_bytes). Output requires at least
512 bytes; workspace is 128 MiB. The native packer embeds five actual HIA
roles: preparation, owned process transport, SHA-256, JSON decoding and public
proof receipt binding. A mechanical capsule dispatches fixed roles and raw
syscalls; the existing native general shared linker emits the shared image.
Readable assembly is source provenance, not a production assembler dependency.

The owner duplicates the checker descriptor, checks anonymous regular
executable custody, exact mode 0500 and all four seals, reads and hashes all
image bytes and compares them with the owned expected pin. Each original
export receives a separate fresh HIAMVP02 proof with the original per-proof
timeout. Normalization happens in the preceding owner. Process lifetime
covers the proof deadline plus the already qualified bounded transport
allowance; it does not reset the proof deadline. Logical publication
cancellation remains a coordinator decision at the original checkpoints.

Every proved receipt binds function, Core pair, private checker image,
checker source inventory and its digest, solver closure, native
implementation, structural verification, claims, scope, counterexample and
absence of execution authority. A final clock check refuses a proved result
after that proof's deadline. Before success the complete sealed checker is
read and hashed again. Owned image and process descriptors are closed.
Unknown/disproved receipts never authorize construction.

## Private request and result

The HIAMVPF1 header is 256 bytes: mode at +8 (1 totality, 2 translation),
timeout milliseconds at +16 (1..30000), sealed checker descriptor at +24,
aligned cancellation capability or zero at +32, before/after canonical byte
counts at +40/+48 and ABI bytes at +56. Bytes +64..127 are zero; +128 holds
the 32-byte expected checker SHA-256; +160..255 are zero. The tail is before
Core, after Core, HIAMVAB1. Each Core remains at most 8 MiB. Totality has no
after Core. ABI is a freshly admitted parent-owned capability, not public
caller verification facts; its structural framing is checked again here.

The HIAMVFR2 result has a 512-byte header: status +8, detail +16, mode +24,
export count +32, proved count +40, current ordinal +48, private outcome +56,
total extent +64, wait status +72 and elapsed nanoseconds +80. Actual image,
before Core, after Core and ABI hashes are at +96/+128/+160/+192. Each tail
receipt is an eight-byte byte count followed by exact bound JSON.

Status 0 means every required proof passed this stage; 1 is unproved; 2 is
deadline exhaustion; 3 is child execution/output failure; 4 is transport/I/O
failure; 5 is binding/claim refusal; 6 is insufficient result storage.
Malformed private framing returns 0xfffffffd before output mutation. No
failed stage grants publication or execution authority.

## Qualification and remaining composition

The checkpoint has 106 actual semantic, framing, custody, cancellation and
captured-receipt fault cases and 32 native packaging/transactional cases.
Semantic comparisons cover all eleven scalar ABI types, sixteen separately
proved sorted exports, an actual equivalent rewrite, different behavior,
permitted checked division and a real totality counterexample. Original MV
decisions are the external oracle; original solver identity is not mimicked.

A preserved earlier counterfactual accepted a corrupted checker inventory
digest. Current code explicitly rejects it and also checks the source-image
object and solver image identity. Compiler-capacity and external-fixture
mistakes remain identified in the qualification provenance. Actual building,
image ownership, all finite probes, selection, leases, retirement, unbounded
public counters and background optimization remain mandatory components of
the subsequent runtime integration.
