# Core v9 fixed-width byte memory

Primitive Core v9 adds four instructions over the existing byte-buffer loans.
The public resource and alias contracts are unchanged. Core v8 and earlier
reject these instructions; adding an instruction name does not upgrade an
older document's schema.

| Instruction | Arguments | Result | Effects |
| --- | --- | --- | --- |
| `buffer.load.u64.le` | readable loan, `usize` offset | `u64` | `read`, `trap` |
| `buffer.load.u64.be` | readable loan, `usize` offset | `u64` | `read`, `trap` |
| `buffer.store.u64.le` | writable loan, `usize` offset, `u64` value | none | `write`, `trap` |
| `buffer.store.u64.be` | writable loan, `usize` offset, `u64` value | none | `write`, `trap` |

All four instructions have an empty attributes object. Offsets and lengths are
unsigned 64-bit Core scalars. The whole eight-byte range must pass
`offset <= length && 8 <= length - offset` before narrowing, pointer arithmetic,
or reading or writing any byte. A failed store leaves every buffer byte intact.
Offsets need not be aligned. Endian order is explicit and independent of the
machine's native order; there is no signed extension or shift by 64.

The operations allocate no payload, create no view and transfer no resource.
They require the same live, unsuspended loan authority as the byte operations.
A load may use a read-only or writable loan. A store requires an exclusive
writable loan. None of these instructions permits mutable aliases, retains a
borrow after its scope, or changes the foreign caller's distinct-allocation
and pointer-liveness obligations.

## Implementations and admission scope

The primary Core verifier, reference VM, direct x86-64 backend, LLVM lowering,
Rust ownership shadow and owned VM, and the bounded assembly selfhost compiler
implement v9. The resource analyzers admit the explicit new schema and account
for each word operation as one VM operation with no allocation. Values loaded
from memory remain unknown scalar facts in static allocation analysis; reading
a word does not provide authority for a derived allocation bound.

The selfhost compiler accepts v8 and v9 assembly. Its own source remains v8 so
that the previously pinned v8 compiler can build the new compiler. The schema
word occupies workspace bytes `[1016592, 1016600)`, after the existing export
table. Source, output, workspace, function, block and instruction limits are
unchanged. The new source must satisfy the existing 8,192-instruction limit.

The independently selected native Core JSON, instruction/shape/admission and
authoring-policy profiles retain their declared older input scopes. They are
not qualified as v9 frontends by this change. The Rust scalar-only entry point
also retains its older scope; v9 resource programs use the owned entry point.
The v8 opcode catalog remains a v8 catalog, and the v9 catalog is separate.

The Python seed's checked foreign-buffer wrapper has its existing bounded loan
capacity. B3's generated static borrowed ABI instead carries full 64-bit
extents. Tests and receipts name these different interfaces explicitly; a
successful large borrowed call is not a claim about the seed wrapper.

## Required qualification

`tests.test_hia_word_memory` and the Rust word-memory tests exercise exact
bytes, both endian orders, unaligned offsets, high offset bits, effects, types,
loans, schema rejection and unchanged bytes on a VM bounds failure.

`tools/qualify_hia_word_memory.py --compiler <B3.image.bin> --clang <clang>
--output <new-directory>` executes the actual direct, LLVM and selfhost native
code against the same independent byte oracle. It requires every tool and
case; missing backends are failures. Disposable native children distinguish
the backend's bounds trap from a guard-page fault and preserve shared buffers
for an after-trap byte comparison. A test-only allocator witness binds fresh
zeroed sparse mappings to the generated direct/LLVM object's existing
`calloc`/`free` imports, allowing observable failure bytes and legitimate
offsets above 4 GiB without allocating four gigabytes of physical memory.
The witness does not implement the new instructions or alter their guards.

The bootstrap and prior compiler qualification remain separate gates:
`B1 == B2 == B3`, cross-bootstrap with the original v8 compiler, the existing
modified-source fixed-point test, and all prior compiler qualification
families. LLVM AArch64/RISC-V object generation is compile qualification only;
it does not establish execution on those architectures. A support declaration
or source digest is not a substitute for any of these execution receipts.

This extension alone makes no claim that the whole language or Codex product
has migrated, that the backends are formally equivalent, or that the template
performance requirement has been met.
