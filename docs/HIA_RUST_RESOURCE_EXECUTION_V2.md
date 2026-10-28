# Independent Rust execution of primitive resources

`rust/hia-core-shadow` provides an independent finite interpreter for the
existing `hepta.hia.program.v1` through `.v7` resource ISA. It consumes Core
JSON directly, checks the complete module with its Rust Owner/Loan verifier,
and executes Rust scalar/resource operations. It does not invoke Python,
replay source, call generated native code, or grant production admission.

## Interface and report version

```text
hia-core-shadow --owned-run FUNCTION JSON_ARGS [OPTIONS_JSON]
```

Core JSON is read from stdin. Public entries still require precisely typed
scalar arguments and scalar returns; an explicitly declared export list is
respected. Borrowed returns, resource-valued public entries, unknown versions,
unknown options and unknown operations reject. Composite input must first be
normalized to its existing primitive Core namespace; the independent Rust
process accepts only those primitive bytes and independently checks them.

Execution now returns `hepta.hia.rust-owned-execution.v2`. This is an explicit
report change, not a new meaning for the former v1-only execution receipt.
`program_schema` records the exact input version, and `program_sha256` binds
the independently checked canonical document. The capability claims are
`finite_primitive_resource_execution`, `primitive_v1_v7_resource_execution`
and `recursive_buffer_chains_supported`. Historical v1-only claim keys are
absent. Nonclaims concerning production admission, general provenance,
whole-language soundness, backend refinement and ABI/hardware remain false.

`status`, `steps`, budgets, `resources`, returned `values`, and stopped
`error.code` retain their meanings. v1–v6 input resource ledgers have exactly
their previous byte-owner/loan fields. v7 additionally reports chain roots
created/consumed/live and nodes created/dropped/live. Choosing a newer input
version never makes an operation legal in an older version.

## Bulk byte behavior

v2 fill/copy, v3 overlap-safe move, v4 swap, v5 offset copy and v6 range fill
execute through checked views. Every dynamic bounds guard precedes mutation.
Range checks compare offsets with extents before subtracting; zero-length
operations still require valid offsets. Swap requires both indices strictly
inside the owner, including when they are equal. Cross-owner copy requires
distinct roots and storage; same-owner move uses memmove semantics.

Bulk operations do not create owners or loans, make source-language allocator
calls, or add one step per byte. Rust uses bounded slices without cloning an
entire byte range into temporary storage. The existing live requested-byte
budget and one tick per instruction are unchanged.

## Chain storage, loans and event order

Chain roots and nodes live in separate index tables. Nodes hold a header-owner
identity, a payload-owner identity and an optional successor-node identity.
There are no raw host pointers or recursively owned Rust links. A head loan
records the chain as its logical root and the head payload as its byte storage.
Reborrows and borrowed call formals retain both identities. Distinct readonly
call formals remain distinct loans even when their actual argument is shared.

Each node requests the existing 24-byte header through the same allocation
path and failure sequence as payloads. On successful push, the header and
empty fallback are new byte owners; the payload remains owned inside the node.
On failed push, the optional allocator's internal empty owner is created and
then dropped, while the original payload and tail are returned unchanged.
Both outcomes consume the old chain root and create its returned root.

Pop consumes a chain root. A nonempty pop frees only its header and returns
the existing payload with a new tail root. Empty pop creates an empty root and
an empty byte owner. Empty owners never make allocation/free calls. Empty
head borrowing traps with `bounds` before creating a loan. Move changes the
SSA binding without creating or consuming a chain root.

Destruction consumes the chain root first, then iterates over nodes. Each
iteration charges one tick before dropping its payload, dropping its header
and counting the node as dropped. A step-budget stop may therefore have no
live chain root while retaining live nodes and bytes. The stopped ledger must
not report unexecuted destructor work. Releasing oracle host memory when its
process finishes is not a program resource event.

Heap budget refusal occurs before the allocation-attempt counter increments
and before push consumes either input. It remains `budget_exceeded: heap`,
not a fallible allocator result. Ordinary injected allocation failure follows
the existing optional/infallible allocator semantics.

## Finite policy and validation scope

The policy remains 1–1,000,000 steps, at most 64 MiB of simultaneously live
requested bytes and 32 active calls; defaults are 100,000 steps and 16 MiB.
Metadata/host RSS is not reported as requested program storage. The checked
input, finite operation count and live-byte budget bound this development
oracle; they are not an operating-system isolation or native runtime promise.

Rust unit tests retain v1 resource behavior and independently specify chain
counter examples. Python test drivers send the same canonical Core bytes to
the independent Rust binary and compare returns, traps, steps, full resource
ledgers and program digests with the separate Python VM. Native comparisons
execute emitted LLVM and observe real results and allocator calls. None of
those tests substitutes Python execution for Rust execution.

Test counts, exact source identities, tool hashes, failures, budget stops and
execution results belong in retained run receipts. This document does not
claim a test ran merely because its code exists. The extension covers the
specified primitive resource ISA; it does not prove source-to-Core refinement,
arbitrary recursive ADTs, foreign-pointer provenance, concurrency, all ABIs,
or the correctness of the LLVM backend.
