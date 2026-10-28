# Rust owned-memory execution: finite v5 scope

The existing Rust `--owned-run` Machine now executes the canonical bulk-memory
operations in primitive HIA v2–v7 and recursive chains in v7. The canonical
Python verifier, schemas, source frontend, nominal lowering and interpreter
semantics are unchanged. Rust remains an independent development oracle;
successful execution grants no production or native-backend authority.

## Report compatibility and admission

Modules containing a chain type or instruction select
`bounded-cfg-owned-memory-v5`. Modules without chains retain
`bounded-cfg-byte-owner-bulk-v3` (v1–v7) or
`bounded-cfg-byte-owner-loan-returns-v4` (v8), including the existing ledger
key set for the selected primitive version. These profiles use report schema
`hepta.hia.rust-byte-owner-execution.v1` and the same Machine, owner/loan maps,
call frames and allocation-failure counter.

The whole module passes the existing Rust ownership verifier before the
capability scan or any execution, including uncalled helpers. Unsupported
schemas, wrong-version instructions, forged resource handles, illegal aliases,
invalid lifetimes and unknown instructions reject. A tiny step budget or an
earlier injected allocator failure cannot hide an invalid suffix/helper.

Public JSON parameters/results remain scalar. Internal calls may transfer
owners/chains and borrow nonescaping read/mutable views. The policy remains
at most 32 root-inclusive frames, 1,000,000 ticks and 16 MiB of live payload/node
bytes. The live-byte ledger does not measure host VM metadata or total RSS.

## Executed resource operations

| Operation family | Actual behavior |
| --- | --- |
| Existing byte-owner/loan operations | Unchanged allocation, transfer, reads/writes, nested reborrow, loan end and explicit drop in the common Machine |
| `buffer.fill`, `buffer.fill_range` | Mutate only an admitted mutable view; validate the entire requested range before writing |
| `buffer.copy`, `buffer.copy_range` | Copy between distinct admitted roots; validate both complete ranges before writes; bounded 4096-byte scratch crosses larger ranges without a size-proportional temporary allocation |
| `buffer.move_within` | Validate both ranges, then preserve overlapping memmove semantics in either direction |
| `buffer.swap` | Validate both indices before changing either byte |
| `chain.empty`, `chain.is_empty` | Real linear chain identities, including empty descriptors with no allocator call |
| `chain.try_push` | Consume the input descriptor/payload; success owns a 24-byte node and returns a real empty fallback owner; allocation refusal returns the original payload and unchanged tail through a new chain identity |
| `chain.pop` | Consume the descriptor, free a present node header, return its payload and the remaining chain; empty pop returns a real empty owner and false |
| `chain.head_read`, `chain.head_mut` | Borrow the actual head payload; empty head traps; head loans/reborrows prevent shape changes and premature owner destruction |
| Chain `owner.move`, `owner.drop` and internal calls/results | Preserve identities during transfer; destruction consumes the descriptor then ticks and drops one payload/header pair per node |

Node headers and payloads share the ordinary owner ledger and allocator-failure
sequence. Heap checks precede allocator attempts. Zero-byte owners remain
linear objects but neither consume allocator attempts nor contribute byte
allocations/frees. The v7 ledger includes all six chain counters, including
live nodes left by a stopped destructor.

Rust stores chain links as flat IDs, so dropping the host VM after a budget stop
cannot recursively destroy a host linked-list structure. Host container
destruction is not reported as executed Hepta cleanup. A trap or evaluator
stop preserves the actual stopped ledger, including remaining owners and loans.

## Source returned borrows and composition

The existing source frontend supports a restricted helper whose body is one
explicit checked projection borrow of an incoming borrowed parameter. It
inlines the projection and retains the caller's parent/child loan lifetimes.
The source fixture `examples/hia_resource_core/borrowed_projection.hepta`
executes a mutable projection observation, a later mutation after its loans
end, a shared projection observation and final owning-record destruction.
The existing `generic_owners.hepta` and migrated `OwnedBytes` fixtures also
execute through the real source frontend and both VMs.

This is **source-level projection inlining**. Primitive v1–v7 still reject
function results of `readbuf`/`mutbuf`, including uncalled helpers. The distinct
primitive v8 contract permits original-parameter/direct-child loan returns;
its chain composition uses the same Machine under the
[v5 profile](HIA_RUST_RETURNED_CHAINS_V8.md). The current source profile
also rejects stored local returned borrows, nonprojection helper bodies,
explicit lifetime returns and borrowing a returned temporary as an assignment
place. A broader source contract needs explicit lifetime/root relations across
the frontend, verifier, interpreter and native consumers.

Existing nominal record/enum/task input is accepted by canonical Python
normalization, then the exact verified primitive bytes execute in both VMs.
The corpus covers stored owner/parent/child bundles, inactive enum owner slots,
owner-valued task results, cancellation while pending or running, repeated
cancel, cancellation after completion, close/join and chain-owned task state.
Raw nominal input to Rust continues to reject rather than invoke a hidden
lowerer. The recorded original input and normalized Core establish which
frontend path was actually used.

Cancellation here is the existing explicit cooperative task protocol.
Asynchronous cancellation, concurrent mutation and unwinding cleanup on traps
are not established by this extension.

## Reproducible finite evidence

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_owned_vm tests.test_hia_rust_owned_cfg -v
python tools/qualify_hia_rust_owned_memory.py --output /tmp/hia-owned-memory.json
```

The dedicated collector runs `tests/test_hia_rust_owned_memory.py`, builds the
actual executable using Cargo's reported artifact path and captures:

- original Hepta source or nominal/primitive input, its identity and canonical
  Core bytes represented as exact JSON data;
- source lowering/normalization receipts and program hashes;
- complete Python and Rust reports, exact status/ticks/values/error-code and
  every resource field, with raw Rust process stdout/stderr and invocation;
- wrong-version/alias/lifecycle/primitive-loan-return rejections and frontends
  that intentionally reject unsupported source syntax, without fallback;
- actual source inventories before/after, Git HEAD/status, compiler build log,
  binary SHA-256, toolchain identity, unmodified test counts and skips/failures.

All six bulk operations have independent byte-result expectations in addition
to Python parity. Native Rust unit tests check that rejected complete ranges
leave bytes unchanged, that copies cross scratch-chunk boundaries, and that
head reborrows freeze chain shape. The differential sweeps selected
allocation-failure positions, heap boundaries and every executed step of
source/aggregate/chain cleanup paths, including partial node destruction.

Each report qualifies only its recorded finite corpus and source inventory.
It does not prove full language safety, source/native refinement, arbitrary
resource execution, a performance advantage over Rust, or completion of the
whole resource-core stage. Actual counts belong to the generated receipt for
the tested revision; historical or development runs must not be relabeled as
qualification of a later integrated SHA.
