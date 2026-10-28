# Independent Rust execution of primitive v7 buffer chains

The opt-in Rust `--owned-run` mode now reports
`cfg-call-byte-owner-chain-v4`. It extends the same scalar/byte-owner Machine
with the six existing primitive v7 operations: `chain.empty`, `chain.try_push`,
`chain.pop`, `chain.is_empty`, `chain.head_read` and `chain.head_mut`.
`owner.move`, `owner.drop`, block arguments and consuming internal calls also
accept chain owners. Existing v1–v6 byte behavior remains admitted.

The canonical Python verifier remains the production admission authority.
Rust independently verifies the complete primitive document before execution;
it never invokes Python, LLVM or a producer receipt to execute an instruction.
The public entry accepts and returns only scalar JSON values. Chain/owner/loan
handles are private runtime values and cannot be fabricated through CLI input.
The default scalar checker/interpreter still refuses resource programs.

## Allocation, loans and destruction

An explicit arena stores chain descriptors and nodes. A node holds an owned
payload, a 24-byte owned storage allocation and a successor identifier. Payload
bytes and node bytes use the same heap limit, allocation-attempt sequence,
injected failure point and peak/live ledger. Host map bookkeeping is outside
that language-level byte budget; the report is not a process-RSS measurement.
The existing independent execution limits remain one million steps, 32
root-inclusive call frames and at most 16 MiB of language heap bytes.

A successful push consumes the original chain and payload, allocates node
storage, creates the required logical empty fallback owner and returns a new
chain descriptor. A failed node allocation drops its internal empty allocation
placeholder and returns the unchanged caller payload and tail under fresh
output names. A heap-budget stop occurs before consuming an allocation attempt
or transforming the input chain. Zero-byte payloads remain real owners without
allocator calls. Oversized optional buffer requests retain their previous
failure semantics.

Head loans refer to the actual payload root. The shared loan graph checks
mutable/read-only permission, reborrow suspension and call-formal witnesses.
The chain cannot move, pop, push or be consumed by a call while its head has a
live loan. A read-only formal's child does not suspend a separate aliased
read-only formal, including when both came from the same mutable head loan.

Chain destruction uses an explicit loop, never a recursive host destructor.
The chain descriptor is consumed first, then the Machine charges one step
before each payload/node drop. If the step budget expires during destruction,
the report retains unvisited nodes and bytes even though the descriptor is
already consumed. Process cleanup is not recorded as language cleanup. Node
storage and payload frees remain separately observable in selected native
allocator controls.

## Validation scope

`tests/test_hia_rust_owned_chain.py` compares the actual Rust executable with
the Python interpreter for status, stop code, scalar results, exact step count
and the complete resource-field inventory. The corpus exercises:

- Dynamic lengths through 4,097 nodes, construction/draining CFGs, consuming
  cross-function returns, head mutation and iterative cancellation cleanup.
- Each payload/node refusal in an eight-node construction, successful recovery
  of a rejected push's readable payload, zero-size payloads, empty pops and
  empty-head traps.
- Heap thresholds before failure injection and every step cut in a four-node
  construction/destruction, including all three partially completed drops.
- Head reborrow/call-formal aliases, bulk byte operations on the head, resumed
  mutable access, and a consuming recursive call stopped at the frame limit.
- Dynamic payload extents, oversized optional allocations and malformed
  ownership/version/public-boundary inputs rejected before any execution.

A third closed arithmetic specification checks selected return values,
physical allocation attempts, node/payload frees and peak bytes. Selected
LLVM/native controls execute the same Core with an independent allocator
driver; they overlap the parity corpus and must not be reported as disjoint
additional Rust/Python observations. Exact execution counts belong to the
retained test logs for a particular source commit, not this specification.

The nominal/composite examples are explicitly elaborated by Python and then
their resulting primitive Core bytes are independently admitted by Rust. Raw
nominal/composite input remains rejected by the Rust decoder. These checks do
not prove the elaborator, arbitrary recursive ADTs, escaping loans, asynchronous
scheduling, whole-language soundness, backend refinement, hardware safety or
Rust performance superiority. They close the missing independent executable
semantics of this finite v7 chain profile.

Run the existing Cargo suite and all independent owned execution tests on one
frozen source tree:

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_owned_vm tests.test_hia_rust_owned_cfg \
  tests.test_hia_rust_owned_bulk tests.test_hia_rust_owned_chain -v
```

Cargo and the selected native Clang must be available. Missing tools cause
explicit skips in the Python harness and cannot count as qualification.
